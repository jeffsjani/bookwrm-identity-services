import { randomUUID } from "node:crypto";
import type { EmailDeliveryProvider, VerificationEmail } from "./EmailDeliveryProvider.js";
import { normalizeEmail } from "./EmailNormalizationService.js";
import type { DeliveryEvent, DeliveryState, VerificationAuditType, VerificationChallengeRepository, VerificationSnapshot } from "./VerificationChallengeRepository.js";
import { VerificationError, type VerificationChallenge, type VerificationContext, type VerificationPurpose } from "./VerificationChallenge.js";
import type { VerificationPolicy } from "./VerificationPolicy.js";
import { VerificationSecrets } from "./VerificationSecrets.js";

export class EmailVerificationService {
	constructor(
		private readonly repository: VerificationChallengeRepository,
		private readonly provider: EmailDeliveryProvider,
		private readonly secrets: VerificationSecrets,
		private readonly policy: VerificationPolicy,
		private readonly clock: () => number = Date.now
	) {}

	async start(context: VerificationContext, email: string, purpose: VerificationPurpose) {
		const destination = normalizeEmail(email);
		const destinationHash = this.secrets.destination(destination);
		const outcome = await this.repository.transaction(context, destinationHash, snapshot => {
			const now = this.clock();
			const challenge: VerificationChallenge = {
				...context, id: randomUUID(), channel: "EMAIL", purpose,
				destinationNormalized: destination, destinationHash, codeHash: "",
				status: "PENDING", expiresAt: new Date(now + this.policy.expirationSeconds * 1000).toISOString(),
				attemptCount: 0, maxAttempts: this.policy.maxAttempts, sendCount: 0,
				lastSentAt: new Date(now).toISOString(), verifiedAt: null, consumedAt: null,
				createdAt: new Date(now).toISOString(), updatedAt: new Date(now).toISOString()
			};
			if (this.destinationLimited(snapshot, now)) {
				this.audit(snapshot, challenge, "EMAIL_VERIFICATION_RATE_LIMITED");
				return { error: "RATE_LIMITED" } as const;
			}
			snapshot.challenges.push(challenge);
			this.audit(snapshot, challenge, "EMAIL_VERIFICATION_STARTED");
			this.event(snapshot, challenge, "CHALLENGE_CREATED");
			return { email: this.prepareSend(snapshot, challenge, now), challengeId: challenge.id };
		});
		if (outcome.error !== undefined) throw new VerificationError(outcome.error, 429);
		await this.deliver(context, outcome.email, false);
		return { challengeId: outcome.challengeId, expiresIn: this.policy.expirationSeconds, resendAfter: this.policy.resendCooldownSeconds };
	}

	async resend(context: VerificationContext, challengeId: string) {
		const outcome = await this.withChallenge(context, challengeId, (snapshot, challenge) => {
			const error = this.pendingError(snapshot, challenge);
			if (error) return { error };
			const now = this.clock();
			if (now - Date.parse(challenge.lastSentAt) < this.policy.resendCooldownSeconds * 1000 ||
				challenge.sendCount >= this.policy.maxSendsPerChallenge || this.destinationLimited(snapshot, now)) {
				this.audit(snapshot, challenge, "EMAIL_VERIFICATION_RATE_LIMITED");
				return { error: "RATE_LIMITED" };
			}
			return { email: this.prepareSend(snapshot, challenge, now) };
		});
		if (outcome.error !== undefined) throw new VerificationError(outcome.error, outcome.error === "RATE_LIMITED" ? 429 : 400);
		await this.deliver(context, outcome.email, true);
		return { challengeId, expiresIn: this.policy.expirationSeconds, resendAfter: this.policy.resendCooldownSeconds };
	}

	async verify(context: VerificationContext, challengeId: string, code: string, purpose?: VerificationPurpose) {
		const outcome = await this.withChallenge(context, challengeId, (snapshot, challenge) => {
			if (purpose && challenge.purpose !== purpose) return { error: "INVALID_CHALLENGE" };
			const error = this.pendingError(snapshot, challenge);
			if (error) return { error };
			if (!new RegExp(`^\\d{${this.policy.otpLength}}$`).test(code) || !this.secrets.matches(challenge.id, code, challenge.codeHash)) {
				challenge.attemptCount += 1;
				challenge.updatedAt = this.timestamp();
				this.audit(snapshot, challenge, "EMAIL_VERIFICATION_FAILED");
				if (challenge.attemptCount >= challenge.maxAttempts) {
					challenge.status = "LOCKED";
					challenge.codeHash = "";
					this.audit(snapshot, challenge, "EMAIL_VERIFICATION_LOCKED");
				}
				return { error: "INVALID_CODE" };
			}
			challenge.status = "VERIFIED";
			challenge.verifiedAt = this.timestamp();
			challenge.updatedAt = challenge.verifiedAt;
			challenge.codeHash = "";
			this.audit(snapshot, challenge, "EMAIL_VERIFICATION_VERIFIED");
			this.event(snapshot, challenge, "USER_VERIFIED");
			return { verified: true as const, verificationId: challenge.id };
		});
		if (outcome.error !== undefined) throw new VerificationError(outcome.error);
		return outcome;
	}

	async consume(context: VerificationContext, verificationId: string, email: string, purpose: VerificationPurpose) {
		const destination = normalizeEmail(email);
		const outcome = await this.withChallenge(context, verificationId, (snapshot, challenge) => {
			if (challenge.destinationNormalized !== destination || challenge.purpose !== purpose || challenge.status !== "VERIFIED") {
				return { error: "INVALID_EVIDENCE" };
			}
			if (Date.parse(challenge.expiresAt) <= this.clock()) {
				this.expire(snapshot, challenge);
				return { error: "INVALID_EVIDENCE" };
			}
			challenge.status = "CONSUMED";
			challenge.consumedAt = this.timestamp();
			challenge.updatedAt = challenge.consumedAt;
			return { evidence: { ...context, verificationId: challenge.id, email: destination, purpose, verifiedAt: challenge.verifiedAt! } };
		});
		if (outcome.error !== undefined) throw new VerificationError(outcome.error);
		return outcome.evidence;
	}

	async recordProviderEvent(messageId: string, eventId: string, state: Extract<DeliveryState, "DELIVERED" | "DEFERRED" | "BOUNCED" | "COMPLAINED" | "SUPPRESSED" | "PROVIDER_FAILED">) {
		const accepted = await this.repository.findByProviderMessageId(messageId);
		if (!accepted) throw new VerificationError("DELIVERY_NOT_FOUND", 503);
		await this.withChallenge(accepted, accepted.challengeId, (snapshot, challenge) => {
			if (!snapshot.delivery.some(event => event.id === eventId)) {
				this.event(snapshot, challenge, state, accepted.sendId, messageId, eventId);
			}
		});
	}

	private async withChallenge<Result>(context: VerificationContext, id: string,
		work: (snapshot: VerificationSnapshot, challenge: VerificationChallenge) => Result): Promise<Result> {
		const found = await this.repository.findById(id);
		if (!found || found.tenantId !== context.tenantId || found.applicationId !== context.applicationId) {
			throw new VerificationError("INVALID_CHALLENGE");
		}
		return this.repository.transaction(context, found.destinationHash, snapshot => {
			const challenge = snapshot.challenges.find(item => item.id === id)!;
			return work(snapshot, challenge);
		});
	}

	private prepareSend(snapshot: VerificationSnapshot, challenge: VerificationChallenge, now: number): VerificationEmail {
		let code = this.secrets.generate(this.policy.otpLength);
		while (this.secrets.matches(challenge.id, code, challenge.codeHash)) code = this.secrets.generate(this.policy.otpLength);
		challenge.codeHash = this.secrets.code(challenge.id, code);
		challenge.sendCount += 1;
		challenge.lastSentAt = new Date(now).toISOString();
		challenge.updatedAt = challenge.lastSentAt;
		challenge.expiresAt = new Date(now + this.policy.expirationSeconds * 1000).toISOString();
		const sendId = randomUUID();
		this.event(snapshot, challenge, "SEND_REQUESTED", sendId);
		return { destination: challenge.destinationNormalized, code, purpose: challenge.purpose,
			expiresIn: this.policy.expirationSeconds, tenant: challenge.tenantId, application: challenge.applicationId, sendId };
	}

	private async deliver(context: VerificationContext, email: VerificationEmail, resent: boolean) {
		const controller = new AbortController();
		let timer: ReturnType<typeof setTimeout> | undefined;
		let result: { messageId: string } | undefined;
		let failure: "PROVIDER_FAILED" | "PROVIDER_TIMEOUT" | undefined;
		try {
			result = await Promise.race([
				this.provider.sendVerificationEmail(email, controller.signal),
				new Promise<never>((_resolve, reject) => {
					timer = setTimeout(() => { controller.abort(); reject(new Error("timeout")); }, this.policy.providerTimeoutMs);
				})
			]);
			if (!result.messageId) failure = "PROVIDER_FAILED";
		} catch {
			failure = controller.signal.aborted ? "PROVIDER_TIMEOUT" : "PROVIDER_FAILED";
		} finally {
			if (timer) clearTimeout(timer);
		}
		await this.repository.transaction(context, this.secrets.destination(email.destination), snapshot => {
			const requested = snapshot.delivery.find(event => event.sendId === email.sendId && event.state === "SEND_REQUESTED")!;
			const challenge = snapshot.challenges.find(item => item.id === requested.challengeId)!;
			this.event(snapshot, challenge, failure ?? "PROVIDER_ACCEPTED", email.sendId, result?.messageId ?? null);
			this.audit(snapshot, challenge, failure ? "EMAIL_VERIFICATION_FAILED" : resent ? "EMAIL_VERIFICATION_RESENT" : "EMAIL_VERIFICATION_SENT");
		});
		if (failure) throw new VerificationError("DELIVERY_UNAVAILABLE", 503);
	}

	private destinationLimited(snapshot: VerificationSnapshot, now: number): boolean {
		const sends = snapshot.delivery.filter(event => event.state === "SEND_REQUESTED");
		return sends.filter(event => Date.parse(event.occurredAt) > now - 3_600_000).length >= this.policy.maxSendsPerDestinationHour ||
			sends.filter(event => Date.parse(event.occurredAt) > now - 86_400_000).length >= this.policy.maxSendsPerDestinationDay;
	}

	private pendingError(snapshot: VerificationSnapshot, challenge: VerificationChallenge): string | undefined {
		if (challenge.status !== "PENDING") return "INVALID_CHALLENGE";
		if (Date.parse(challenge.expiresAt) <= this.clock()) {
			this.expire(snapshot, challenge);
			return "CHALLENGE_EXPIRED";
		}
		return undefined;
	}
	private expire(snapshot: VerificationSnapshot, challenge: VerificationChallenge) {
		challenge.status = "EXPIRED";
		challenge.codeHash = "";
		challenge.updatedAt = this.timestamp();
		this.audit(snapshot, challenge, "EMAIL_VERIFICATION_EXPIRED");
	}
	private timestamp() { return new Date(this.clock()).toISOString(); }
	private audit(snapshot: VerificationSnapshot, challenge: VerificationChallenge, type: VerificationAuditType) {
		snapshot.audit.push({ id: randomUUID(), tenantId: challenge.tenantId, applicationId: challenge.applicationId,
			challengeId: challenge.id, destinationHash: challenge.destinationHash, type, occurredAt: this.timestamp() });
	}
	private event(snapshot: VerificationSnapshot, challenge: VerificationChallenge, state: DeliveryState,
		sendId: string | null = null, providerMessageId: string | null = null, id: string = randomUUID()) {
		const event: DeliveryEvent = { id, tenantId: challenge.tenantId, applicationId: challenge.applicationId,
			challengeId: challenge.id, destinationHash: challenge.destinationHash, sendId, providerMessageId, state, occurredAt: this.timestamp() };
		snapshot.delivery.push(event);
	}
}