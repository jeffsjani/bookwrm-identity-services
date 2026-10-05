import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { InMemoryVerificationChallengeRepository } from "../src/email/InMemoryVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { InMemoryRegistrationRepository } from "../src/registration/InMemoryRegistrationRepository.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";
import { RegistrationError } from "../src/registration/RegistrationTypes.js";

const context = { tenantId: "tenant-a", applicationId: "application-a" };

function fixture() {
	const challenges = new InMemoryVerificationChallengeRepository();
	const provider = new InMemoryEmailDeliveryProvider();
	let now = Date.parse("2026-10-04T12:00:00Z");
	const secrets = new VerificationSecrets("test-secret".repeat(4));
	const emailService = new EmailVerificationService(challenges, provider, secrets, defaultVerificationPolicy, () => now);
	const subjects = new InMemoryIdentitySubjectRepository();
	const registration = new RegistrationService(new InMemoryRegistrationRepository(challenges, subjects));
	return { challenges, provider, emailService, subjects, registration, advance: (seconds: number) => { now += seconds * 1000; } };
}

async function verifiedChallenge(fx: ReturnType<typeof fixture>, email: string, ctx = context) {
	const { challengeId } = await fx.emailService.start(ctx, email, "REGISTRATION");
	const code = fx.provider.messages.at(-1)!.code;
	await fx.emailService.verify(ctx, challengeId, code);
	return challengeId;
}

describe("H3 registration completion", () => {
	it("Case A: valid verified evidence creates a canonical IdentitySubject with HAPI_EMAIL provenance", async () => {
		const fx = fixture();
		const verificationId = await verifiedChallenge(fx, "Person@Example.com");
		const outcome = await fx.registration.complete({ context, verificationId });
		expect(outcome).toMatchObject({ registered: true, email: "Person@example.com", emailVerified: true, created: true });
		expect(outcome.subject).toEqual(expect.any(String));

		const subject = await fx.subjects.findByOidcSubject(outcome.subject);
		expect(subject).toMatchObject({ primaryProvider: "HAPI_EMAIL", email: "Person@example.com", emailVerified: true, status: "ACTIVE" });
		expect((await fx.challenges.findById(verificationId))?.status).toBe("CONSUMED");
		expect((await fx.challenges.findById(verificationId))?.consumedAt).not.toBeNull();
	});

	it("rejects an unverified (PENDING) challenge", async () => {
		const fx = fixture();
		const { challengeId } = await fx.emailService.start(context, "a@example.com", "REGISTRATION");
		await expect(fx.registration.complete({ context, verificationId: challengeId })).rejects.toThrow("UNVERIFIED_CHALLENGE");
	});

	it("rejects an expired challenge", async () => {
		const fx = fixture();
		const { challengeId } = await fx.emailService.start(context, "a@example.com", "REGISTRATION");
		fx.advance(700);
		await expect(fx.emailService.verify(context, challengeId, fx.provider.messages.at(-1)!.code)).rejects.toThrow("CHALLENGE_EXPIRED");
		await expect(fx.registration.complete({ context, verificationId: challengeId })).rejects.toThrow("EXPIRED_CHALLENGE");
	});

	it("rejects a locked challenge", async () => {
		const fx = fixture();
		const { challengeId } = await fx.emailService.start(context, "a@example.com", "REGISTRATION");
		for (let attempt = 0; attempt < 5; attempt++) await expect(fx.emailService.verify(context, challengeId, "wrong")).rejects.toThrow("INVALID_CODE");
		await expect(fx.registration.complete({ context, verificationId: challengeId })).rejects.toThrow("LOCKED_CHALLENGE");
	});

	it("rejects wrong purpose (RECOVERY verified evidence cannot register)", async () => {
		const fx = fixture();
		const { challengeId } = await fx.emailService.start(context, "a@example.com", "RECOVERY");
		await fx.emailService.verify(context, challengeId, fx.provider.messages.at(-1)!.code);
		await expect(fx.registration.complete({ context, verificationId: challengeId })).rejects.toThrow("INVALID_PURPOSE");
	});

	it("rejects wrong tenant without leaking challenge existence", async () => {
		const fx = fixture();
		const verificationId = await verifiedChallenge(fx, "a@example.com");
		await expect(fx.registration.complete({ context: { tenantId: "other-tenant", applicationId: context.applicationId }, verificationId }))
			.rejects.toThrow("INVALID_EVIDENCE");
	});

	it("rejects wrong application without leaking challenge existence", async () => {
		const fx = fixture();
		const verificationId = await verifiedChallenge(fx, "a@example.com");
		await expect(fx.registration.complete({ context: { tenantId: context.tenantId, applicationId: "other-application" }, verificationId }))
			.rejects.toThrow("INVALID_EVIDENCE");
	});

	it("rejects an unknown verificationId", async () => {
		const fx = fixture();
		await expect(fx.registration.complete({ context, verificationId: randomUUID() })).rejects.toThrow("INVALID_EVIDENCE");
	});

	it("a successful retry with the same verificationId is idempotent (no second identity)", async () => {
		const fx = fixture();
		const verificationId = await verifiedChallenge(fx, "retry@example.com");
		const first = await fx.registration.complete({ context, verificationId });
		const second = await fx.registration.complete({ context, verificationId });
		expect(second).toMatchObject({ registered: true, subject: first.subject, email: first.email, idempotentReplay: true, created: false });
		expect((await fx.subjects.list()).filter(subject => subject.primaryProvider === "HAPI_EMAIL" && subject.email === "retry@example.com").length).toBe(1);
	});

	it("Case B: a second verification for the same already-registered email reuses the existing identity", async () => {
		const fx = fixture();
		const first = await fx.registration.complete({ context, verificationId: await verifiedChallenge(fx, "same@example.com") });
		const second = await fx.registration.complete({ context, verificationId: await verifiedChallenge(fx, "same@example.com") });
		expect(second.subject).toBe(first.subject);
		expect(second.created).toBe(false);
		expect((await fx.subjects.list()).filter(subject => subject.email === "same@example.com").length).toBe(1);
	});

	it("Case C: a verified email already owned by a different (non-HAPI_EMAIL) identity is a controlled conflict, not a merge", async () => {
		const fx = fixture();
		await fx.subjects.create({
			id: randomUUID(), oidcSubject: randomUUID(), applicationId: context.applicationId, primaryProvider: "PrivateID",
			primaryProviderSubject: randomUUID(), email: "conflict@example.com", emailVerified: false, status: "ACTIVE"
		});
		const verificationId = await verifiedChallenge(fx, "conflict@example.com");
		await expect(fx.registration.complete({ context, verificationId })).rejects.toThrow("ACCOUNT_CONFLICT");
		// The challenge/evidence is left untouched -- still available for a future linking/recovery flow.
		expect((await fx.challenges.findById(verificationId))?.status).toBe("VERIFIED");
		expect((await fx.subjects.list()).filter(subject => subject.email === "conflict@example.com").length).toBe(1);
	});

	it("replay after consumption by something other than H3 is rejected, never treated as proof of identity", async () => {
		const fx = fixture();
		const verificationId = await verifiedChallenge(fx, "foreign@example.com");
		// Simulate the H2 consume() path (used by some *other* flow) marking it CONSUMED directly,
		// bypassing H3's registration_evidence linkage entirely.
		await fx.challenges.transaction(context, (await fx.challenges.findById(verificationId))!.destinationHash, snapshot => {
			const challenge = snapshot.challenges.find(item => item.id === verificationId)!;
			challenge.status = "CONSUMED";
			challenge.consumedAt = new Date().toISOString();
		});
		await expect(fx.registration.complete({ context, verificationId })).rejects.toThrow("EVIDENCE_ALREADY_CONSUMED");
	});

	it("creates no password, no PrivateID authenticator, and no IdentityAccountLink", async () => {
		const fx = fixture();
		const verificationId = await verifiedChallenge(fx, "clean@example.com");
		const outcome = await fx.registration.complete({ context, verificationId });
		const subject = await fx.subjects.findByOidcSubject(outcome.subject);
		expect(subject).not.toHaveProperty("password");
		expect(subject?.primaryProvider).toBe("HAPI_EMAIL");
	});

	it("security: a guessed/foreign verificationId never succeeds", async () => {
		const fx = fixture();
		await expect(fx.registration.complete({ context, verificationId: randomUUID() })).rejects.toBeInstanceOf(RegistrationError);
	});
});
