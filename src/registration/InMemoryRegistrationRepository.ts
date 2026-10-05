import { randomUUID } from "node:crypto";

import { IdentityRegistry } from "../identity/IdentityRegistry.js";
import { inMemoryIdentityClaimSourceStore } from "../identity/InMemoryIdentityClaimSourceStore.js";
import type { IdentitySubjectRepository } from "../identity/IdentitySubjectRepository.js";
import type { VerificationChallengeRepository } from "../email/VerificationChallengeRepository.js";
import type { RegistrationRepository } from "./RegistrationRepository.js";
import {
		RegistrationError,
		type CompleteRegistrationInput,
		type RegistrationAuditEntry,
		type RegistrationAuditType,
		type RegistrationErrorCode,
		type RegistrationOutcome
} from "./RegistrationTypes.js";

type EvidenceRecord = { identitySubjectId: string };

// Test-only stand-in for PostgresRegistrationRepository (never used in production). Mirrors the same
// validation/idempotency/conflict decisions. True concurrency guarantees are validated against real
// PostgreSQL (Task 18/20) -- single-threaded JS cannot reproduce genuine interleaving here.
export class InMemoryRegistrationRepository implements RegistrationRepository {
		private readonly evidenceByChallengeId = new Map<string, EvidenceRecord>();
		private readonly auditEntries: RegistrationAuditEntry[] = [];

		constructor(
				private readonly challenges: VerificationChallengeRepository,
				private readonly subjects: IdentitySubjectRepository
		) {}

		auditLog(): RegistrationAuditEntry[] {
				return [...this.auditEntries];
		}

		async complete(input: CompleteRegistrationInput): Promise<RegistrationOutcome> {
				const { context, verificationId } = input;
				this.audit("IDENTITY_REGISTRATION_STARTED", context, verificationId, null);

				const challenge = await this.challenges.findById(verificationId);
				if (!challenge || challenge.tenantId !== context.tenantId || challenge.applicationId !== context.applicationId) {
						return this.fail("INVALID_EVIDENCE", context, verificationId, null);
				}
				if (challenge.channel !== "EMAIL" || challenge.purpose !== "REGISTRATION") {
						return this.fail("INVALID_PURPOSE", context, verificationId, null);
				}

				if (challenge.status === "CONSUMED") {
						const evidence = this.evidenceByChallengeId.get(verificationId);
						if (!evidence) return this.fail("EVIDENCE_ALREADY_CONSUMED", context, verificationId, null);
						const subject = await this.subjects.findById(evidence.identitySubjectId);
						if (!subject) return this.fail("EVIDENCE_ALREADY_CONSUMED", context, verificationId, null);
						this.audit("IDENTITY_REGISTRATION_IDEMPOTENT", context, verificationId, subject.id);
						return { registered: true, subject: subject.oidcSubject, email: subject.email!, emailVerified: true, created: false, idempotentReplay: true };
				}

				if (challenge.status === "PENDING") return this.fail("UNVERIFIED_CHALLENGE", context, verificationId, null);
				if (challenge.status === "EXPIRED") return this.fail("EXPIRED_CHALLENGE", context, verificationId, null);
				if (challenge.status === "LOCKED") return this.fail("LOCKED_CHALLENGE", context, verificationId, null);
				if (challenge.status !== "VERIFIED" || !challenge.verifiedAt) return this.fail("INVALID_EVIDENCE", context, verificationId, null);

				const email = challenge.destinationNormalized;
				const verifiedAt = challenge.verifiedAt;

				const conflicting = (await this.subjects.findByEmail(email)).filter(subject => subject.primaryProvider !== "HAPI_EMAIL");
				if (conflicting.length > 0) {
						return this.fail("ACCOUNT_CONFLICT", context, verificationId, null);
				}

				const registry = new IdentityRegistry(this.subjects);
				const existingBefore = await registry.findByProvider("HAPI_EMAIL", email);
				const subject = await registry.resolveOrCreate({
						provider: "HAPI_EMAIL",
						providerSubject: email,
						email,
						emailVerified: true,
						applicationId: context.applicationId ?? undefined
				});
				const created = !existingBefore;

				this.evidenceByChallengeId.set(verificationId, { identitySubjectId: subject.id });
				await this.challenges.transaction(context, challenge.destinationHash, snapshot => {
						const current = snapshot.challenges.find(item => item.id === verificationId);
						if (current && current.status === "VERIFIED") {
								current.status = "CONSUMED";
								current.consumedAt = new Date().toISOString();
								current.updatedAt = current.consumedAt;
						}
				});

				if (created) {
						await inMemoryIdentityClaimSourceStore.recordClaimSource(subject.id, "email", "HAPI_EMAIL", verifiedAt);
						await inMemoryIdentityClaimSourceStore.recordClaimSource(subject.id, "emailVerified", "HAPI_EMAIL", verifiedAt);
				}

				this.audit("IDENTITY_REGISTERED", context, verificationId, subject.id);
				return { registered: true, subject: subject.oidcSubject, email, emailVerified: true, created, idempotentReplay: false };
		}

		private fail(code: RegistrationErrorCode, context: CompleteRegistrationInput["context"], verificationId: string,
				identitySubjectId: string | null): never {
				const type: RegistrationAuditType = code === "ACCOUNT_CONFLICT" ? "IDENTITY_REGISTRATION_CONFLICT" : "IDENTITY_REGISTRATION_FAILED";
				this.audit(type, context, verificationId, identitySubjectId, code);
				const statusCode = code === "ACCOUNT_CONFLICT" || code === "EVIDENCE_ALREADY_CONSUMED" ? 409 : 400;
				throw new RegistrationError(code, statusCode);
		}

		private audit(type: RegistrationAuditType, context: CompleteRegistrationInput["context"], verificationChallengeId: string | null,
				identitySubjectId: string | null, detail?: string): void {
				this.auditEntries.push({
						id: randomUUID(),
						tenantId: context.tenantId,
						applicationId: context.applicationId,
						verificationChallengeId,
						identitySubjectId,
						type,
						detail,
						occurredAt: new Date().toISOString()
				});
		}
}
