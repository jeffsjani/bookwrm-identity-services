import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type pg from "pg";

import { IdentityRegistry } from "../identity/IdentityRegistry.js";
import { PostgresIdentitySubjectRepository } from "../identity/PostgresIdentitySubjectRepository.js";
import { PostgresIdentityClaimSourceStore } from "../identity/PostgresIdentityClaimSourceStore.js";
import type { PostgresClient } from "../identity/infrastructure/PostgresInfrastructure.js";
import type { RegistrationRepository } from "./RegistrationRepository.js";
import { RegistrationError, type CompleteRegistrationInput, type RegistrationAuditType, type RegistrationErrorCode, type RegistrationOutcome } from "./RegistrationTypes.js";

type ChallengeRow = {
		id: string;
		tenant_id: string;
		application_id: string | null;
		channel: string;
		purpose: string;
		destination_normalized: string;
		status: string;
		verified_at: string | Date | null;
		consumed_at: string | Date | null;
};

// System-of-record implementation. The entire registration-completion unit of work (Task 9) runs on
// one Postgres transaction/client: verification lock, identity resolve-or-create, claim provenance,
// verification consumption, and audit all commit or roll back together.
export class PostgresRegistrationRepository implements RegistrationRepository {
		constructor(private readonly pool: pg.Pool) {}

		async ensureSchema(): Promise<void> {
				await this.pool.query(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
		}

		async complete(input: CompleteRegistrationInput): Promise<RegistrationOutcome> {
				const { context, verificationId } = input;
				const client = await this.pool.connect();
				try {
						await client.query("BEGIN");
						await this.audit(client, "IDENTITY_REGISTRATION_STARTED", context, verificationId, null);

						const locked = await client.query<ChallengeRow>(
								"SELECT * FROM verification_challenges WHERE id = $1 FOR UPDATE",
								[verificationId]
						);
						const challenge = locked.rows[0];

						// Not found, wrong tenant, or wrong application all read identically (Task 19): never
						// leak which case applies to an unauthenticated/mismatched caller.
						if (!challenge || challenge.tenant_id !== context.tenantId || challenge.application_id !== context.applicationId) {
								return this.fail(client, "INVALID_EVIDENCE", context, verificationId, null);
						}

						if (challenge.channel !== "EMAIL" || challenge.purpose !== "REGISTRATION") {
								return this.fail(client, "INVALID_PURPOSE", context, verificationId, null);
						}

						if (challenge.status === "CONSUMED") {
								const evidence = await client.query<{ identity_subject_id: string }>(
										"SELECT identity_subject_id FROM registration_evidence WHERE verification_challenge_id = $1",
										[verificationId]
								);
								if (!evidence.rows[0]) {
										// Consumed by something other than a successful H3 registration (or evidence row
										// lost) -- must never be treated as proof of identity. Task 10/19 (replay safety).
										return this.fail(client, "EVIDENCE_ALREADY_CONSUMED", context, verificationId, null);
								}
								const subjectRepo = new PostgresIdentitySubjectRepository(client as unknown as PostgresClient);
								const subject = await subjectRepo.findById(evidence.rows[0].identity_subject_id);
								if (!subject) {
										return this.fail(client, "EVIDENCE_ALREADY_CONSUMED", context, verificationId, null);
								}
								await this.audit(client, "IDENTITY_REGISTRATION_IDEMPOTENT", context, verificationId, subject.id);
								await client.query("COMMIT");
								return { registered: true, subject: subject.oidcSubject, email: subject.email!, emailVerified: true, created: false, idempotentReplay: true };
						}

						if (challenge.status === "PENDING") return this.fail(client, "UNVERIFIED_CHALLENGE", context, verificationId, null);
						if (challenge.status === "EXPIRED") return this.fail(client, "EXPIRED_CHALLENGE", context, verificationId, null);
						if (challenge.status === "LOCKED") return this.fail(client, "LOCKED_CHALLENGE", context, verificationId, null);
						if (challenge.status !== "VERIFIED" || !challenge.verified_at) return this.fail(client, "INVALID_EVIDENCE", context, verificationId, null);

						const email = challenge.destination_normalized;
						const verifiedAt = challenge.verified_at instanceof Date ? challenge.verified_at.toISOString() : challenge.verified_at;

						// Case C (Task 7): a verified email already belonging to a *different* canonical identity
						// (any provider other than HAPI_EMAIL) must never be silently merged into or superseded by
						// a new registration. The evidence/challenge is left untouched -- this still leaves it
						// available for a future authenticated linking/recovery flow.
						const conflicting = await client.query<{ id: string }>(
								"SELECT id FROM identity_subjects WHERE email = $1 AND primary_provider <> 'HAPI_EMAIL' FOR UPDATE",
								[email]
						);
						if (conflicting.rows[0]) {
								return this.fail(client, "ACCOUNT_CONFLICT", context, verificationId, null);
						}

						// Case A/B/D (Tasks 7+9): IdentityRegistry.resolveOrCreate persists via the existing
						// (primaryProvider, primaryProviderSubject) unique constraint, so concurrent registrations
						// for the same normalized email -- whether via this same verification or a different one --
						// always collapse onto exactly one canonical IdentitySubject row.
						const registry = new IdentityRegistry(new PostgresIdentitySubjectRepository(client as unknown as PostgresClient));
						const existingBefore = await registry.findByProvider("HAPI_EMAIL", email);
						const subject = await registry.resolveOrCreate({
								provider: "HAPI_EMAIL",
								providerSubject: email,
								email,
								emailVerified: true,
								applicationId: context.applicationId ?? undefined
						});
						const created = !existingBefore;

						await client.query(
								`INSERT INTO registration_evidence (verification_challenge_id, identity_subject_id, tenant_id, application_id, email_normalized, created_at)
								 VALUES ($1, $2, $3, $4, $5, NOW())
								 ON CONFLICT (verification_challenge_id) DO NOTHING`,
								[verificationId, subject.id, context.tenantId, context.applicationId, email]
						);
						await client.query(
								"UPDATE verification_challenges SET status = 'CONSUMED', consumed_at = NOW(), updated_at = NOW() WHERE id = $1",
								[verificationId]
						);

						if (created) {
								// Task 6/H3P Task 4: provenance for the claims established at creation, using the
								// existing governed claim-source store (IdentityClaimResolver only updates *existing*
								// claims, so creation-time provenance is recorded directly via its same primitive).
								// Bound to this SAME open transaction client -- never a second, independent
								// connection/transaction -- so provenance commits/rolls back atomically with the
								// IdentitySubject, registration evidence, and challenge consumption above.
								const claimSources = new PostgresIdentityClaimSourceStore(client as unknown as PostgresClient);
								await claimSources.recordClaimSource(subject.id, "email", "HAPI_EMAIL", verifiedAt);
								await claimSources.recordClaimSource(subject.id, "emailVerified", "HAPI_EMAIL", verifiedAt);
						}

						await this.audit(client, "IDENTITY_REGISTERED", context, verificationId, subject.id);
						await client.query("COMMIT");
						return { registered: true, subject: subject.oidcSubject, email, emailVerified: true, created, idempotentReplay: false };
				} catch (error) {
						await client.query("ROLLBACK").catch(() => undefined);
						if (error instanceof RegistrationError) throw error;
						throw new RegistrationError("REGISTRATION_UNAVAILABLE", 503);
				} finally {
						client.release();
				}
		}

		private async fail(client: pg.PoolClient, code: RegistrationErrorCode,
				context: CompleteRegistrationInput["context"], verificationId: string, identitySubjectId: string | null): Promise<never> {
				const type: RegistrationAuditType = code === "ACCOUNT_CONFLICT" ? "IDENTITY_REGISTRATION_CONFLICT" : "IDENTITY_REGISTRATION_FAILED";
				await this.audit(client, type, context, verificationId, identitySubjectId, code);
				await client.query("COMMIT");
				const statusCode = code === "ACCOUNT_CONFLICT" || code === "EVIDENCE_ALREADY_CONSUMED" ? 409 : 400;
				throw new RegistrationError(code, statusCode);
		}

		private async audit(client: pg.PoolClient, type: RegistrationAuditType, context: CompleteRegistrationInput["context"],
				verificationChallengeId: string | null, identitySubjectId: string | null, detail?: string): Promise<void> {
				await client.query(
						`INSERT INTO identity_registration_audit (id, tenant_id, application_id, verification_challenge_id, identity_subject_id, type, detail, occurred_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
						[randomUUID(), context.tenantId, context.applicationId, verificationChallengeId, identitySubjectId, type, detail ?? null]
				);
		}
}
