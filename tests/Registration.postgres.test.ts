import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { PostgresRegistrationRepository } from "../src/registration/PostgresRegistrationRepository.js";
import { PostgresIdentityClaimSourceStore } from "../src/identity/PostgresIdentityClaimSourceStore.js";
import { RegistrationError } from "../src/registration/RegistrationTypes.js";

const databaseUrl = process.env.HAPI_REGISTRATION_TEST_DATABASE_URL ?? process.env.HAPI_EMAIL_TEST_DATABASE_URL;

describe.skipIf(!databaseUrl)("H3 durable PostgreSQL atomicity/concurrency", () => {
	const pool = new pg.Pool({ connectionString: databaseUrl, max: 16 });
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const challengeRepository = new PostgresVerificationChallengeRepository(pool);
	const secrets = new VerificationSecrets("h3-postgres-test-secret".repeat(3));
	const provider = new InMemoryEmailDeliveryProvider();
	const emailService = new EmailVerificationService(challengeRepository, provider, secrets, defaultVerificationPolicy);
	const registrationRepository = new PostgresRegistrationRepository(pool);
	const context = { tenantId, applicationId };
	const uniqueEmail = () => `${randomUUID()}@example.com`;

	async function verifiedChallenge(email: string): Promise<string> {
		const { challengeId } = await emailService.start(context, email, "REGISTRATION");
		const code = provider.messages.at(-1)!.code;
		await emailService.verify(context, challengeId, code);
		return challengeId;
	}

	beforeAll(async () => {
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		await challengeRepository.ensureSchema();
		await registrationRepository.ensureSchema();
		await pool.query("INSERT INTO tenants VALUES ($1, 'H3 test', $2, 'active', NOW(), NOW())", [tenantId, `h3-${tenantId}`]);
		await pool.query("INSERT INTO applications VALUES ($1, $2, 'H3 test', 'h3', 'active', NOW(), NOW())", [applicationId, tenantId]);
	});

	afterAll(async () => {
		await pool.query("DELETE FROM identity_registration_audit WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM registration_evidence WHERE tenant_id = $1", [tenantId]);
		await pool.query(
			"DELETE FROM identity_claim_provenance WHERE identity_subject_id IN (SELECT id FROM identity_subjects WHERE application_id = $1)",
			[applicationId]
		);
		await pool.query("DELETE FROM identity_subjects WHERE application_id = $1", [applicationId]);
		await pool.query("DELETE FROM verification_delivery_events WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM email_verification_audit WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM verification_challenges WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM applications WHERE id = $1", [applicationId]);
		await pool.query("DELETE FROM tenants WHERE id = $1", [tenantId]);
		await pool.end();
	});

	it("creates exactly one canonical IdentitySubject and consumes the challenge exactly once (happy path)", async () => {
		const email = uniqueEmail();
		const verificationId = await verifiedChallenge(email);
		const outcome = await registrationRepository.complete({ context, verificationId });
		expect(outcome).toMatchObject({ registered: true, email, emailVerified: true, created: true });
		const rows = await pool.query("SELECT * FROM identity_subjects WHERE primary_provider = 'HAPI_EMAIL' AND primary_provider_subject = $1", [email]);
		expect(rows.rows).toHaveLength(1);
		const evidence = await pool.query("SELECT * FROM registration_evidence WHERE verification_challenge_id = $1", [verificationId]);
		expect(evidence.rows).toHaveLength(1);
		const challenge = await pool.query("SELECT status, consumed_at FROM verification_challenges WHERE id = $1", [verificationId]);
		expect(challenge.rows[0].status).toBe("CONSUMED");
		expect(challenge.rows[0].consumed_at).not.toBeNull();

		// H3P Task 4/13: HAPI_EMAIL provenance must commit atomically alongside the identity and
		// challenge consumption above, and must survive a brand-new store instance (simulated restart).
		const provenance = await pool.query(
			"SELECT claim_name, source FROM identity_claim_provenance WHERE identity_subject_id = $1 ORDER BY claim_name",
			[rows.rows[0].id]
		);
		expect(provenance.rows).toEqual([
			{ claim_name: "email", source: "HAPI_EMAIL" },
			{ claim_name: "emailVerified", source: "HAPI_EMAIL" }
		]);
		const restartedStore = new PostgresIdentityClaimSourceStore(pool);
		const sources = await restartedStore.getClaimSources(rows.rows[0].id);
		expect(sources.email).toBe("HAPI_EMAIL");
		expect(sources.emailVerified).toBe("HAPI_EMAIL");
	});

	it("Task 9/18: concurrent completion of the SAME verification yields exactly one registered identity and one consumption", async () => {
		const email = uniqueEmail();
		const verificationId = await verifiedChallenge(email);
		const attempts = await Promise.allSettled(
			Array.from({ length: 10 }, () => new PostgresRegistrationRepository(pool).complete({ context, verificationId }))
		);
		const fulfilled = attempts.filter((result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof registrationRepository.complete>>> => result.status === "fulfilled");
		// Every concurrent caller either genuinely creates it or safely observes the idempotent replay --
		// never a rejection, and never more than one created=true outcome.
		expect(fulfilled).toHaveLength(10);
		expect(fulfilled.filter(result => result.value.created)).toHaveLength(1);
		const subjects = fulfilled.map(result => result.value.subject);
		expect(new Set(subjects).size).toBe(1);
		const rows = await pool.query("SELECT * FROM identity_subjects WHERE primary_provider = 'HAPI_EMAIL' AND primary_provider_subject = $1", [email]);
		expect(rows.rows).toHaveLength(1);
	});

	it("Task 7/18: concurrent completion of two DIFFERENT verifications for the same email collapses onto one canonical identity", async () => {
		const email = uniqueEmail();
		const verificationIdA = await verifiedChallenge(email);
		const verificationIdB = await verifiedChallenge(email);
		const [outcomeA, outcomeB] = await Promise.all([
			new PostgresRegistrationRepository(pool).complete({ context, verificationId: verificationIdA }),
			new PostgresRegistrationRepository(pool).complete({ context, verificationId: verificationIdB })
		]);
		expect(outcomeA.subject).toBe(outcomeB.subject);
		const rows = await pool.query("SELECT * FROM identity_subjects WHERE primary_provider = 'HAPI_EMAIL' AND primary_provider_subject = $1", [email]);
		expect(rows.rows).toHaveLength(1);
		const bothChallenges = await pool.query("SELECT status FROM verification_challenges WHERE id = ANY($1)", [[verificationIdA, verificationIdB]]);
		expect(bothChallenges.rows.every(row => row.status === "CONSUMED")).toBe(true);
	});

	it("a successful retry (same verificationId) is idempotent and never creates a second identity", async () => {
		const email = uniqueEmail();
		const verificationId = await verifiedChallenge(email);
		const first = await registrationRepository.complete({ context, verificationId });
		const second = await registrationRepository.complete({ context, verificationId });
		expect(second).toMatchObject({ subject: first.subject, idempotentReplay: true, created: false });
		const rows = await pool.query("SELECT * FROM identity_subjects WHERE primary_provider = 'HAPI_EMAIL' AND primary_provider_subject = $1", [email]);
		expect(rows.rows).toHaveLength(1);
	});

	it("Case C conflict: a verified email already owned by a different-provider identity is rejected without mutation", async () => {
		const email = uniqueEmail();
		const conflictingSubjectId = randomUUID();
		await pool.query(
			"INSERT INTO identity_subjects (id, oidc_subject, application_id, primary_provider, primary_provider_subject, email, email_verified, status, created_at, updated_at) VALUES ($1, $2, $3, 'PrivateID', $4, $5, false, 'ACTIVE', NOW(), NOW())",
			[conflictingSubjectId, randomUUID(), applicationId, randomUUID(), email]
		);
		const verificationId = await verifiedChallenge(email);
		await expect(registrationRepository.complete({ context, verificationId })).rejects.toThrow("ACCOUNT_CONFLICT");
		const challenge = await pool.query("SELECT status FROM verification_challenges WHERE id = $1", [verificationId]);
		expect(challenge.rows[0].status).toBe("VERIFIED");
		const rows = await pool.query("SELECT * FROM identity_subjects WHERE email = $1", [email]);
		expect(rows.rows).toHaveLength(1);
		// H3P: a rejected/rolled-back registration must never leave behind HAPI_EMAIL provenance.
		const provenance = await pool.query("SELECT * FROM identity_claim_provenance WHERE identity_subject_id = $1 AND source = 'HAPI_EMAIL'", [
			conflictingSubjectId
		]);
		expect(provenance.rows).toHaveLength(0);
	});

	it("wrong tenant and wrong application are both rejected identically (no information leak)", async () => {
		const otherTenantId = randomUUID();
		const otherApplicationId = randomUUID();
		await pool.query("INSERT INTO tenants VALUES ($1, 'Other tenant', $2, 'active', NOW(), NOW())", [otherTenantId, `other-${otherTenantId}`]);
		await pool.query("INSERT INTO applications VALUES ($1, $2, 'Other app', 'other', 'active', NOW(), NOW())", [otherApplicationId, otherTenantId]);
		try {
			const verificationId = await verifiedChallenge(uniqueEmail());
			await expect(registrationRepository.complete({ context: { tenantId: otherTenantId, applicationId }, verificationId })).rejects.toThrow("INVALID_EVIDENCE");
			await expect(registrationRepository.complete({ context: { tenantId, applicationId: otherApplicationId }, verificationId })).rejects.toThrow("INVALID_EVIDENCE");
		} finally {
			await pool.query("DELETE FROM applications WHERE id = $1", [otherApplicationId]);
			await pool.query("DELETE FROM tenants WHERE id = $1", [otherTenantId]);
		}
	});

	it("rejects replay after consumption by something other than H3 as EVIDENCE_ALREADY_CONSUMED", async () => {
		const verificationId = await verifiedChallenge(uniqueEmail());
		await pool.query("UPDATE verification_challenges SET status = 'CONSUMED', consumed_at = NOW() WHERE id = $1", [verificationId]);
		await expect(registrationRepository.complete({ context, verificationId })).rejects.toThrow("EVIDENCE_ALREADY_CONSUMED");
	});

	it("does not disturb an existing (pre-H3) IdentitySubject's provider/claims", async () => {
		const existingId = randomUUID();
		const existingOidcSubject = randomUUID();
		await pool.query(
			"INSERT INTO identity_subjects (id, oidc_subject, application_id, primary_provider, primary_provider_subject, email, email_verified, status, created_at, updated_at) VALUES ($1, $2, $3, 'PrivateID', $4, $5, true, 'ACTIVE', NOW(), NOW())",
			[existingId, existingOidcSubject, applicationId, randomUUID(), "existing-h3@example.com"]
		);
		const before = (await pool.query("SELECT * FROM identity_subjects WHERE id = $1", [existingId])).rows[0];
		const verificationId = await verifiedChallenge(uniqueEmail());
		await registrationRepository.complete({ context, verificationId });
		const after = (await pool.query("SELECT * FROM identity_subjects WHERE id = $1", [existingId])).rows[0];
		expect(after).toEqual(before);
	});

	it("exposes RegistrationError instances, never raw Postgres errors, for malformed verificationId", async () => {
		await expect(registrationRepository.complete({ context, verificationId: "not-a-uuid" })).rejects.toBeInstanceOf(RegistrationError);
	});
});
