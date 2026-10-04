import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";

const databaseUrl = process.env.HAPI_EMAIL_TEST_DATABASE_URL;

describe.skipIf(!databaseUrl)("H2 durable PostgreSQL semantics", () => {
	const pool = new pg.Pool({ connectionString: databaseUrl, max: 12 });
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const subjectId = randomUUID();
	const context = { tenantId, applicationId };
	const repository = new PostgresVerificationChallengeRepository(pool);
	const otherRepository = new PostgresVerificationChallengeRepository(pool);
	const secrets = new VerificationSecrets("postgres-test-secret".repeat(3));
	const provider = new InMemoryEmailDeliveryProvider();
	let now = Date.now();
	const service = new EmailVerificationService(repository, provider, secrets, defaultVerificationPolicy, () => now);
	const otherService = new EmailVerificationService(otherRepository, provider, secrets, defaultVerificationPolicy, () => now);
	const uniqueEmail = () => `${randomUUID()}@example.com`;

	beforeAll(async () => {
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		await repository.ensureSchema();
		await repository.ensureSchema();
		await pool.query("INSERT INTO tenants VALUES ($1, 'H2 test', $2, 'active', NOW(), NOW())", [tenantId, `h2-${tenantId}`]);
		await pool.query("INSERT INTO applications VALUES ($1, $2, 'H2 test', 'h2', 'active', NOW(), NOW())", [applicationId, tenantId]);
		await pool.query("INSERT INTO identity_subjects (id, oidc_subject, primary_provider, primary_provider_subject, email, email_verified, status, created_at, updated_at) VALUES ($1, $2, 'PrivateID', $3, 'existing@example.com', false, 'ACTIVE', NOW(), NOW())", [subjectId, randomUUID(), randomUUID()]);
	});
	afterAll(async () => {
		await pool.query("DELETE FROM verification_delivery_events WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM email_verification_audit WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM verification_challenges WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM identity_subjects WHERE id = $1", [subjectId]);
		await pool.query("DELETE FROM applications WHERE id = $1", [applicationId]);
		await pool.query("DELETE FROM tenants WHERE id = $1", [tenantId]);
		await pool.end();
	});

	it("migrates idempotently and persists every first-class challenge field without plaintext OTP", async () => {
		const { challengeId } = await service.start(context, uniqueEmail(), "REGISTRATION");
		const challenge = (await otherRepository.findById(challengeId))!;
		expect(Object.keys(challenge).sort()).toEqual([
			"id", "tenantId", "applicationId", "channel", "purpose", "destinationNormalized", "destinationHash", "codeHash", "status", "expiresAt",
			"attemptCount", "maxAttempts", "sendCount", "lastSentAt", "verifiedAt", "consumedAt", "createdAt", "updatedAt"
		].sort());
		expect(challenge.codeHash).toMatch(/^[a-f0-9]{64}$/);
		expect(JSON.stringify(challenge)).not.toContain(provider.messages.at(-1)!.code);
	});
	it("separate repositories/services serialize concurrent verification and consumption with exactly one winner", async () => {
		const email = uniqueEmail();
		const before = (await pool.query("SELECT * FROM identity_subjects ORDER BY id")).rows;
		const { challengeId } = await service.start(context, email, "RECOVERY");
		const code = provider.messages.at(-1)!.code;
		const verify = await Promise.allSettled(Array.from({ length: 10 }, (_value, index) => (index % 2 ? service : otherService).verify(context, challengeId, code)));
		expect(verify.filter(result => result.status === "fulfilled")).toHaveLength(1);
		const consume = await Promise.allSettled(Array.from({ length: 10 }, (_value, index) => (index % 2 ? service : otherService).consume(context, challengeId, email, "RECOVERY")));
		expect(consume.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect((await repository.findById(challengeId))?.status).toBe("CONSUMED");
		await expect(otherService.consume(context, challengeId, email, "RECOVERY")).rejects.toThrow("INVALID_EVIDENCE");
		expect((await pool.query("SELECT * FROM identity_subjects ORDER BY id")).rows).toEqual(before);
	});
	it("serializes concurrent resend and rejects the old code across repository instances", async () => {
		const { challengeId } = await service.start(context, uniqueEmail(), "EMAIL_CHANGE");
		const old = provider.messages.at(-1)!.code;
		now += 60_000;
		const count = provider.messages.length;
		const results = await Promise.allSettled(Array.from({ length: 10 }, (_value, index) => (index % 2 ? service : otherService).resend(context, challengeId)));
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(provider.messages).toHaveLength(count + 1);
		await expect(otherService.verify(context, challengeId, old)).rejects.toThrow("INVALID_CODE");
		await expect(service.verify(context, challengeId, provider.messages.at(-1)!.code)).resolves.toMatchObject({ verified: true });
	});
	it("destination limits cannot be bypassed by concurrent starts on separate repositories", async () => {
		const email = uniqueEmail();
		const policy = { ...defaultVerificationPolicy, maxSendsPerDestinationHour: 2 };
		const first = new EmailVerificationService(repository, provider, secrets, policy, () => now);
		const second = new EmailVerificationService(otherRepository, provider, secrets, policy, () => now);
		const results = await Promise.allSettled(Array.from({ length: 10 }, (_value, index) => (index % 2 ? first : second).start(context, email, "INVITATION")));
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(2);
		const sends = await pool.query("SELECT * FROM verification_delivery_events WHERE tenant_id = $1 AND destination_hash = $2 AND state = 'SEND_REQUESTED'", [tenantId, secrets.destination(email)]);
		expect(sends.rows).toHaveLength(2);
	});
	it("commits failed attempts, expiration and audit while rolling back aborted transactions", async () => {
		const { challengeId } = await service.start(context, uniqueEmail(), "REGISTRATION");
		await expect(service.verify(context, challengeId, "wrong")).rejects.toThrow("INVALID_CODE");
		expect((await otherRepository.findById(challengeId))?.attemptCount).toBe(1);
		const challenge = (await repository.findById(challengeId))!;
		await expect(repository.transaction(context, challenge.destinationHash, snapshot => {
			snapshot.challenges[0].status = "LOCKED";
			throw new Error("rollback probe");
		})).rejects.toThrow("rollback probe");
		expect((await otherRepository.findById(challengeId))?.status).toBe("PENDING");
		now += 600_000;
		await expect(service.verify(context, challengeId, provider.messages.at(-1)!.code)).rejects.toThrow("CHALLENGE_EXPIRED");
		expect((await repository.findById(challengeId))?.status).toBe("EXPIRED");
		const audit = await pool.query("SELECT type FROM email_verification_audit WHERE challenge_id = $1", [challengeId]);
		expect(audit.rows.map(row => row.type)).toContain("EMAIL_VERIFICATION_EXPIRED");
	});
	it("concurrent webhook replay has one durable event and never establishes ownership", async () => {
		const { challengeId } = await service.start(context, uniqueEmail(), "REGISTRATION");
		const messageId = provider.messages.at(-1)!.sendId;
		const eventId = `resend:${randomUUID()}`;
		await Promise.all(Array.from({ length: 10 }, (_value, index) => (index % 2 ? service : otherService).recordProviderEvent(messageId, eventId, "DELIVERED")));
		const events = await pool.query("SELECT * FROM verification_delivery_events WHERE id = $1", [eventId]);
		expect(events.rows).toHaveLength(1);
		expect((await repository.findById(challengeId))?.status).toBe("PENDING");
	});
});