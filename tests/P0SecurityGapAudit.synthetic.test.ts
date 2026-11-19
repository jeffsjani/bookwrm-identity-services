// P0 Security Gap Verification — controlled synthetic tests (isolated infrastructure only).
// Phase A/D: concurrent wrong-code OTP floods must never exceed maxAttempts, lockout must be
// durable across repository instances ("restarts"), and resend must not reset attempt counts.
// Phase C: OIDCRateLimiter behavior under injected Redis faults (outage, hang, partial failure).
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";

const databaseUrl = process.env.HAPI_EMAIL_TEST_DATABASE_URL;

describe.skipIf(!databaseUrl)("Phase A/D — OTP attempt limiting under concurrency and restart", () => {
	const pool = new pg.Pool({ connectionString: databaseUrl, max: 16 });
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const context = { tenantId, applicationId };
	const secrets = new VerificationSecrets("p0-audit-secret".repeat(4));
	const provider = new InMemoryEmailDeliveryProvider();
	let now = Date.now();
	// Two independent repository/service instances simulate two application instances.
	const repositoryA = new PostgresVerificationChallengeRepository(pool);
	const repositoryB = new PostgresVerificationChallengeRepository(pool);
	const serviceA = new EmailVerificationService(repositoryA, provider, secrets, defaultVerificationPolicy, () => now);
	const serviceB = new EmailVerificationService(repositoryB, provider, secrets, defaultVerificationPolicy, () => now);
	const uniqueEmail = () => `${randomUUID()}@example.com`;

	beforeAll(async () => {
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		await repositoryA.ensureSchema();
		await pool.query("INSERT INTO tenants VALUES ($1, 'P0 audit', $2, 'active', NOW(), NOW())", [tenantId, `p0-${tenantId}`]);
		await pool.query(
			"INSERT INTO applications (id,tenant_id,name,slug,status,created_at,updated_at,application_key) VALUES ($1::uuid,$2,'P0 audit','p0','active',NOW(),NOW(),$1::text)",
			[applicationId, tenantId]);
	});
	afterAll(async () => {
		await pool.query("DELETE FROM verification_delivery_events WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM email_verification_audit WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM verification_challenges WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM applications WHERE tenant_id = $1", [tenantId]);
		await pool.query("DELETE FROM tenants WHERE id = $1", [tenantId]);
		await pool.end();
	});

	it("25 concurrent wrong codes across two instances consume exactly maxAttempts and lock once", async () => {
		const email = uniqueEmail();
		const { challengeId } = await serviceA.start(context, email, "AUTHENTICATION");
		const flood = await Promise.allSettled(Array.from({ length: 25 }, (_v, index) =>
			(index % 2 ? serviceA : serviceB).verify(context, challengeId, "000000")));
		expect(flood.every(outcome => outcome.status === "rejected")).toBe(true);
		const challenge = await repositoryB.findById(challengeId);
		expect(challenge?.status).toBe("LOCKED");
		expect(challenge?.attemptCount).toBe(defaultVerificationPolicy.maxAttempts);
		const lockedEvents = await pool.query(
			"SELECT COUNT(*)::int AS count FROM email_verification_audit WHERE challenge_id = $1 AND type = 'EMAIL_VERIFICATION_LOCKED'",
			[challengeId]);
		expect(lockedEvents.rows[0].count).toBe(1);
		// Even the genuine code is rejected after lockout, and the stored code hash was destroyed.
		const code = provider.messages.at(-1)!.code;
		await expect(serviceA.verify(context, challengeId, code)).rejects.toThrow("INVALID_CHALLENGE");
		expect(challenge?.codeHash).toBe("");
	});

	it("lockout is visible to a brand-new pool and repository (restart persistence)", async () => {
		const email = uniqueEmail();
		const { challengeId } = await serviceA.start(context, email, "AUTHENTICATION");
		for (let attempt = 0; attempt < defaultVerificationPolicy.maxAttempts; attempt++) {
			await expect(serviceA.verify(context, challengeId, "000000")).rejects.toThrow();
		}
		const freshPool = new pg.Pool({ connectionString: databaseUrl, max: 2 });
		try {
			const freshRepository = new PostgresVerificationChallengeRepository(freshPool);
			const seen = await freshRepository.findById(challengeId);
			expect(seen?.status).toBe("LOCKED");
			expect(seen?.attemptCount).toBe(defaultVerificationPolicy.maxAttempts);
		} finally {
			await freshPool.end();
		}
	});

	it("resend issues a new code but never resets the failed attempt count", async () => {
		const email = uniqueEmail();
		const { challengeId } = await serviceA.start(context, email, "AUTHENTICATION");
		await expect(serviceA.verify(context, challengeId, "000000")).rejects.toThrow("INVALID_CODE");
		await expect(serviceB.verify(context, challengeId, "000000")).rejects.toThrow("INVALID_CODE");
		now += (defaultVerificationPolicy.resendCooldownSeconds + 1) * 1000;
		await serviceB.resend(context, challengeId);
		const challenge = await repositoryA.findById(challengeId);
		expect(challenge?.attemptCount).toBe(2);
		expect(challenge?.status).toBe("PENDING");
		// Remaining budget is only maxAttempts - 2 regardless of the resend.
		await expect(serviceA.verify(context, challengeId, "000001")).rejects.toThrow("INVALID_CODE");
		await expect(serviceB.verify(context, challengeId, "000002")).rejects.toThrow("INVALID_CODE");
		await expect(serviceA.verify(context, challengeId, "000003")).rejects.toThrow("INVALID_CODE");
		expect((await repositoryB.findById(challengeId))?.status).toBe("LOCKED");
	});

	it("fresh challenges for one destination stay bounded by the hourly destination send budget", async () => {
		const email = uniqueEmail();
		const outcomes: string[] = [];
		for (let round = 0; round < defaultVerificationPolicy.maxSendsPerDestinationHour + 3; round++) {
			try {
				await serviceA.start(context, email, "AUTHENTICATION");
				outcomes.push("started");
			} catch (error) {
				outcomes.push((error as Error).message);
			}
		}
		expect(outcomes.filter(outcome => outcome === "started")).toHaveLength(defaultVerificationPolicy.maxSendsPerDestinationHour);
		expect(outcomes.at(-1)).toBe("RATE_LIMITED");
	});
});

// Phase C — OIDCRateLimiter under injected Redis faults. The limiter resolves its client via
// getRedisClient(), so the module is mocked with a controllable stub.
type StubBehavior = {
	incr: (key: string) => Promise<number>;
	expire: (key: string, seconds: number) => Promise<number>;
};
const stub: { behavior: StubBehavior } = {
	behavior: { incr: async () => 1, expire: async () => 1 }
};
vi.mock("../src/oidc/infrastructure/RedisInfrastructure.js", () => ({
	getRedisClient: () => ({
		incr: (key: string) => stub.behavior.incr(key),
		expire: (key: string, seconds: number) => stub.behavior.expire(key, seconds)
	}),
	oidcRedisKey: (key: string) => `oidc:${key}`
}));

describe("Phase C — rate limiter behavior under injected Redis faults", () => {
	beforeEach(() => {
		stub.behavior = { incr: async () => 1, expire: async () => 1 };
	});

	it("a Redis outage rejects the request instead of allowing it (fail-closed, non-429)", async () => {
		const { OIDCRateLimiter } = await import("../src/oidc/infrastructure/OIDCRateLimiter.js");
		stub.behavior.incr = async () => { throw new Error("connection refused"); };
		const limiter = new OIDCRateLimiter();
		const outcome = limiter.assertWithinLimits({ ip: "198.51.100.7", clientId: "", userId: "" });
		await expect(outcome).rejects.toThrow("connection refused");
		await outcome.catch((error: Error & { statusCode?: number }) => {
			// No statusCode: callers map this to 5xx/unavailable, never to an allowed attempt.
			expect(error.statusCode).toBeUndefined();
		});
	});

	it("a hung Redis command leaves the request pending indefinitely (availability hazard, no timeout)", async () => {
		const { OIDCRateLimiter } = await import("../src/oidc/infrastructure/OIDCRateLimiter.js");
		stub.behavior.incr = () => new Promise<never>(() => undefined);
		const limiter = new OIDCRateLimiter();
		const outcome = Promise.race([
			limiter.assertWithinLimits({ ip: "198.51.100.8", clientId: "", userId: "" }).then(() => "resolved", () => "rejected"),
			new Promise<string>(resolve => setTimeout(() => resolve("still-pending"), 250))
		]);
		await expect(outcome).resolves.toBe("still-pending");
	});

	it("an expire failure after the first incr strands a TTL-less counter that keeps throttling (no automatic reset)", async () => {
		const { OIDCRateLimiter } = await import("../src/oidc/infrastructure/OIDCRateLimiter.js");
		const counters = new Map<string, number>();
		stub.behavior.incr = async key => {
			const next = (counters.get(key) ?? 0) + 1;
			counters.set(key, next);
			return next;
		};
		stub.behavior.expire = async () => { throw new Error("expire failed"); };
		const limiter = new OIDCRateLimiter();
		const context = { ip: "198.51.100.9", clientId: "", userId: "" };
		// First request errors after already consuming count 1, and no TTL is ever attached.
		await expect(limiter.assertWithinLimits(context)).rejects.toThrow("expire failed");
		let firstLimited: number | undefined;
		for (let request = 2; request <= 125; request++) {
			try {
				await limiter.assertWithinLimits(context);
			} catch (error) {
				firstLimited = request;
				expect((error as Error & { statusCode?: number }).statusCode).toBe(429);
				break;
			}
		}
		// Limit default is 120/minute: the stranded counter still enforces it, and because the key
		// has no TTL this bucket would now throttle this identifier forever (never self-heals).
		expect(firstLimited).toBe(121);
		expect(counters.get("oidc:ratelimit:ip:198.51.100.9")).toBe(121);
	});
});
