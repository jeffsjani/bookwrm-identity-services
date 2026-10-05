import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { InMemoryVerificationChallengeRepository } from "../src/email/InMemoryVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import type { EmailAuthenticationRepository } from "../src/authentication/email/EmailAuthenticationTypes.js";
import { registerEmailAuthenticationRoutes } from "../src/routes/emailAuthentication.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { configureEmailVerification } from "../src/adapters/email/EmailVerificationComposition.js";

function fixture(overrides = {}) {
	const context = { tenantId: randomUUID(), applicationId: randomUUID() };
	const authority = { context, clientId: "h4-client" };
	const challenges = new InMemoryVerificationChallengeRepository();
	const provider = new InMemoryEmailDeliveryProvider();
	let now = Date.now();
	const h2 = new EmailVerificationService(challenges, provider,
		new VerificationSecrets("h4-local-test-secret".repeat(3)),
		{ ...defaultVerificationPolicy, ...overrides }, () => now);
	const repository: EmailAuthenticationRepository = {
		audit: vi.fn(async () => {}),
		establish: vi.fn(async () => ({
			authenticated: true as const, subject: "stable-subject", authenticationResult: "opaque-result",
			expiresIn: 60, authenticationMethod: "HAPI_EMAIL" as const,
			authenticatedAt: new Date(now).toISOString(), assurance: "email_otp" as const
		})),
		consumeResult: vi.fn(async () => ({
			id: "internal", sub: "stable-subject", authenticationMethod: "HAPI_EMAIL" as const,
			authenticatedAt: new Date(now).toISOString(), assurance: "email_otp" as const
		}))
	};
	const service = new EmailAuthenticationService(h2, challenges, repository);
	return { service, h2, challenges, provider, authority, repository, advance: (seconds: number) => { now += seconds * 1000; } };
}

describe("H4 reuses H2 lifecycle", () => {
	it("starts without identity lookup; verifies through H2 and resolves only verified evidence", async () => {
		const f = fixture();
		const start = await f.service.start(f.authority, "Person@EXAMPLE.COM");
		expect(start).toEqual({ challengeId: expect.any(String), expiresIn: 600, resendAfter: 60 });
		expect(f.provider.messages[0]).toMatchObject({ destination: "Person@example.com", purpose: "AUTHENTICATION" });
		expect(f.repository.establish).not.toHaveBeenCalled();
		expect(await f.service.verify(f.authority, start.challengeId, f.provider.messages[0].code))
			.toMatchObject({ authenticated: true, subject: "stable-subject", expiresIn: 60 });
		expect(f.repository.establish).toHaveBeenCalledExactlyOnceWith(f.authority, start.challengeId);
		expect(f.repository.audit).toHaveBeenCalledWith(f.authority, "EMAIL_AUTHENTICATION_VERIFIED", start.challengeId, "EMAIL_PROVED");
	});
	it("wrong OTP never establishes a principal and exhausted attempts lock", async () => {
		const f = fixture({ maxAttempts: 2 });
		const start = await f.service.start(f.authority, "a@example.com");
		for (let n = 0; n < 2; n++) await expect(f.service.verify(f.authority, start.challengeId, "wrong")).rejects.toThrow("INVALID_CODE");
		expect((await f.challenges.findById(start.challengeId))?.status).toBe("LOCKED");
		expect(f.repository.establish).not.toHaveBeenCalled();
		expect(f.repository.audit).toHaveBeenCalledWith(f.authority, "EMAIL_AUTHENTICATION_FAILED", start.challengeId, "INVALID_CODE");
	});
	it("expired OTP fails closed", async () => {
		const f = fixture();
		const start = await f.service.start(f.authority, "a@example.com");
		f.advance(600);
		await expect(f.service.verify(f.authority, start.challengeId, f.provider.messages[0].code)).rejects.toThrow("CHALLENGE_EXPIRED");
		expect(f.repository.establish).not.toHaveBeenCalled();
	});
	it("resend keeps challenge, rotates OTP, rejects old code", async () => {
		const f = fixture();
		const start = await f.service.start(f.authority, "a@example.com");
		await expect(f.service.resend(f.authority, start.challengeId)).rejects.toThrow("RATE_LIMITED");
		f.advance(60);
		expect(await f.service.resend(f.authority, start.challengeId)).toEqual(start);
		expect(f.provider.messages[1].code).not.toBe(f.provider.messages[0].code);
		await expect(f.service.verify(f.authority, start.challengeId, f.provider.messages[0].code)).rejects.toThrow("INVALID_CODE");
		await expect(f.service.verify(f.authority, start.challengeId, f.provider.messages[1].code)).resolves.toMatchObject({ authenticated: true });
	});
	it("rate limits share the existing H2 destination budget across purposes", async () => {
		const f = fixture({ maxSendsPerDestinationHour: 1 });
		await f.h2.start(f.authority.context, "a@example.com", "REGISTRATION");
		await expect(f.service.start(f.authority, "a@example.com")).rejects.toThrow("RATE_LIMITED");
		expect(f.repository.audit).toHaveBeenCalledWith(f.authority, "EMAIL_AUTHENTICATION_RATE_LIMITED", null, "RATE_LIMITED");
	});
	it.each(["tenantId", "applicationId"] as const)("rejects wrong %s without changing evidence", async field => {
		const f = fixture();
		const start = await f.service.start(f.authority, "a@example.com");
		const wrong = { ...f.authority, context: { ...f.authority.context, [field]: randomUUID() } };
		await expect(f.service.verify(wrong, start.challengeId, f.provider.messages[0].code)).rejects.toThrow("INVALID_CHALLENGE");
		await expect(f.service.resend(wrong, start.challengeId)).rejects.toThrow("INVALID_CHALLENGE");
		expect((await f.challenges.findById(start.challengeId))?.attemptCount).toBe(0);
	});
	it("rejects other purposes before verify or resend can mutate them", async () => {
		const f = fixture();
		const start = await f.h2.start(f.authority.context, "a@example.com", "REGISTRATION");
		f.advance(60);
		await expect(f.service.resend(f.authority, start.challengeId)).rejects.toThrow("INVALID_CHALLENGE");
		await expect(f.service.verify(f.authority, start.challengeId, f.provider.messages[0].code)).rejects.toThrow("INVALID_CHALLENGE");
		expect((await f.challenges.findById(start.challengeId))?.status).toBe("PENDING");
	});
	it("concurrent verify has one winner and replay never produces another result", async () => {
		const f = fixture();
		const start = await f.service.start(f.authority, "a@example.com");
		const attempts = await Promise.allSettled(Array.from({ length: 8 }, () =>
			f.service.verify(f.authority, start.challengeId, f.provider.messages[0].code)));
		expect(attempts.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(f.repository.establish).toHaveBeenCalledTimes(1);
		await expect(f.service.verify(f.authority, start.challengeId, f.provider.messages[0].code)).rejects.toThrow("INVALID_CHALLENGE");
	});
});

describe("H4 HTTP trusted-client boundary", () => {
	async function appFixture() {
		const f = fixture();
		const tenants = new InMemoryTenantRepository();
		const applications = new InMemoryApplicationRepository();
		const clients = new InMemoryOIDCClientRepository();
		await tenants.upsert({ id: f.authority.context.tenantId, name: "H4", slug: "h4", status: "active" });
		await applications.upsert({ id: f.authority.context.applicationId, tenantId: f.authority.context.tenantId, name: "H4", slug: "h4", status: "active" });
		await clients.upsert({ id: randomUUID(), applicationId: f.authority.context.applicationId,
			clientId: f.authority.clientId, clientSecret: "test-secret", redirectUris: ["https://rp.example/callback"],
			scopes: ["openid", "email"], grantTypes: ["authorization_code"], responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
		const app = Fastify();
		await registerEmailAuthenticationRoutes(app, f.service, { tenants, applications, clients });
		const headers = { authorization: "Basic " + Buffer.from("h4-client:test-secret").toString("base64") };
		return { ...f, app, headers, tenants, applications, clients };
	}
	it("existing and unknown start responses share exactly the same shape/status and delivery path", async () => {
		const f = await appFixture();
		try {
			for (const email of ["existing@example.com", "unknown@example.com"]) {
				const r = await f.app.inject({ method: "POST", url: "/v1/authentication/email/start", headers: f.headers, payload: { email } });
				expect(r.statusCode).toBe(200);
				expect(r.json()).toEqual({ challengeId: expect.any(String), expiresIn: 600, resendAfter: 60 });
				expect(r.headers["cache-control"]).toBe("no-store");
			}
			expect(f.repository.establish).not.toHaveBeenCalled();
			expect(f.provider.messages).toHaveLength(2);
		} finally { await f.app.close(); }
	});
	it("rejects untrusted requests, body injection, malformed JSON, and public clients", async () => {
		const f = await appFixture();
		try {
			expect((await f.app.inject({ method: "POST", url: "/v1/authentication/email/start", payload: { email: "a@example.com" } })).statusCode).toBe(401);
			for (const field of ["tenantId", "applicationId", "emailVerified", "purpose"]) {
				expect((await f.app.inject({ method: "POST", url: "/v1/authentication/email/start", headers: f.headers,
					payload: { email: "a@example.com", [field]: "injected" } })).statusCode).toBe(400);
			}
			const malformed = await f.app.inject({ method: "POST", url: "/v1/authentication/email/verify",
				headers: { ...f.headers, "content-type": "application/json" }, payload: '{"code":"not-for-output",' });
			expect(malformed.statusCode).toBe(400);
			expect(malformed.json()).toEqual({ error: "INVALID_REQUEST" });
			expect(malformed.headers["cache-control"]).toBe("no-store");
			const client = await f.clients.findByClientId("h4-client");
			await f.clients.upsert({ ...client!, tokenEndpointAuthMethod: "none" });
			expect((await f.app.inject({ method: "POST", url: "/v1/authentication/email/start", headers: f.headers,
				payload: { email: "a@example.com" } })).statusCode).toBe(401);
		} finally { await f.app.close(); }
	});
	it("returns an explicit sanitized failure if result persistence is unavailable", async () => {
		const f = await appFixture();
		try {
			const started = await f.service.start(f.authority, "a@example.com");
			vi.mocked(f.repository.establish).mockRejectedValueOnce(new Error("backend-only-detail"));
			const response = await f.app.inject({ method: "POST", url: "/v1/authentication/email/verify",
				headers: f.headers, payload: { challengeId: started.challengeId, code: f.provider.messages[0].code } });
			expect(response.statusCode).toBe(503);
			expect(response.json()).toEqual({ error: "AUTHENTICATION_UNAVAILABLE" });
			expect(f.repository.audit).toHaveBeenCalledWith(f.authority, "EMAIL_AUTHENTICATION_FAILED",
				started.challengeId, "AUTHENTICATION_UNAVAILABLE");
		} finally { await f.app.close(); }
	});
	it("is opt-in and rejects incomplete feature configuration", async () => {
		const app = Fastify();
		await expect(configureEmailVerification(app, {})).resolves.toBeUndefined();
		await expect(configureEmailVerification(app, { HAPI_EMAIL_AUTHENTICATION_ENABLED: "true" })).rejects.toThrow("requires H2");
		await expect(configureEmailVerification(app, { HAPI_EMAIL_AUTHENTICATION_ENABLED: "invalid" })).rejects.toThrow("must be true or false");
		await app.close();
	});
});
