import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { InMemoryVerificationChallengeRepository } from "../src/email/InMemoryVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { InMemoryRegistrationRepository } from "../src/registration/InMemoryRegistrationRepository.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";
import { registerRegistrationRoutes } from "../src/routes/registration.js";

async function apiFixture() {
	const challenges = new InMemoryVerificationChallengeRepository();
	const provider = new InMemoryEmailDeliveryProvider();
	const secrets = new VerificationSecrets("route-test-secret".repeat(3));
	const emailService = new EmailVerificationService(challenges, provider, secrets, defaultVerificationPolicy);
	const subjects = new InMemoryIdentitySubjectRepository();
	const registration = new RegistrationService(new InMemoryRegistrationRepository(challenges, subjects));

	const tenants = new InMemoryTenantRepository();
	const applications = new InMemoryApplicationRepository();
	const clients = new InMemoryOIDCClientRepository();
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const otherApplicationId = randomUUID();
	await tenants.upsert({ id: tenantId, name: "t", slug: "t", status: "active" });
	await applications.upsert({ id: applicationId, tenantId, name: "a", slug: "a", status: "active" });
	await applications.upsert({ id: otherApplicationId, tenantId, name: "other", slug: "other", status: "active" });
	await clients.upsert({ id: randomUUID(), clientId: "client", clientSecret: "client-secret", applicationId,
		redirectUris: [], scopes: [], grantTypes: [], responseTypes: [], requirePkce: true, tokenEndpointAuthMethod: "client_secret_basic" });
	await clients.upsert({ id: randomUUID(), clientId: "public-client", clientSecret: "", applicationId,
		redirectUris: [], scopes: [], grantTypes: [], responseTypes: [], requirePkce: true, tokenEndpointAuthMethod: "none" });

	const app = Fastify();
	await registerRegistrationRoutes(app, registration, { clients, applications, tenants });
	const headers = (clientId = "client", secret = "client-secret") => ({ authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}` });

	const context = { tenantId, applicationId };
	async function verifiedChallenge(email: string, purpose: "REGISTRATION" | "RECOVERY" = "REGISTRATION") {
		const { challengeId } = await emailService.start(context, email, purpose);
		const code = provider.messages.at(-1)!.code;
		await emailService.verify(context, challengeId, code);
		return challengeId;
	}

	return { app, headers, verifiedChallenge, tenantId, applicationId, otherApplicationId, clients };
}

describe("H3 HTTP /v1/registration/complete", () => {
	it("valid verificationId registers and returns an application-neutral payload", async () => {
		const { app, headers, verifiedChallenge } = await apiFixture();
		try {
			const verificationId = await verifiedChallenge("person@example.com");
			const response = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: headers(), payload: { verificationId } });
			expect(response.statusCode).toBe(200);
			const body = response.json();
			expect(body).toEqual({ registered: true, subject: expect.any(String), email: "person@example.com", emailVerified: true });
			expect(body.subject).not.toContain(verificationId);
			expect(response.headers["cache-control"]).toBe("no-store");
		} finally { await app.close(); }
	});

	it("rejects missing/invalid Basic auth with 401 and never leaks whether the client exists", async () => {
		const { app, verifiedChallenge } = await apiFixture();
		try {
			const verificationId = await verifiedChallenge("person@example.com");
			const noAuth = await app.inject({ method: "POST", url: "/v1/registration/complete", payload: { verificationId } });
			expect(noAuth.statusCode).toBe(401);
			const badSecret = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: { authorization: `Basic ${Buffer.from("client:wrong").toString("base64")}` }, payload: { verificationId } });
			expect(badSecret.statusCode).toBe(401);
			const unknownClient = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: { authorization: `Basic ${Buffer.from("ghost:ghost").toString("base64")}` }, payload: { verificationId } });
			expect(unknownClient.statusCode).toBe(401);
			const publicClient = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: { authorization: `Basic ${Buffer.from("public-client:").toString("base64")}` }, payload: { verificationId } });
			expect(publicClient.statusCode).toBe(401);
		} finally { await app.close(); }
	});

	it("Task 3/19: the .strict() schema rejects any client-supplied email/tenantId/emailVerified/claimSource/oidcSubject injection", async () => {
		const { app, headers, verifiedChallenge } = await apiFixture();
		try {
			const verificationId = await verifiedChallenge("person@example.com");
			for (const injected of [
				{ verificationId, email: "attacker@example.com" },
				{ verificationId, tenantId: randomUUID() },
				{ verificationId, emailVerified: true },
				{ verificationId, claimSource: "HAPI_EMAIL" },
				{ verificationId, oidcSubject: "attacker-controlled-sub" }
			]) {
				const response = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: headers(), payload: injected });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toEqual({ error: "INVALID_REQUEST" });
			}
		} finally { await app.close(); }
	});

	it("cross-tenant and cross-application verification references are both rejected as INVALID_EVIDENCE via the trusted H1 context, never the request body", async () => {
		const { app, headers, verifiedChallenge } = await apiFixture();
		try {
			const verificationId = await verifiedChallenge("person@example.com");
			const otherTenantApp = await apiFixture();
			try {
				const crossTenant = await otherTenantApp.app.inject({ method: "POST", url: "/v1/registration/complete", headers: otherTenantApp.headers(), payload: { verificationId } });
				expect(crossTenant.statusCode).toBe(400);
				expect(crossTenant.json()).toEqual({ error: "INVALID_EVIDENCE" });
			} finally { await otherTenantApp.app.close(); }
		} finally { await app.close(); }
	});

	it("a client bound to a different application in the SAME tenant is also rejected as INVALID_EVIDENCE", async () => {
		const { app, verifiedChallenge, otherApplicationId, clients } = await apiFixture();
		try {
			await clients.upsert({ id: randomUUID(), clientId: "other-app-client", clientSecret: "client-secret", applicationId: otherApplicationId,
				redirectUris: [], scopes: [], grantTypes: [], responseTypes: [], requirePkce: true, tokenEndpointAuthMethod: "client_secret_basic" });
			const verificationId = await verifiedChallenge("person@example.com");
			const header = { authorization: `Basic ${Buffer.from("other-app-client:client-secret").toString("base64")}` };
			const response = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: header, payload: { verificationId } });
			expect(response.statusCode).toBe(400);
			expect(response.json()).toEqual({ error: "INVALID_EVIDENCE" });
		} finally { await app.close(); }
	});

	it("wrong purpose (RECOVERY) evidence is rejected for registration", async () => {
		const { app, headers, verifiedChallenge } = await apiFixture();
		try {
			const verificationId = await verifiedChallenge("person@example.com", "RECOVERY");
			const response = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: headers(), payload: { verificationId } });
			expect(response.statusCode).toBe(400);
			expect(response.json()).toEqual({ error: "INVALID_PURPOSE" });
		} finally { await app.close(); }
	});

	it("a successful retry of the same verificationId is idempotent at the HTTP layer and returns the same subject", async () => {
		const { app, headers, verifiedChallenge } = await apiFixture();
		try {
			const verificationId = await verifiedChallenge("person@example.com");
			const first = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: headers(), payload: { verificationId } });
			const second = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: headers(), payload: { verificationId } });
			expect(first.statusCode).toBe(200);
			expect(second.statusCode).toBe(200);
			expect(second.json().subject).toBe(first.json().subject);
		} finally { await app.close(); }
	});

	it("malformed JSON is rejected without ever echoing or logging request content", async () => {
		const { app, headers } = await apiFixture();
		try {
			const response = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: { ...headers(), "content-type": "application/json" }, payload: "{\"verificationId\":" });
			expect(response.statusCode).toBe(400);
			expect(response.json()).toEqual({ error: "INVALID_REQUEST" });
		} finally { await app.close(); }
	});

	it("unknown/guessed verificationId is rejected as INVALID_EVIDENCE, not a 404/500 that would confirm existence", async () => {
		const { app, headers } = await apiFixture();
		try {
			const response = await app.inject({ method: "POST", url: "/v1/registration/complete", headers: headers(), payload: { verificationId: randomUUID() } });
			expect(response.statusCode).toBe(400);
			expect(response.json()).toEqual({ error: "INVALID_EVIDENCE" });
		} finally { await app.close(); }
	});
});
