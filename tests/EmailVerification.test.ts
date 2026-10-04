import { describe, expect, it, vi } from "vitest";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import Fastify from "fastify";
import { parse } from "@babel/parser";
import { Webhook } from "svix";
import { normalizeEmail } from "../src/email/EmailNormalizationService.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy, verificationPolicyFromEnvironment } from "../src/email/VerificationPolicy.js";
import { InMemoryVerificationChallengeRepository } from "../src/email/InMemoryVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { registerEmailVerificationRoutes } from "../src/routes/emailVerification.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { inMemoryIdentitySubjectRepository, InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { ResendEmailDeliveryProvider } from "../src/adapters/email/resend/ResendEmailDeliveryProvider.js";
import { registerResendWebhook } from "../src/adapters/email/resend/ResendWebhookAdapter.js";

const context = { tenantId: "tenant", applicationId: "application" };
function fixture(overrides = {}) {
	const repository = new InMemoryVerificationChallengeRepository();
	const provider = new InMemoryEmailDeliveryProvider();
	let now = Date.parse("2026-10-04T12:00:00Z");
	const policy = { ...defaultVerificationPolicy, ...overrides };
	const service = new EmailVerificationService(repository, provider, new VerificationSecrets("test-secret".repeat(4)), policy, () => now);
	return { repository, provider, service, advance: (seconds: number) => { now += seconds * 1000; } };
}

describe("H2 challenge lifecycle", () => {
	it("correct OTP produces bound verified evidence, never a subject", async () => {
		const { service, provider, repository } = fixture();
		const started = await service.start(context, "Person@example.com", "REGISTRATION");
		expect(started).toEqual({ challengeId: expect.any(String), expiresIn: 600, resendAfter: 60 });
		expect(await service.verify(context, started.challengeId, provider.messages[0].code)).toEqual({ verified: true, verificationId: started.challengeId });
		expect((await repository.findById(started.challengeId))?.status).toBe("VERIFIED");
	});
	it("incorrect OTP consumes attempts and locks at the configured maximum", async () => {
		const { service, repository } = fixture();
		const { challengeId } = await service.start(context, "a@example.com", "RECOVERY");
		for (let attempt = 0; attempt < 5; attempt++) await expect(service.verify(context, challengeId, "wrong")).rejects.toThrow("INVALID_CODE");
		expect((await repository.findById(challengeId))?.status).toBe("LOCKED");
		await expect(service.resend(context, challengeId)).rejects.toThrow("INVALID_CHALLENGE");
		expect(repository.inspect().audit.map(event => event.type)).toContain("EMAIL_VERIFICATION_LOCKED");
	});
	it("expires without producing evidence", async () => {
		const { service, provider, repository, advance } = fixture();
		const { challengeId } = await service.start(context, "a@example.com", "INVITATION");
		advance(600);
		await expect(service.verify(context, challengeId, provider.messages[0].code)).rejects.toThrow("CHALLENGE_EXPIRED");
		expect((await repository.findById(challengeId))?.status).toBe("EXPIRED");
	});
	it("enforces cooldown, resends on one challenge, rejects old code", async () => {
		const { service, provider, repository, advance } = fixture();
		const { challengeId } = await service.start(context, "a@example.com", "EMAIL_CHANGE");
		await expect(service.resend(context, challengeId)).rejects.toThrow("RATE_LIMITED");
		advance(60);
		await service.resend(context, challengeId);
		expect(repository.inspect().challenges).toHaveLength(1);
		expect(provider.messages[1].code).not.toBe(provider.messages[0].code);
		await expect(service.verify(context, challengeId, provider.messages[0].code)).rejects.toThrow("INVALID_CODE");
		await expect(service.verify(context, challengeId, provider.messages[1].code)).resolves.toMatchObject({ verified: true });
	});
	it("enforces sends per challenge without resetting verification attempts", async () => {
		const { service, repository, advance } = fixture({ maxSendsPerChallenge: 2 });
		const { challengeId } = await service.start(context, "a@example.com", "REGISTRATION");
		await expect(service.verify(context, challengeId, "wrong")).rejects.toThrow();
		advance(60);
		await service.resend(context, challengeId);
		advance(60);
		await expect(service.resend(context, challengeId)).rejects.toThrow("RATE_LIMITED");
		expect((await repository.findById(challengeId))?.attemptCount).toBe(1);
	});
	it.each(["Hour", "Day"])("enforces rolling destination/%s limits across applications", async period => {
		const { service } = fixture({ [`maxSendsPerDestination${period}`]: 2 });
		await service.start(context, "a@example.com", "REGISTRATION");
		await service.start({ ...context, applicationId: "other" }, "a@example.com", "RECOVERY");
		await expect(service.start(context, "a@example.com", "REGISTRATION")).rejects.toThrow("RATE_LIMITED");
		await expect(service.start({ ...context, tenantId: "other" }, "a@example.com", "REGISTRATION")).resolves.toBeDefined();
	});
	it("rejects cross-tenant, cross-application, wrong purpose and unbound consumption", async () => {
		const { service, provider } = fixture();
		const { challengeId } = await service.start(context, "a@example.com", "RECOVERY");
		const code = provider.messages[0].code;
		await expect(service.verify({ ...context, tenantId: "other" }, challengeId, code)).rejects.toThrow("INVALID_CHALLENGE");
		await expect(service.verify({ ...context, applicationId: "other" }, challengeId, code)).rejects.toThrow("INVALID_CHALLENGE");
		await expect(service.verify(context, challengeId, code, "REGISTRATION")).rejects.toThrow("INVALID_CHALLENGE");
		await expect(service.consume(context, challengeId, "a@example.com", "RECOVERY")).rejects.toThrow("INVALID_EVIDENCE");
		await service.verify(context, challengeId, code);
		await expect(service.consume(context, challengeId, "b@example.com", "RECOVERY")).rejects.toThrow("INVALID_EVIDENCE");
		await expect(service.consume(context, challengeId, "a@example.com", "REGISTRATION")).rejects.toThrow("INVALID_EVIDENCE");
	});
	it("concurrent verify and consume each have one winner; consumed evidence cannot be reused", async () => {
		const { service, provider, repository } = fixture();
		const { challengeId } = await service.start(context, "a@example.com", "REGISTRATION");
		const verified = await Promise.allSettled(Array.from({ length: 8 }, () => service.verify(context, challengeId, provider.messages[0].code)));
		expect(verified.filter(result => result.status === "fulfilled")).toHaveLength(1);
		const consumed = await Promise.allSettled(Array.from({ length: 8 }, () => service.consume(context, challengeId, "a@example.com", "REGISTRATION")));
		expect(consumed.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect((await repository.findById(challengeId))?.status).toBe("CONSUMED");
		await expect(service.consume(context, challengeId, "a@example.com", "REGISTRATION")).rejects.toThrow("INVALID_EVIDENCE");
	});
	it("concurrent resend and concurrent destination sends have one winner", async () => {
		const { service, advance, provider } = fixture({ maxSendsPerDestinationHour: 2 });
		const { challengeId } = await service.start(context, "a@example.com", "REGISTRATION");
		advance(60);
		const results = await Promise.allSettled(Array.from({ length: 8 }, () => service.resend(context, challengeId)));
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(provider.messages).toHaveLength(2);
		const starts = await Promise.allSettled(Array.from({ length: 8 }, () => service.start(context, "b@example.com", "REGISTRATION")));
		expect(starts.filter(result => result.status === "fulfilled")).toHaveLength(2);
	});
	it("does not persist plaintext OTP or put secrets/email in audit and telemetry", async () => {
		const { service, repository, provider } = fixture();
		await service.start(context, "sensitive@example.com", "REGISTRATION");
		const snapshot = repository.inspect();
		expect(JSON.stringify(snapshot)).not.toContain(provider.messages[0].code);
		expect(JSON.stringify([...snapshot.audit, ...snapshot.delivery])).not.toContain("sensitive@example.com");
		expect(JSON.stringify([...snapshot.audit, ...snapshot.delivery])).not.toContain("codeHash");
	});
	it("delivery telemetry never verifies ownership and webhook replay is idempotent", async () => {
		const { service, provider, repository } = fixture();
		const { challengeId } = await service.start(context, "a@example.com", "REGISTRATION");
		for (const state of ["DELIVERED", "DEFERRED", "BOUNCED", "COMPLAINED", "SUPPRESSED", "PROVIDER_FAILED"] as const) {
			await service.recordProviderEvent(provider.messages[0].sendId, state, state);
			await service.recordProviderEvent(provider.messages[0].sendId, state, state);
		}
		expect((await repository.findById(challengeId))?.status).toBe("PENDING");
		expect(repository.inspect().delivery.filter(event => event.state === "DELIVERED")).toHaveLength(1);
	});
	it.each(["failure", "timeout"])("handles provider %s without leaking provider errors or establishing evidence", async mode => {
		const { repository } = fixture();
		const provider = { sendVerificationEmail: async () => {
			if (mode === "failure") throw new Error("provider secret payload");
			return new Promise<{ messageId: string }>(() => {});
		} };
		const service = new EmailVerificationService(repository, provider, new VerificationSecrets("test-secret".repeat(4)), { ...defaultVerificationPolicy, providerTimeoutMs: 5 });
		await expect(service.start(context, "a@example.com", "REGISTRATION")).rejects.toThrow("DELIVERY_UNAVAILABLE");
		expect(repository.inspect().challenges[0].status).toBe("PENDING");
		expect(repository.inspect().delivery.at(-1)?.state).toBe(mode === "failure" ? "PROVIDER_FAILED" : "PROVIDER_TIMEOUT");
		expect(JSON.stringify(repository.inspect())).not.toContain("provider secret");
	});
});

describe("H2 verification primitives", () => {
	it("normalizes domains deterministically without rewriting local addresses", () => {
		expect(normalizeEmail("  Person.Name+tag@GMAIL.COM  ")).toBe("Person.Name+tag@gmail.com");
		expect(normalizeEmail(normalizeEmail("A@EXAMPLE.COM"))).toBe("A@example.com");
		expect(normalizeEmail("a@b\u00fccher.example")).toBe("a@xn--bcher-kva.example");
	});
	it.each(["", "a", "a@@example.com", "a..b@example.com", "a@-example.com", "a\n@example.com",
		"a@exam\nple.com", "a@example.com/path", "a@example.com?query", "a@example.com#fragment", "a@example%2ecom", "a@example.com\\path"])("rejects malformed email %s", email => {
		expect(() => normalizeEmail(email)).toThrow("INVALID_EMAIL");
	});
	it("generates secure numeric codes and stores only challenge-bound keyed hashes", () => {
		const secrets = new VerificationSecrets("test-secret".repeat(4));
		const code = secrets.generate(6);
		expect(code).toMatch(/^\d{6}$/);
		const hash = secrets.code("challenge", code);
		expect(hash).not.toContain(code);
		expect(secrets.matches("challenge", code, hash)).toBe(true);
		expect(secrets.matches("other", code, hash)).toBe(false);
		expect(secrets.matches("challenge", "wrong", hash)).toBe(false);
	});
	it("centralizes and validates configuration", () => {
		expect(verificationPolicyFromEnvironment({})).toEqual(defaultVerificationPolicy);
		expect(verificationPolicyFromEnvironment({ HAPI_EMAIL_MAX_SENDS_PER_CHALLENGE: "3" }).maxSendsPerChallenge).toBe(3);
		expect(() => verificationPolicyFromEnvironment({ HAPI_EMAIL_OTP_LENGTH: "0" })).toThrow();
	});
});

async function apiFixture() {
	const fixtureData = fixture();
	const logs: string[] = [];
	const app = Fastify({ logger: { stream: { write: (message: string) => { logs.push(message); } } } });
	const tenants = new InMemoryTenantRepository();
	const applications = new InMemoryApplicationRepository();
	const clients = new InMemoryOIDCClientRepository();
	const applicationIds: string[] = [];
	for (const clientId of ["client", "other-client"]) {
		const tenantId = randomUUID();
		const applicationId = randomUUID();
		applicationIds.push(applicationId);
		await tenants.upsert({ id: tenantId, name: clientId, slug: clientId, status: "active" });
		await applications.upsert({ id: applicationId, tenantId, name: clientId, slug: clientId, status: "active" });
		await clients.upsert({ id: randomUUID(), clientId, clientSecret: "client-secret", applicationId,
			redirectUris: [], scopes: [], grantTypes: [], responseTypes: [], requirePkce: true, tokenEndpointAuthMethod: "client_secret_basic" });
	}
	const headers = (clientId = "client", secret = "client-secret") => ({ authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}` });
	await registerEmailVerificationRoutes(app, fixtureData.service, { clients, applications, tenants });
	return { ...fixtureData, app, logs, headers, clients, tenants, applications, applicationIds };
}

describe("H2 HTTP security and isolation", () => {
	it("malformed JSON never echoes or logs OTP or client credentials", async () => {
		const { app, headers, logs } = await apiFixture();
		try {
			const response = await app.inject({ method: "POST", url: "/v1/identity/email/verify", headers: { ...headers(), "content-type": "application/json" }, payload: '{"code":"123456"' });
			expect(response.statusCode).toBe(400);
			expect(response.json()).toEqual({ error: "INVALID_REQUEST" });
			expect(logs.join("")).not.toContain("123456");
			expect(logs.join("")).not.toContain("client-secret");
		} finally { await app.close(); }
	});
	it("start/resend/verify contract uses trusted H1 client authority and no public consumption", async () => {
		const { app, provider, headers, advance, applicationIds } = await apiFixture();
		try {
			const started = await app.inject({ method: "POST", url: "/v1/identity/email/start", headers: headers(), payload: { email: "a@example.com", purpose: "REGISTRATION", applicationId: applicationIds[0] } });
			expect(started.statusCode).toBe(200);
			expect(started.headers["cache-control"]).toBe("no-store");
			const { challengeId } = started.json();
			const crossTenant = await app.inject({ method: "POST", url: "/v1/identity/email/verify", headers: headers("other-client"), payload: { challengeId, code: provider.messages[0].code } });
			expect(crossTenant.statusCode).toBe(400);
			const wrongPurpose = await app.inject({ method: "POST", url: "/v1/identity/email/verify", headers: headers(), payload: { challengeId, code: provider.messages[0].code, purpose: "RECOVERY" } });
			expect(wrongPurpose.statusCode).toBe(400);
			const cooldown = await app.inject({ method: "POST", url: "/v1/identity/email/resend", headers: headers(), payload: { challengeId } });
			expect(cooldown.statusCode).toBe(429);
			advance(60);
			const resent = await app.inject({ method: "POST", url: "/v1/identity/email/resend", headers: headers(), payload: { challengeId } });
			expect(resent.statusCode).toBe(200);
			const verified = await app.inject({ method: "POST", url: "/v1/identity/email/verify", headers: headers(), payload: { challengeId, code: provider.messages[1].code } });
			expect(verified.json()).toEqual({ verified: true, verificationId: challengeId });
			expect((await app.inject({ method: "POST", url: "/v1/identity/email/consume", headers: headers(), payload: { verificationId: challengeId } })).statusCode).toBe(404);
		} finally { await app.close(); }
	});
	it("rejects arbitrary tenant/application selection, bad credentials, public clients and suspended authorities", async () => {
		const { app, headers, clients, tenants, applicationIds } = await apiFixture();
		try {
			const inject = (payload: object, auth = headers()) => app.inject({ method: "POST", url: "/v1/identity/email/start", headers: auth, payload: { email: "a@example.com", purpose: "REGISTRATION", ...payload } });
			expect((await inject({ tenantId: randomUUID() })).statusCode).toBe(400);
			expect((await inject({ applicationId: applicationIds[1] })).statusCode).toBe(403);
			expect((await inject({}, {})).statusCode).toBe(401);
			expect((await inject({}, headers("client", "wrong"))).statusCode).toBe(401);
			expect((await inject({ email: "broken" })).statusCode).toBe(400);
			expect((await inject({ purpose: "LOGIN" })).statusCode).toBe(400);
			const client = (await clients.findByClientId("client"))!;
			await clients.upsert({ ...client, tokenEndpointAuthMethod: "none" });
			expect((await inject({})).statusCode).toBe(401);
			await clients.upsert({ ...client, tokenEndpointAuthMethod: "client_secret_basic" });
			const tenant = (await tenants.list())[0];
			await tenants.upsert({ ...tenant, status: "suspended" });
			expect((await inject({})).statusCode).toBe(401);
		} finally { await app.close(); }
	});
	it("H2 never creates, resolves, merges or mutates IdentitySubject and does not enumerate accounts", async () => {
		const seed = await inMemoryIdentitySubjectRepository.create({ id: randomUUID(), oidcSubject: randomUUID(), primaryProvider: "PrivateID", primaryProviderSubject: randomUUID(), email: "existing@example.com", emailVerified: false, status: "ACTIVE" });
		const before = await inMemoryIdentitySubjectRepository.list();
		const spies = [InMemoryIdentitySubjectRepository, PostgresIdentitySubjectRepository].flatMap(repository =>
			["create", "resolveOrCreate", "update", "findByEmail", "touchLastAuthentication", "relinkPrimaryProviderSubject"].map(method =>
				vi.spyOn(repository.prototype, method as "create").mockImplementation(() => { throw new Error("H2 crossed IdentitySubject boundary"); })));
		const { app, provider, headers, logs, repository, advance } = await apiFixture();
		try {
			const responses = [];
			for (const email of ["existing@example.com", "unknown@example.com"]) {
				const response = await app.inject({ method: "POST", url: "/v1/identity/email/start", headers: headers(), payload: { email, purpose: "REGISTRATION" } });
				responses.push(response);
				const { challengeId } = response.json();
				advance(60);
				await app.inject({ method: "POST", url: "/v1/identity/email/resend", headers: headers(), payload: { challengeId } });
				await app.inject({ method: "POST", url: "/v1/identity/email/verify", headers: headers(), payload: { challengeId, code: provider.messages.at(-1)!.code } });
			}
			expect(responses.map(response => response.statusCode)).toEqual([200, 200]);
			expect(Object.keys(responses[0].json()).sort()).toEqual(Object.keys(responses[1].json()).sort());
			expect(await inMemoryIdentitySubjectRepository.list()).toEqual(before);
			for (const spy of spies) expect(spy).not.toHaveBeenCalled();
			for (const message of provider.messages) expect(logs.join("")).not.toContain(message.code);
			for (const challenge of repository.inspect().challenges) {
				expect(logs.join("")).not.toContain(challenge.destinationNormalized);
				expect(logs.join("")).not.toContain("codeHash");
			}
			expect(logs.join("")).not.toContain("client-secret");
		} finally {
			spies.forEach(spy => spy.mockRestore());
			await app.close();
			await inMemoryIdentitySubjectRepository.delete(seed.oidcSubject);
		}
	});
	it("H2 Core's transitive dependency graph excludes application-specific identity and vendors", () => {
		const core = resolve("src/email");
		const visited = new Set<string>();
		const visit = (file: string) => {
			if (visited.has(file)) return;
			visited.add(file);
			expect(file).not.toMatch(/base44|bookwrmuser|BiometricIdentity|PendingIdentityActivation|PrivateID|IdentitySubject|IdentityRegistry|OIDCService/i);
			const source = readFileSync(file, "utf8");
			expect(source).not.toMatch(/Base44|Bookwrm|x-bookwrm-user-id|BiometricIdentity|PendingIdentityActivation|PrivateID|IdentitySubject/i);
			expect(source).not.toMatch(/import\s*\(/);
			for (const imported of parse(source, { sourceType: "module", plugins: ["typescript"] }).program.body) {
				if (imported.type !== "ImportDeclaration" && imported.type !== "ExportNamedDeclaration" && imported.type !== "ExportAllDeclaration") continue;
				const moduleName = imported.source?.value;
				if (!moduleName) continue;
				expect(moduleName).not.toMatch(/resend|svix/i);
				if (moduleName?.startsWith(".")) visit(resolve(dirname(file), moduleName.replace(/\.js$/, ".ts")));
			}
		};
		for (const file of readdirSync(core).filter(file => file.endsWith(".ts"))) visit(resolve(core, file));
		expect(visited.size).toBeGreaterThan(5);
	});
});

describe("Resend boundary", () => {
	it("sends a generic HAPI ID template with configured sender and per-send idempotency", async () => {
		const transport = vi.fn(async () => new Response(JSON.stringify({ id: "provider-message" }), { status: 200 }));
		const provider = new ResendEmailDeliveryProvider("test-api-key", "HAPI ID <verify@id.hapiinc.com>", transport);
		const message = { destination: "a@example.com", code: "123456", purpose: "REGISTRATION" as const, expiresIn: 600, tenant: "tenant", application: null, sendId: randomUUID() };
		expect(await provider.sendVerificationEmail(message, new AbortController().signal)).toEqual({ messageId: "provider-message" });
		const [url, request] = transport.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://api.resend.com/emails");
		expect(request.headers).toMatchObject({ "Idempotency-Key": message.sendId });
		const content = JSON.parse(request.body as string);
		expect(content.from).toBe("HAPI ID <verify@id.hapiinc.com>");
		expect(content.subject).toBe("Your HAPI ID verification code");
		expect(content.text).toContain("This code expires in 10 minutes.");
		expect(content.text).not.toMatch(/Bookwrm|Base44/);
	});
	it("sanitizes provider rejection and malformed responses", async () => {
		const message = { destination: "a@example.com", code: "123456", purpose: "REGISTRATION" as const, expiresIn: 600, tenant: "tenant", application: null, sendId: randomUUID() };
		for (const response of [new Response("secret", { status: 403 }), new Response("{}", { status: 200 })]) {
			const provider = new ResendEmailDeliveryProvider("test-key", "sender@example.com", async () => response);
			await expect(provider.sendVerificationEmail(message, new AbortController().signal)).rejects.toThrow(/Email provider/);
		}
	});
	it("validates signed raw webhooks, rejects tampering/stale/missing signatures, deduplicates without verifying", async () => {
		const { service, provider, repository } = fixture();
		const inactiveApp = Fastify();
		await registerResendWebhook(inactiveApp, service);
		try {
			const inactive = await inactiveApp.inject({ method: "POST", url: "/v1/identity/email/webhooks/resend", payload: { type: "email.delivered", data: { email_id: "untrusted" } } });
			expect(inactive.statusCode).toBe(503);
			expect(inactive.json()).toEqual({ error: "WEBHOOK_NOT_CONFIGURED" });
			expect(repository.inspect().delivery).toHaveLength(0);
		} finally { await inactiveApp.close(); }
		const { challengeId } = await service.start(context, "a@example.com", "REGISTRATION");
		const app = Fastify();
		const secret = `whsec_${Buffer.from("webhook-test-secret").toString("base64")}`;
		await registerResendWebhook(app, service, secret);
		const webhook = new Webhook(secret);
		const body = JSON.stringify({ type: "email.delivered", data: { email_id: provider.messages[0].sendId } });
		const id = "msg_delivery";
		const timestamp = new Date();
		const headers = { "content-type": "application/json", "svix-id": id, "svix-timestamp": String(Math.floor(timestamp.getTime() / 1000)), "svix-signature": webhook.sign(id, timestamp, body) };
		try {
			for (let replay = 0; replay < 2; replay++) expect((await app.inject({ method: "POST", url: "/v1/identity/email/webhooks/resend", headers, payload: body })).statusCode).toBe(204);
			expect(repository.inspect().delivery.filter(event => event.state === "DELIVERED")).toHaveLength(1);
			expect((await repository.findById(challengeId))?.status).toBe("PENDING");
			expect((await app.inject({ method: "POST", url: "/v1/identity/email/webhooks/resend", headers, payload: `${body} ` })).statusCode).toBe(400);
			expect((await app.inject({ method: "POST", url: "/v1/identity/email/webhooks/resend", payload: JSON.parse(body) })).statusCode).toBe(400);
			const stale = new Date(Date.now() - 600_000);
			expect((await app.inject({ method: "POST", url: "/v1/identity/email/webhooks/resend", headers: { ...headers, "svix-timestamp": String(Math.floor(stale.getTime() / 1000)), "svix-signature": webhook.sign(id, stale, body) }, payload: body })).statusCode).toBe(400);
		} finally { await app.close(); }
	});
});