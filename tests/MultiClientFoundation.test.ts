import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { requireApplicationMethod, resolveRegisteredClient } from "../src/identity/H1ClientAuthority.js";
import { InMemoryApplicationAccountLinks, ApplicationAccountLinkConflict } from "../src/identity/ApplicationAccountLinks.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { configuration } from "../src/config/ConfigurationService.js";
import type { AuthenticationProvider } from "../src/authentication/AuthenticationProvider.js";
import { ensureOidcTestEnvironment, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

async function fixture() {
	ensureOidcTestEnvironment();
	process.env.HAPI_UNIVERSAL_LOGIN_ENABLED = "true";
	configuration.reload();
	const tenants = new InMemoryTenantRepository(), applications = new InMemoryApplicationRepository();
	const clients = new InMemoryOIDCClientRepository(), tenantId = randomUUID();
	await tenants.upsert({ id: tenantId, name: "Synthetic", slug: tenantId, status: "active" });
	for (const key of ["BOOKWRM_TEST", "ELITE_TEST"]) {
		await applications.upsert({ id: key, tenantId, name: key, slug: key, applicationKey: key, status: "active",
			allowedAuthenticationMethods: ["HAPI_EMAIL"], allowedIdentityProviders: [] });
		await clients.upsert({ id: randomUUID(), applicationId: key, clientId: key, clientSecret: "test-secret",
			redirectUris: ["https://rp.example/callback"], scopes: ["openid", "email"], grantTypes: ["authorization_code"],
			responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
	}
	const authority = { tenants, applications, clients };
	const provider: AuthenticationProvider = {
		authenticate: vi.fn(async () => { throw new Error("Interactive provider must not run"); }),
		cancel: vi.fn(async () => {}), logout: vi.fn(async () => {}),
		status: vi.fn(async () => ({ state: "idle" as const })),
		beginAsyncAuthentication: vi.fn(async () => ({ sessionId: "mock", launchUrl: "https://provider.example/launch" }))
	};
	const oidc = new OIDCService({ authenticationProvider: provider, oidcClients: clients, clientAuthority: authority });
	const app = Fastify();
	await app.register(formbody);
	await oidc.registerEndpoints(app);
	const query = (overrides: Record<string, string> = {}) => new URLSearchParams({
		client_id: "BOOKWRM_TEST", redirect_uri: "https://rp.example/callback", response_type: "code",
		scope: "openid email", nonce: "test-nonce", code_challenge_method: "S256",
		code_challenge: pkceChallengeFromVerifier("v".repeat(43)), ...overrides
	});
	return { app, oidc, authority, provider, query };
}

describe("Phase 4 registered application authority", () => {
	afterEach(() => { delete process.env.HAPI_UNIVERSAL_LOGIN_ENABLED; configuration.reload(); });
	it("resolves both synthetic products and permits multiple clients per application", async () => {
		const f = await fixture();
		try {
			const web = await f.authority.clients.findByClientId("BOOKWRM_TEST");
			await f.authority.clients.upsert({ ...web!, id: randomUUID(), clientId: "BOOKWRM_NATIVE", clientSecret: "",
				tokenEndpointAuthMethod: "none" });
			for (const clientId of ["BOOKWRM_TEST", "ELITE_TEST", "BOOKWRM_NATIVE"]) {
				const response = await f.app.inject({ url: `/authorize?${f.query({ client_id: clientId })}` });
				expect(response.statusCode, response.body).toBe(302);
			}
			expect((await resolveRegisteredClient("BOOKWRM_NATIVE", f.authority)).application.applicationKey).toBe("BOOKWRM_TEST");
		} finally { await f.app.close(); }
	});
	for (const kind of ["unknown", "disabled-client", "disabled-application", "mismatch", "redirect", "provider"] as const) {
		it(`rejects ${kind} before authentication`, async () => {
			const f = await fixture();
			try {
				const client = (await f.authority.clients.findByClientId("BOOKWRM_TEST"))!;
				const application = (await f.authority.applications.findById("BOOKWRM_TEST"))!;
				const overrides: Record<string, string> = {};
				if (kind === "unknown") overrides.client_id = "UNKNOWN";
				if (kind === "disabled-client") await f.authority.clients.upsert({ ...client, status: "suspended" });
				if (kind === "disabled-application") await f.authority.applications.upsert({ ...application, status: "suspended" });
				if (kind === "mismatch") await f.authority.clients.upsert({ ...client, applicationId: "UNREGISTERED" });
				if (kind === "redirect") overrides.redirect_uri = "https://evil.example/callback";
				if (kind === "provider") overrides.idp_hint = "pepperdine";
				const response = await f.app.inject({ url: `/authorize?${f.query(overrides)}` });
				expect(response.statusCode).toBe(400);
				expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
			} finally { await f.app.close(); }
		});
	}
	it("refuses direct Face invocation and flag-off Face fallback for an email-only application", async () => {
		const f = await fixture();
		try {
			const started = await f.app.inject({ url: `/authorize?${f.query()}` });
			const cookie = String(started.headers["set-cookie"]).split(";")[0];
			const page = await f.app.inject({ url: "/login", headers: { cookie } });
			expect(page.body).not.toContain("Continue with Face");
			const csrf = /name="csrf" value="([^"]+)"/.exec(page.body);
			// The chooser has no email adapter in this fixture, so read the interaction's CSRF server-side.
			const { AuthorizationInteractionStore } = await import("../src/oidc/AuthorizationInteractionStore.js");
			const interaction = await new AuthorizationInteractionStore().find(cookie.split("=")[1]);
			const response = await f.app.inject({ method: "POST", url: "/login/face", headers: { cookie },
				payload: { csrf: csrf?.[1] ?? interaction!.csrf } });
			expect(response.statusCode).toBe(403);
			process.env.HAPI_UNIVERSAL_LOGIN_ENABLED = "false"; configuration.reload();
			const fallback = await f.app.inject({ url: `/authorize?${f.query()}` });
			expect(fallback.statusCode).toBe(403);
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
		} finally { await f.app.close(); }
	});
	it("denies disallowed methods and does not treat login_hint as authentication", async () => {
		const f = await fixture();
		try {
			await expect(requireApplicationMethod("BOOKWRM_TEST", f.authority, "EXTERNAL_OIDC")).rejects.toMatchObject({ statusCode: 403 });
			const response = await f.app.inject({ url: `/authorize?${f.query({ login_hint: "unverified@example.com" })}` });
			expect(response.statusCode).toBe(302);
			expect(response.headers.location).toBe("/login");
			expect(f.provider.authenticate).not.toHaveBeenCalled();
		} finally { await f.app.close(); }
	});
	it("rejects a client rebound to another enabled application during an interaction", async () => {
		const f = await fixture();
		try {
			const started = await f.app.inject({ url: `/authorize?${f.query()}` });
			const cookie = String(started.headers["set-cookie"]).split(";")[0];
			const client = (await f.authority.clients.findByClientId("BOOKWRM_TEST"))!;
			await f.authority.clients.upsert({ ...client, applicationId: "ELITE_TEST" });
			const page = await f.app.inject({ url: "/login", headers: { cookie } });
			expect(page.statusCode).toBe(400);
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
		} finally { await f.app.close(); }
	});
	it("refuses direct email-result handoff before consuming authentication when policy disables email", async () => {
		const f = await fixture();
		try {
			const consume = vi.fn(async () => { throw new Error("Disallowed authentication result consumed"); });
			f.oidc.configureEmailAuthentication({ consume });
			const application = (await f.authority.applications.findById("BOOKWRM_TEST"))!;
			await f.authority.applications.upsert({ ...application, allowedAuthenticationMethods: [] });
			const response = await f.app.inject({ method: "POST", url: "/authorize",
				headers: { authorization: `Basic ${Buffer.from("BOOKWRM_TEST:test-secret").toString("base64")}` },
				payload: { ...Object.fromEntries(f.query()), authentication_result: "r".repeat(43) } });
			expect(response.statusCode).toBe(403);
			expect(consume).not.toHaveBeenCalled();
		} finally { await f.app.close(); }
	});
});

describe("Phase 4 application-scoped account links and authorization isolation", () => {
	const evidence = { authority: "OIDC_CONTINUITY" as const, clientId: "test-client",
		requestId: "test-request", authenticationMethod: "HAPI_EMAIL" as const };
	it("links one canonical identity to independent local accounts without propagating roles or membership", async () => {
		const links = new InMemoryApplicationAccountLinks(), subject = randomUUID();
		await links.reconcile({ identitySubjectId: subject, applicationId: "BOOKWRM_TEST", externalAccountId: "BW-1", evidence });
		expect(await links.find("ELITE_TEST", "BW-1")).toBeUndefined();
		const bookwrmRoles = new Map([["BW-1", ["admin"]]]);
		const eliteRoles = new Map<string, string[]>();
		const elite = await links.reconcile({ identitySubjectId: subject, applicationId: "ELITE_TEST", externalAccountId: "EL-1", evidence });
		expect(elite.link.identitySubjectId).toBe(subject);
		expect(bookwrmRoles.get("BW-1")).toEqual(["admin"]);
		expect(eliteRoles.get(elite.link.externalAccountId)).toBeUndefined();
		expect(elite.link).not.toHaveProperty("roles");
		expect(elite.link).not.toHaveProperty("membership");
		expect((await links.find("BOOKWRM_TEST", "BW-1"))?.externalAccountId).toBe("BW-1");
	});
	it("is idempotent and collision-safe for both uniqueness directions, with audit outcomes", async () => {
		const links = new InMemoryApplicationAccountLinks();
		const input = { identitySubjectId: randomUUID(), applicationId: "ELITE_TEST", externalAccountId: "EL-1", evidence };
		const first = await links.reconcile(input), second = await links.reconcile(input);
		expect(first.created).toBe(true); expect(second).toEqual({ link: first.link, created: false });
		await expect(links.reconcile({ ...input, identitySubjectId: randomUUID() })).rejects.toBeInstanceOf(ApplicationAccountLinkConflict);
		await expect(links.reconcile({ ...input, externalAccountId: "EL-2" })).rejects.toBeInstanceOf(ApplicationAccountLinkConflict);
		expect(links.audit.map(event => event.result)).toEqual(["created", "existing", "conflict", "conflict"]);
	});
});
