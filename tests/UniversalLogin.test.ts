import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import { readFileSync } from "node:fs";
import pg from "pg";
import { chromium, type Browser, type Page } from "playwright";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from "fastify";
import formbody from "@fastify/formbody";
import { JSDOM } from "jsdom";
import { Redis } from "ioredis";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { configuration } from "../src/config/ConfigurationService.js";
import { resolveConfiguredIssuer } from "../src/config/IssuerPolicy.js";
import { OIDCService, type OIDCClient } from "../src/oidc/OIDCService.js";
import { AuthorizationInteractionStore, AUTHORIZATION_INTERACTION_TTL_MS } from "../src/oidc/AuthorizationInteractionStore.js";
import type { AuthenticationProvider, PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { InMemoryVerificationChallengeRepository } from "../src/email/InMemoryVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import { EmailAuthenticationError, type EmailAuthenticationRepository, type EmailPrincipal } from "../src/authentication/email/EmailAuthenticationTypes.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { interactiveEmailAuthentication } from "../src/adapters/email/EmailVerificationComposition.js";
import { authorizeH1Client } from "../src/identity/H1ClientAuthority.js";
import { identityRegistry, IdentityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import { getCurrentPrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";
import { HapiFaceEnrollmentService } from "../src/authenticators/HapiFaceEnrollmentService.js";
import { getRedisClient, oidcRedisKey } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import * as redisInfrastructure from "../src/oidc/infrastructure/RedisInfrastructure.js";
import { OIDCRateLimiter } from "../src/oidc/infrastructure/OIDCRateLimiter.js";
import { ensureOidcTestEnvironment, pkceChallengeFromVerifier } from "./oidcTestHarness.js";
import { diagnosticCorrelationId } from "../src/oidc/UniversalLoginDiagnostics.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { InMemoryRegistrationRepository } from "../src/registration/InMemoryRegistrationRepository.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";
import { registerStagingTestConsole, STAGING_CONSOLE_CALLBACK, STAGING_ISSUER, validateStagingConsoleUserInfo } from "../src/oidc/StagingTestConsole.js";
import { protectStagingConsoleInternalLogs } from "../src/oidc/StagingConsoleInternal.js";
import { registerPathOnlyNotFoundHandler, serializeRequestForLog } from "../src/security/RequestLogging.js";
import { PostgresPasskeyCredentialRepository } from "../src/identity/PostgresPasskeyCredentialRepository.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

const REDIRECT = "https://rp.example/callback";
const CLIENT_ID = "ul-client";
const CLIENT_SECRET = "ul-client-secret";
const COOKIE = "__Host-hapi_login";
const KNOWN_EMAIL = "member@example.com";

function setFlag(value: boolean | undefined): void {
	if (value === undefined) delete process.env.HAPI_UNIVERSAL_LOGIN_ENABLED;
	else process.env.HAPI_UNIVERSAL_LOGIN_ENABLED = String(value);
	configuration.reload();
}

function cookieFrom(response: LightMyRequestResponse): string | undefined {
	const header = response.headers["set-cookie"];
	const cookies = Array.isArray(header) ? header : header ? [header] : [];
	return cookies.find(value => value.startsWith(`${COOKIE}=`))?.split(";")[0].slice(COOKIE.length + 1) || undefined;
}

function setCookies(response: LightMyRequestResponse): string[] {
	const header = response.headers["set-cookie"];
	return Array.isArray(header) ? header : header ? [header] : [];
}

function csrfFrom(html: string): string {
	const match = /name="csrf" value="([^"]+)"/.exec(html);
	if (!match) throw new Error("csrf field missing");
	return match[1];
}

function publicPage(html: string): string {
	return html.replace(/nonce="[^"]+"/g, 'nonce=""')
		.replace(/name="csrf" value="[^"]+"/g, 'name="csrf" value=""');
}

function form(payload: Record<string, string>): { headers: Record<string, string>; payload: string } {
	return { headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams(payload).toString() };
}

function authorizeQuery(verifier: string, overrides: Record<string, string> = {}): string {
	return new URLSearchParams({
		response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT,
		scope: "openid profile email", state: "ul-state-Ω+/=&", nonce: "ul-nonce-123",
		code_challenge_method: "S256", code_challenge: pkceChallengeFromVerifier(verifier), ...overrides
	}).toString();
}

function decodeJwt(token: string): Record<string, unknown> {
	return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")) as Record<string, unknown>;
}

function diagnosticEvents(logs: string[]): Array<Record<string, unknown>> {
	return logs
		.map(line => { try { return JSON.parse(line); } catch { return null; } })
		.filter((entry): entry is Record<string, unknown> => Boolean(entry) && typeof entry!.event === "string"
			&& ((entry!.event as string).startsWith("UNIVERSAL_LOGIN_") || (entry!.event as string).startsWith("EMAIL_FLOW_")
				|| (entry!.event as string).startsWith("EMAIL_AUTHENTICATION_") || (entry!.event as string).startsWith("EMAIL_REGISTRATION_")));
}

async function emailFixture(options: { emailInteractive?: boolean; clientId?: string; redirectUri?: string; console?: boolean; knownEmail?: string;
	interactionStore?: AuthorizationInteractionStore; passkeyCredentials?: PostgresPasskeyCredentialRepository } = {}) {
	ensureOidcTestEnvironment();
	const clientId = options.clientId ?? CLIENT_ID;
	const redirectUri = options.redirectUri ?? REDIRECT;
	const clientSecret = options.console ? CLIENT_SECRET.padEnd(40, "x") : CLIENT_SECRET;
	const knownEmail = options.knownEmail ?? KNOWN_EMAIL;
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const tenants = new InMemoryTenantRepository();
	const applications = new InMemoryApplicationRepository();
	const clients = new InMemoryOIDCClientRepository();
	await tenants.upsert({ id: tenantId, name: "Bookwrm", slug: `bookwrm-${tenantId}`, status: "active" });
	await applications.upsert({ id: applicationId, tenantId, name: "Bookwrm Web", slug: "web", status: "active",
		allowedAuthenticationMethods: ["HAPI_EMAIL", "PRIVATEID_FACE"] });
	await clients.upsert({ id: randomUUID(), applicationId, clientId, clientSecret,
		redirectUris: [redirectUri], scopes: ["openid", "profile", "email"], grantTypes: ["authorization_code"],
		responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
	const h1 = { clients, applications, tenants };
	const oidcClient: OIDCClient = { client_id: clientId, client_secret: clientSecret, redirect_uris: [redirectUri],
		scope: "openid profile email", grant_types: ["authorization_code"], response_types: ["code"],
		token_endpoint_auth_method: "client_secret_basic", require_pkce: true };

	let now = Date.now();
	const challenges = new InMemoryVerificationChallengeRepository();
	const delivery = new InMemoryEmailDeliveryProvider();
	const h2 = new EmailVerificationService(challenges, delivery,
		new VerificationSecrets("h6-local-test-secret".repeat(3)), defaultVerificationPolicy, () => now);

	// The canonical HAPI_EMAIL subject that already exists (H3). H4/H6 must resolve it and never create one.
	const subjects = new InMemoryIdentitySubjectRepository();
	const subjectRegistry = new IdentityRegistry(subjects);
	const subject = await subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId,
		primaryProvider: "HAPI_EMAIL", primaryProviderSubject: knownEmail, email: knownEmail,
		emailVerified: true, status: "ACTIVE" });
	const results = new Map<string, EmailPrincipal & { context: string }>();
	const created: string[] = [];
	const repository: EmailAuthenticationRepository = {
		audit: vi.fn(async () => {}),
		establish: vi.fn(async (authority, challengeId) => {
			const challenge = await challenges.findById(challengeId);
			if (challenge?.destinationNormalized.toLowerCase() !== knownEmail) throw new EmailAuthenticationError();
			const authenticatedAt = new Date(now).toISOString();
			const authenticationResult = randomBytes(32).toString("base64url");
			results.set(authenticationResult, { id: subject.id, sub: subject.oidcSubject, email: knownEmail, emailVerified: true,
				authenticationMethod: "HAPI_EMAIL", authenticatedAt, assurance: "email_otp",
				context: `${authority.context.tenantId}:${authority.context.applicationId}:${authority.clientId}` });
			return { authenticated: true as const, subject: subject.oidcSubject, authenticationResult, expiresIn: 60,
				authenticationMethod: "HAPI_EMAIL" as const, authenticatedAt, assurance: "email_otp" as const };
		}),
		consumeResult: vi.fn(async (authority, result) => {
			const principal = results.get(result);
			results.delete(result);
			if (!principal || principal.context !== `${authority.context.tenantId}:${authority.context.applicationId}:${authority.clientId}`) {
				throw new EmailAuthenticationError();
			}
			const { context: _context, ...rest } = principal;
			return rest;
		})
	};
	const service = new EmailAuthenticationService(h2, challenges, repository);
	const registrationRepository = new InMemoryRegistrationRepository(challenges, subjects);
	const registration = new RegistrationService(registrationRepository);
	const provider: AuthenticationProvider = {
		authenticate: vi.fn(async () => { throw new Error("must not authenticate synchronously"); }),
		cancel: vi.fn(async () => {}), status: vi.fn(async () => ({ state: "idle" as const })), logout: vi.fn(async () => {}),
		setPendingAuthorizationContext: vi.fn((_context: PendingAuthorizationContext) => {}),
		beginAsyncAuthentication: vi.fn(async (correlationId: string) => ({
			sessionId: `face-session-${correlationId}`, launchUrl: "https://privateid.example.com/launch?session=opaque"
		}))
	} as unknown as AuthenticationProvider;
	const oidc = new OIDCService({ authenticationProvider: provider, clients: [oidcClient], oidcClients: clients, clientAuthority: h1,
		interactionStore: options.interactionStore, passkeyCredentials: options.passkeyCredentials });
	oidc.configureEmailAuthentication({
		async consume(request, token, expectedClient) {
			const client = await authorizeH1Client(request, h1);
			if (client.clientId !== expectedClient) throw new EmailAuthenticationError();
			return service.consumeResult(client, token);
		},
		...(options.emailInteractive === false ? {} : { interactive: interactiveEmailAuthentication(service, h1, {
			verification: h2, challenges, registration, subjects: subjectRegistry
		}) })
	});
	const logs: string[] = [];
	const app = Fastify({ trustProxy: options.console ? "127.0.0.1" : false,
		logger: { level: "info", stream: new Writable({ write(chunk, _enc, done) { logs.push(String(chunk)); done(); } }),
			...(options.console ? { serializers: { req: serializeRequestForLog } } : {}) } });
	if (options.console) {
		registerPathOnlyNotFoundHandler(app);
		protectStagingConsoleInternalLogs(app);
	}
	await app.register(formbody);
	await oidc.registerEndpoints(app);
	if (options.console) await registerStagingTestConsole(app, {
		issuer: STAGING_ISSUER, env: { STAGING_TEST_CONSOLE_ENABLED: "true",
			STAGING_TEST_CONSOLE_USERNAME: "operator", STAGING_TEST_CONSOLE_PASSWORD: "operator-password-".padEnd(40, "x"),
			HAPI_EMAIL_PROVIDER: "resend", HAPI_EMAIL_AUTHENTICATION_ENABLED: "true", HAPI_UNIVERSAL_LOGIN_ENABLED: "true",
			STAGING_WEB_CLIENT_SECRET: clientSecret }
	});
	await app.ready();
	const lookup = vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
	const basic = { authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64") };
	return { app, oidc, h1, oidcClient, provider, delivery, service, challenges, repository, registrationRepository,
		registration, subjects, subject, created, logs, lookup, basic,
		advance: (ms: number) => { now += ms; }, tenantId, applicationId };
}

type Fixture = Awaited<ReturnType<typeof emailFixture>>;

async function beginInteraction(f: Pick<Fixture, "app">, verifier: string, overrides: Record<string, string> = {}) {
	const authorize = await f.app.inject({ method: "GET", url: `/authorize?${authorizeQuery(verifier, overrides)}` });
	expect(authorize.statusCode, authorize.body).toBe(302);
	expect(authorize.headers.location).toBe("/login");
	const handle = cookieFrom(authorize)!;
	expect(handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
	const chooser = await f.app.inject({ method: "GET", url: "/login", headers: { cookie: `${COOKIE}=${handle}` } });
	expect(chooser.statusCode).toBe(200);
	return { authorize, handle, chooser, csrf: csrfFrom(chooser.body), cookie: { cookie: `${COOKIE}=${handle}` } };
}

async function startEmail(f: Fixture, interaction: Awaited<ReturnType<typeof beginInteraction>>, email: string) {
	const started = await f.app.inject({ method: "POST", url: "/login/email",
		...form({ csrf: interaction.csrf, email }), headers: { ...form({}).headers, ...interaction.cookie } });
	return started;
}

async function submitCode(f: Fixture, interaction: Awaited<ReturnType<typeof beginInteraction>>, code: string) {
	return f.app.inject({ method: "POST", url: "/login/email/code",
		payload: new URLSearchParams({ csrf: interaction.csrf, code }).toString(),
		headers: { ...form({}).headers, ...interaction.cookie } });
}

describe("H6 AuthorizationInteractionStore", () => {
	beforeAll(() => ensureOidcTestEnvironment());
	const base = (): Parameters<AuthorizationInteractionStore["create"]>[0] => ({
		clientId: "c", authorization: { clientId: "c", redirectUri: REDIRECT, scope: "openid", nonce: "n", codeChallenge: "x", state: "s" },
		request: { client_id: "c", redirect_uri: REDIRECT, response_type: "code", scope: "openid" }
	});

	it("issues opaque 256-bit handles stored only under a SHA-256 key", async () => {
		const store = new AuthorizationInteractionStore();
		const { handle, interaction } = await store.create(base());
		expect(handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(Buffer.from(handle, "base64url")).toHaveLength(32);
		expect(interaction.expiresAt - interaction.createdAt).toBe(AUTHORIZATION_INTERACTION_TTL_MS);
		const keys = await getRedisClient().keys("*interaction:*");
		expect(keys.some(key => key.includes(handle))).toBe(false);
		expect(keys.some(key => key.endsWith(createHash("sha256").update(handle).digest("base64url")))).toBe(true);
		expect(await store.find("not-a-handle")).toBeNull();
		expect(await store.find(handle)).toMatchObject({ clientId: "c" });
	});

	it("is single-use under concurrent consumption and never revives", async () => {
		const store = new AuthorizationInteractionStore();
		const { handle } = await store.create(base());
		const results = await Promise.all(Array.from({ length: 8 }, () => store.consume(handle)));
		expect(results.filter(Boolean)).toHaveLength(1);
		expect(await store.find(handle)).toBeNull();
		expect(await store.consume(handle)).toBeNull();
	});

	it("enforces absolute expiry and save never extends it", async () => {
		let now = 1_000_000;
		const store = new AuthorizationInteractionStore(getRedisClient(), 1_000, () => now);
		const { handle, interaction } = await store.create(base());
		now += 500;
		expect(await store.save(handle, { ...interaction, email: { challengeId: "c1" } })).toBe(true);
		expect((await store.find(handle))?.expiresAt).toBe(interaction.expiresAt);
		now += 600;
		expect(await store.find(handle)).toBeNull();
		expect(await store.consume(handle)).toBeNull();
		expect(await store.save(handle, interaction)).toBe(false);
	});

	it("compares CSRF tokens safely", async () => {
		const { interaction } = await new AuthorizationInteractionStore().create(base());
		expect(AuthorizationInteractionStore.csrfMatches(interaction, interaction.csrf)).toBe(true);
		expect(AuthorizationInteractionStore.csrfMatches(interaction, "x")).toBe(false);
		expect(AuthorizationInteractionStore.csrfMatches(interaction, undefined)).toBe(false);
	});

	it("atomically arbitrates enrollment and skip, protects the interaction and finishes once", async () => {
		const store = new AuthorizationInteractionStore();
		const { handle, interaction } = await store.create(base());
		const principal = { id: randomUUID(), sub: randomUUID(), authenticationMethod: "HAPI_EMAIL" as const };
		const offer = await store.offerPasskeyEnrollment(handle, interaction, principal);
		expect(offer).not.toBeNull();
		const proof = offer!.browserProof;
		expect(await store.save(handle, { ...interaction, email: { challengeId: "stale", mode: "AUTHENTICATION" } })).toBe(false);
		expect(await store.consume(handle)).toBeNull();
		const [enroll, skip] = await Promise.all([
			store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, principal.id, "OFFERED", "ENROLLING"),
			store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, principal.id, "OFFERED", "SKIPPED")
		]);
		expect([enroll, skip].filter(Boolean)).toHaveLength(1);
		if (enroll) {
			expect(await store.finishPasskeyEnrollment(handle, proof, interaction.csrf, principal.id)).toBeNull();
			expect(await store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, principal.id,
				"ENROLLING", "ENROLLED")).toBe(true);
		}
		const finished = await Promise.all(Array.from({ length: 8 }, () =>
			store.finishPasskeyEnrollment(handle, proof, interaction.csrf, principal.id)));
		expect(finished.filter(Boolean)).toHaveLength(1);
		expect(finished.find(Boolean)?.principal).toEqual(principal);
		expect(await store.save(handle, interaction)).toBe(false);
		expect(await store.consume(handle)).toBeNull();
	});

	it("rejects stale offers, wrong browser, CSRF, subject and interaction, and expiry", async () => {
		let now = Date.now();
		const store = new AuthorizationInteractionStore(getRedisClient(), 600_000, () => now);
		const { handle, interaction } = await store.create(base());
		const other = await store.create(base());
		const principal = { id: randomUUID(), sub: randomUUID(), authenticationMethod: "APPLE" as const };
		expect(await store.save(handle, { ...interaction, email: { challengeId: "new", mode: "AUTHENTICATION" } })).toBe(true);
		expect(await store.offerPasskeyEnrollment(handle, interaction, principal)).toBeNull();
		const current = await store.find(handle);
		const offer = await store.offerPasskeyEnrollment(handle, current!, principal);
		expect(offer).not.toBeNull();
		const proof = offer!.browserProof;
		expect(await store.transitionPasskeyEnrollment(handle, randomBytes(32).toString("base64url"), current!.csrf,
			principal.id, "OFFERED", "SKIPPED")).toBe(false);
		expect(await store.transitionPasskeyEnrollment(handle, proof, "wrong", principal.id, "OFFERED", "SKIPPED")).toBe(false);
		expect(await store.transitionPasskeyEnrollment(handle, proof, current!.csrf, randomUUID(), "OFFERED", "SKIPPED")).toBe(false);
		expect(await store.transitionPasskeyEnrollment(other.handle, proof, other.interaction.csrf,
			principal.id, "OFFERED", "SKIPPED")).toBe(false);
		now += 300_001;
		expect(await store.transitionPasskeyEnrollment(handle, proof, current!.csrf, principal.id, "OFFERED", "SKIPPED")).toBe(false);
		expect(await store.transitionPasskeyEnrollment(handle, proof, current!.csrf, principal.id, "OFFERED", "ENROLLING")).toBe(false);
		expect(await store.consume(handle)).toBeNull();
		expect(await store.expirePasskeyEnrollment(handle, proof, current!.csrf, principal.id)).toBe(true);
		expect((await store.finishPasskeyEnrollment(handle, proof, current!.csrf, principal.id))?.principal).toEqual(principal);
	});

	it("fails closed when Redis cannot create an enrollment authority", async () => {
		const redis = getRedisClient();
		const store = new AuthorizationInteractionStore(redis);
		const { handle, interaction } = await store.create(base());
		const principal = { id: randomUUID(), sub: randomUUID(), authenticationMethod: "HAPI_EMAIL" as const };
		const failure = vi.spyOn(redis, "eval").mockRejectedValueOnce(new Error("synthetic Redis failure"));
		await expect(store.offerPasskeyEnrollment(handle, interaction, principal)).rejects.toThrow("synthetic Redis failure");
		failure.mockRestore();
		expect(await store.find(handle)).toEqual(interaction);
	});
});

describe("Staging browser console", () => {
	it.each(["REGISTRATION", "AUTHENTICATION", "TOKEN_ERROR", "USERINFO_ERROR"])("handles %s with one OTP and the real OIDC flow without logging secrets", async scenario => {
		vi.stubEnv("OIDC_ISSUER", STAGING_ISSUER);
		vi.stubEnv("OIDC_ALLOWED_ISSUERS", STAGING_ISSUER);
		setFlag(true);
		const f = await emailFixture({ clientId: "staging-web", redirectUri: STAGING_CONSOLE_CALLBACK, console: true,
			...(scenario !== "REGISTRATION" ? { knownEmail: "jeff@hapiinc.com" } : {}) });
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("unexpected network request"); });
		const auth = "Basic " + Buffer.from(`operator:${"operator-password-".padEnd(40, "x")}`).toString("base64");
		const headers = { host: "id-staging.hapiinc.com", "x-forwarded-proto": "https", authorization: auth };
		try {
			const missing = await f.app.inject({ method: "GET", url: "/missing?token=SENSITIVE_OTHER_QUERY" });
			expect(missing.statusCode).toBe(404);
			expect(missing.json().message).toBe("Route GET:/missing not found");
			const index = await f.app.inject({ method: "GET", url: "/staging-console/", headers });
			expect(index.statusCode).toBe(200);
			const consoleCookie = String(index.headers["set-cookie"]).split(";")[0];
			const start = await f.app.inject({ method: "POST", url: "/staging-console/start",
				headers: { ...headers, cookie: consoleCookie, origin: STAGING_ISSUER, "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({ csrf: csrfFrom(index.body) }).toString() });
			expect(start.statusCode).toBe(303);
			const authorizeUrl = new URL(String(start.headers.location));
			expect(authorizeUrl.origin).toBe(STAGING_ISSUER);
			const authorize = await f.app.inject({ method: "GET", url: authorizeUrl.pathname + authorizeUrl.search });
			expect(authorize.statusCode).toBe(302);
			const loginCookie = `${COOKIE}=${cookieFrom(authorize)}`;
			const emailPage = await f.app.inject({ method: "GET", url: "/login/email", headers: { cookie: loginCookie } });
			const csrf = csrfFrom(emailPage.body);
			const send = await f.app.inject({ method: "POST", url: "/login/email", headers: {
				cookie: loginCookie, "content-type": "application/x-www-form-urlencoded"
			}, payload: new URLSearchParams({ csrf, email: "jeff@hapiinc.com" }).toString() });
			expect(send.statusCode).toBe(303);
			expect(f.delivery.messages).toHaveLength(1);
			expect(f.delivery.messages[0].purpose).toBe(scenario === "REGISTRATION" ? "REGISTRATION" : "AUTHENTICATION");
			const otp = f.delivery.messages[0].code;
			const verify = await f.app.inject({ method: "POST", url: "/login/email/code", headers: {
				cookie: loginCookie, "content-type": "application/x-www-form-urlencoded"
			}, payload: new URLSearchParams({ csrf, code: otp }).toString() });
			expect(verify.statusCode, verify.body).toBe(303);
			const callback = new URL(String(verify.headers.location));
			expect(`${callback.origin}${callback.pathname}`).toBe(STAGING_CONSOLE_CALLBACK);
			if (scenario === "TOKEN_ERROR") f.lookup.mockRejectedValueOnce(new Error("SENSITIVE_TOKEN_LOG_SENTINEL"));
			if (scenario === "USERINFO_ERROR") f.lookup.mockImplementationOnce(sub => f.subjects.findByOidcSubject(sub))
				.mockImplementationOnce(sub => f.subjects.findByOidcSubject(sub))
				.mockRejectedValueOnce(new Error("SENSITIVE_USERINFO_LOG_SENTINEL"));
			const challenged = await f.app.inject({ method: "GET", url: callback.pathname + callback.search,
				headers: { ...headers, authorization: "", cookie: consoleCookie } });
			expect(challenged.statusCode).toBe(401);
			expect(challenged.headers["www-authenticate"]).toContain("Basic");
			const callbackResponse = await f.app.inject({ method: "GET", url: callback.pathname + callback.search,
				headers: { ...headers, cookie: consoleCookie } });
			expect(callbackResponse.statusCode, callbackResponse.body).toBe(303);
			expect(callbackResponse.headers.location).toBe("/staging-console/results");
			const results = await f.app.inject({ method: "GET", url: "/staging-console/results",
				headers: { ...headers, cookie: consoleCookie } });
			const failed = scenario === "TOKEN_ERROR" || scenario === "USERINFO_ERROR";
			expect(results.body).toContain(failed ? "Test failed" : "Test passed");
			if (!failed) expect(results.body).toContain("PASS: UserInfo");
			expect(results.body).not.toContain(callback.searchParams.get("code")!);
			expect(results.body).not.toContain(otp);
			const codeReplay = await f.app.inject({ method: "POST", url: "/token",
				headers: { ...f.basic, "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({ grant_type: "authorization_code", code: callback.searchParams.get("code")!,
					redirect_uri: STAGING_CONSOLE_CALLBACK, code_verifier: "a".repeat(43) }).toString() });
			expect(codeReplay.statusCode).toBe(400);
			expect(codeReplay.json().error).toBe("invalid_grant");
			const replay = await f.app.inject({ method: "GET", url: callback.pathname + callback.search,
				headers: { ...headers, cookie: consoleCookie } });
			expect(replay.statusCode).toBe(400);
			expect(f.logs.join("")).not.toContain(callback.searchParams.get("code")!);
			expect(f.logs.join("")).not.toContain(callback.searchParams.get("state")!);
			expect(f.logs.join("")).not.toContain(authorizeUrl.searchParams.get("nonce")!);
			expect(f.logs.join("")).not.toContain(otp);
			expect(f.logs.join("")).not.toContain(CLIENT_SECRET.padEnd(40, "x"));
			expect(f.logs.join("")).not.toContain(auth);
			expect(f.logs.join("")).not.toContain("SENSITIVE_TOKEN_LOG_SENTINEL");
			expect(f.logs.join("")).not.toContain("SENSITIVE_USERINFO_LOG_SENTINEL");
			expect(f.logs.join("")).not.toContain("SENSITIVE_OTHER_QUERY");
			if (scenario === "TOKEN_ERROR") expect(f.logs.join("")).toContain("STAGING_CONSOLE_TOKEN_FAILED");
			if (scenario === "USERINFO_ERROR") expect(f.logs.join("")).toContain("STAGING_CONSOLE_USERINFO_FAILED");
			if (failed) {
				const audit = f.logs.map(line => JSON.parse(line) as { Flow?: string; Error?: string; Success?: boolean })
					.find(entry => entry.Flow === (scenario === "TOKEN_ERROR" ? "token" : "userinfo") &&
						entry.Error === "staging_console_verification_failed");
				expect(audit?.Success).toBe(false);
			}
			expect(fetchSpy).not.toHaveBeenCalled();
		} finally {
			await f.app.close();
			await getRedisClient().del(oidcRedisKey("ratelimit:ip:127.0.0.1"), oidcRedisKey("ratelimit:client:staging-web"));
			vi.restoreAllMocks();
			vi.unstubAllEnvs();
			setFlag(undefined);
		}
	});
});

describe("H6 Universal Login", () => {
	afterEach(() => { setFlag(undefined); vi.restoreAllMocks(); });

	it.each([
		{ email: KNOWN_EMAIL, purpose: "AUTHENTICATION", h5: "false" },
		{ email: "zero-choice-new@example.com", purpose: "REGISTRATION", h5: "false" },
		{ email: KNOWN_EMAIL, purpose: "AUTHENTICATION", h5: "true" },
		{ email: "zero-choice-new@example.com", purpose: "REGISTRATION", h5: "true" }
	])("Bookwrm zero-choice login preserves one $purpose OTP with H5=$h5", async ({ email, purpose, h5 }) => {
		setFlag(true);
		vi.stubEnv("HAPI_FACE_ENROLLMENT_ENABLED", h5);
		configuration.reload();
		const clientId = "bookwrm-base44-production";
		const f = await emailFixture({ clientId });
		try {
			expect(configuration.getFeatureFlag("HAPI_FACE_ENROLLMENT_ENABLED", false)).toBe(h5 === "true");
			const verifier = "zero-choice-verifier-" + randomUUID();
			const remoteAddress = "192.0.2.11";
			const authorize = await f.app.inject({ method: "GET", remoteAddress,
				url: `/authorize?${authorizeQuery(verifier, { client_id: clientId })}` });
			expect(authorize.statusCode, authorize.body).toBe(302);
			expect(authorize.headers.location).toBe("/login");
			const handle = cookieFrom(authorize)!;
			const cookie = { cookie: `${COOKIE}=${handle}` };
			const store = new AuthorizationInteractionStore();
			const initialInteraction = await store.find(handle);
			expect(initialInteraction).not.toBeNull();
			const chooser = await f.app.inject({ method: "GET", url: "/login", headers: cookie, remoteAddress });
			expect(chooser.statusCode).toBe(200);
			const dom = new JSDOM(chooser.body);
			let action: string;
			try {
				const { document } = dom.window;
				expect(document.querySelectorAll("button")).toHaveLength(1);
				expect(document.querySelector("button")?.textContent).toBe("Continue");
				expect(document.forms).toHaveLength(1);
				expect(document.forms[0].method).toBe("get");
				action = document.forms[0].getAttribute("action")!;
				expect(action).toBe("/login/email");
				expect(document.querySelector("svg")?.getAttribute("aria-label")).toBe("Bookwrm");
			} finally { dom.window.close(); }
			expect(chooser.body).not.toContain("Continue with Face");
			expect(chooser.body).not.toContain("/login/face");
			expect(f.challenges.inspect().challenges).toHaveLength(0);
			expect(f.delivery.messages).toHaveLength(0);

			const emailForm = await f.app.inject({ method: "GET", url: action, headers: cookie, remoteAddress });
			expect(emailForm.statusCode).toBe(200);
			expect(emailForm.body).toContain("Welcome to Bookwrm");
			expect(emailForm.body).toContain("STEP 1 OF 2");
			expect(emailForm.body).toContain("Confirm your email");
			expect(emailForm.body).toContain("We'll send you a one-time verification code.");
			expect(emailForm.body).toContain("Send My Code");
			expect(f.challenges.inspect().challenges).toHaveLength(0);
			expect(f.delivery.messages).toHaveLength(0);
			expect(await store.find(handle)).toEqual(initialInteraction);
			const csrf = csrfFrom(emailForm.body);
			const started = await f.app.inject({ method: "POST", url: "/login/email", remoteAddress,
				...form({ csrf, email }), headers: { ...form({}).headers, ...cookie } });
			expect(started.statusCode, started.body).toBe(303);
			expect(started.headers.location).toBe("/login/email/code");
			expect(f.delivery.messages).toHaveLength(1);
			expect(f.delivery.messages[0]).toMatchObject({ purpose, destination: email });
			expect(f.challenges.inspect().challenges).toHaveLength(1);
			const codeForm = await f.app.inject({ method: "GET", url: "/login/email/code", headers: cookie, remoteAddress });
			expect(codeForm.statusCode).toBe(200);
			expect(codeForm.body).toContain("STEP 2 OF 2");
			expect(codeForm.body).toContain("Check your inbox");
			expect(codeForm.body).toContain("Verify &amp; Continue");
			expect(codeForm.body).toContain("Resend code");
			const done = await f.app.inject({ method: "POST", url: "/login/email/code", remoteAddress,
				...form({ csrf, code: f.delivery.messages[0].code }), headers: { ...form({}).headers, ...cookie } });
			expect(done.statusCode, done.body).toBe(303);
			const callback = new URL(done.headers.location as string);
			expect(callback.searchParams.get("state")).toBe("ul-state-Ω+/=&");
			const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic, remoteAddress,
				payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!,
					redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(token.statusCode, token.body).toBe(200);
			const subjects = await f.subjects.findByEmail(email);
			expect(subjects).toHaveLength(1);
			expect(decodeJwt(token.json().id_token)).toMatchObject({
				sub: subjects[0].oidcSubject, email, email_verified: true, amr: ["email"],
				nonce: "ul-nonce-123", aud: clientId
			});
			if (purpose === "AUTHENTICATION") expect(subjects[0].oidcSubject).toBe(f.subject.oidcSubject);
			expect(f.challenges.inspect().challenges).toHaveLength(1);
			expect(f.challenges.inspect().challenges[0]).toMatchObject({
				purpose, status: purpose === "REGISTRATION" ? "CONSUMED" : "VERIFIED"
			});
			expect(f.delivery.messages).toHaveLength(1);
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
		} finally {
			f.lookup.mockRestore();
			await f.app.close();
			vi.unstubAllEnvs();
			configuration.reload();
		}
	});

	it("flag off (default): GET /authorize keeps the existing PrivateID Face launch and /login routes are absent", async () => {
		setFlag(undefined);
		expect(configuration.getFeatureFlag("HAPI_UNIVERSAL_LOGIN_ENABLED", false)).toBe(false);
		const f = await emailFixture();
		try {
			const response = await f.app.inject({ method: "GET", url: `/authorize?${authorizeQuery("v".repeat(43))}` });
			expect(response.statusCode).toBe(302);
			expect(response.headers.location).toBe("https://privateid.example.com/launch?session=opaque");
			expect(cookieFrom(response)).toBeUndefined();
			expect(f.provider.beginAsyncAuthentication).toHaveBeenCalledOnce();
			for (const [method, url] of [["GET", "/login"], ["GET", "/login/email"], ["POST", "/login/email"],
				["GET", "/login/email/code"], ["POST", "/login/email/code"], ["POST", "/login/email/resend"], ["POST", "/login/face"]] as const) {
				expect((await f.app.inject({ method, url })).statusCode).toBe(404);
			}
		} finally { await f.app.close(); }
	});

	it("flag on: GET /authorize renders HAPI-branded Universal Login without launching Face", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const { authorize, chooser } = await beginInteraction(f, "v".repeat(43));
			const cookie = setCookies(authorize).find(value => value.startsWith(COOKIE))!;
			expect(cookie).toMatch(/; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax$/);
			expect(authorize.headers["cache-control"]).toBe("no-store");
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
			expect(chooser.headers["content-type"]).toContain("text/html");
			expect(chooser.headers["cache-control"]).toBe("no-store");
			expect(chooser.headers["x-frame-options"]).toBe("DENY");
			expect(chooser.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
			expect(chooser.body).toContain("Sign in to Bookwrm");
			expect(chooser.body).toContain("Secured by HAPI ID");
			expect(chooser.body).toContain("Continue with Email");
			expect(chooser.body).toContain("Continue with Face");
			expect(chooser.body).not.toMatch(/base44|enrol|<script/i);
			expect(chooser.body).not.toContain(CLIENT_SECRET);
			expect(chooser.body).not.toContain("ul-nonce-123");
		} finally { await f.app.close(); }
	});

	it("Email: authorization → H4 OTP → existing canonical subject → callback → token → userinfo", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const verifier = "ul-email-verifier-" + randomUUID();
			const interaction = await beginInteraction(f, verifier);
			const emailForm = await f.app.inject({ method: "GET", url: "/login/email", headers: interaction.cookie });
			expect(emailForm.statusCode).toBe(200);
			expect(emailForm.body).toContain('type="email"');

			const started = await startEmail(f, interaction, KNOWN_EMAIL);
			expect(started.statusCode, started.body).toBe(303);
			expect(started.headers.location).toBe("/login/email/code");
			expect(f.delivery.messages).toHaveLength(1);
			expect(f.delivery.messages[0]).toMatchObject({ purpose: "AUTHENTICATION" });
			const codeForm = await f.app.inject({ method: "GET", url: "/login/email/code", headers: interaction.cookie });
			expect(codeForm.statusCode).toBe(200);
			expect(codeForm.body).toContain('id="otp-form"');
			expect(codeForm.body).toContain('otpForm.addEventListener("submit", submitOnce)');
			expect(codeForm.headers["content-security-policy"]).toMatch(/script-src 'nonce-[A-Za-z0-9+/]+=*'/);

			const done = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(done.statusCode, done.body).toBe(303);
			const callback = new URL(done.headers.location as string);
			expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT);
			expect(callback.searchParams.get("state")).toBe("ul-state-Ω+/=&");
			expect([...callback.searchParams.keys()].sort()).toEqual(["code", "state"]);
			expect(setCookies(done).find(value => value.startsWith(COOKIE))).toContain("Max-Age=0");
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
			expect(f.repository.establish).toHaveBeenCalledOnce();

			const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!, redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(token.statusCode, token.body).toBe(200);
			const claims = decodeJwt(token.json().id_token);
			expect(claims).toMatchObject({ sub: f.subject.oidcSubject, email: KNOWN_EMAIL, email_verified: true,
				amr: ["email"], nonce: "ul-nonce-123", aud: CLIENT_ID });
			expect(typeof claims.auth_time).toBe("number");
			const userinfo = await f.app.inject({ method: "GET", url: "/userinfo",
				headers: { authorization: `Bearer ${token.json().access_token}` } });
			expect(userinfo.statusCode).toBe(200);
			expect(userinfo.json()).toMatchObject({ sub: f.subject.oidcSubject, email: KNOWN_EMAIL, email_verified: true });

			// Replay: the interaction is single-use and the authorization code is single-use.
			const replay = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(replay.statusCode).toBe(400);
			expect(replay.body).toContain("expired");
			const reuse = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!, redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(reuse.statusCode).toBe(400);

			const logged = f.logs.join("\n");
			expect(logged).not.toContain(f.delivery.messages[0].code);
			expect(logged).not.toContain(KNOWN_EMAIL);
			expect(logged).not.toMatch(/[Mm]ember@[Ee]xample\.com/);
			expect(logged).not.toContain(interaction.handle);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("PKCE is preserved: a wrong code_verifier cannot redeem the Universal Login code", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const verifier = "ul-pkce-verifier-" + randomUUID();
			const interaction = await beginInteraction(f, verifier);
			await startEmail(f, interaction, KNOWN_EMAIL);
			const done = await submitCode(f, interaction, f.delivery.messages[0].code);
			const code = new URL(done.headers.location as string).searchParams.get("code")!;
			const wrong = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "wrong-" + verifier } });
			expect(wrong.statusCode).toBe(400);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("new email uses H2 registration and H3 to finish the original OIDC interaction", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const verifier = "new-user-verifier-" + randomUUID();
			const interaction = await beginInteraction(f, verifier);
			const started = await startEmail(f, interaction, "newperson@example.com");
			expect(started.statusCode).toBe(303);
			expect(started.headers.location).toBe("/login/email/code");
			expect(f.delivery.messages[0]).toMatchObject({ purpose: "REGISTRATION", destination: "newperson@example.com" });
			const registrationChallenge = f.challenges.inspect().challenges.find(challenge =>
				challenge.destinationNormalized === "newperson@example.com");
			expect(registrationChallenge).toMatchObject({ purpose: "REGISTRATION", status: "PENDING" });
			const codeForm = await f.app.inject({ method: "GET", url: "/login/email/code", headers: interaction.cookie });
			expect(codeForm.statusCode).toBe(200);
			expect(codeForm.body).toContain('id="otp-form"');
			expect(codeForm.body).toContain('otpForm.addEventListener("submit", submitOnce)');
			expect(codeForm.headers["content-security-policy"]).toMatch(/script-src 'nonce-[A-Za-z0-9+/]+=*'/);
			expect(publicPage(codeForm.body)).not.toMatch(/register|existing account|new account|H2|H3|H4|IdentitySubject/i);

			const completed = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(completed.statusCode, completed.body).toBe(303);
			const callback = new URL(completed.headers.location as string);
			expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT);
			expect(callback.searchParams.get("state")).toBe("ul-state-Ω+/=&");
			expect([...callback.searchParams.keys()].sort()).toEqual(["code", "state"]);
			const registered = await f.subjects.findByEmail("newperson@example.com");
			expect(registered).toHaveLength(1);
			expect(registered[0]).toMatchObject({ status: "ACTIVE", primaryProvider: "HAPI_EMAIL",
				email: "newperson@example.com", emailVerified: true, applicationId: f.applicationId });
			expect(registered[0].oidcSubject).toBeTruthy();
			expect(await f.challenges.findById(registrationChallenge!.id)).toMatchObject({
				purpose: "REGISTRATION", status: "CONSUMED"
			});
			expect(f.registrationRepository.auditLog().some(entry => entry.type === "IDENTITY_REGISTERED")).toBe(true);

			const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!,
					redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(token.statusCode, token.body).toBe(200);
			expect(decodeJwt(token.json().id_token)).toMatchObject({
				sub: registered[0].oidcSubject, email: "newperson@example.com", email_verified: true,
				amr: ["email"], nonce: "ul-nonce-123", aud: CLIENT_ID
			});
			expect(typeof decodeJwt(token.json().id_token).auth_time).toBe("number");
			const replay = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(replay.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			expect(events.some(event => event.event === "EMAIL_FLOW_STARTED")).toBe(true);
			expect(events.some(event => event.event === "EMAIL_REGISTRATION_COMPLETED")).toBe(true);
			const diagnosticText = JSON.stringify(events);
			for (const sensitive of [interaction.handle, interaction.csrf, "newperson@example.com",
				f.delivery.messages[0].code, registrationChallenge!.id, "ul-state-Ω+/=&", "ul-nonce-123", verifier,
				callback.searchParams.get("code")!, token.json().id_token, token.json().access_token, CLIENT_SECRET]) {
				expect(diagnosticText).not.toContain(sensitive);
			}
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it.each([
		{ journey: "new", email: "invited-new@example.com", purpose: "REGISTRATION" },
		{ journey: "returning", email: KNOWN_EMAIL, purpose: "AUTHENTICATION" }
	])("H6.9 $journey invited user authenticates without invitation state and preserves RP return correlation",
		async ({ email, purpose }) => {
			setFlag(true);
			const f = await emailFixture();
			try {
				const invitationToken = randomBytes(32).toString("base64url");
				const returnDestination = `/invite/${invitationToken}`;
				const state = randomBytes(32).toString("base64url");
				// RP-only stand-in, not a Base44 implementation: HAPI receives only the random state.
				const rpReturns = new Map([[state, returnDestination]]);
				const verifier = randomBytes(32).toString("base64url");
				const nonce = randomBytes(32).toString("base64url");
				const existingAuthenticator = await inMemoryUserAuthenticatorRepository.create({
					id: randomUUID(), userId: f.subject.id, provider: "privateid",
					providerSubject: `h69-face-${randomUUID()}`, authenticatorType: "face", status: "active"
				});
				const register = vi.spyOn(f.registration, "complete");
				const h5 = vi.spyOn(HapiFaceEnrollmentService.prototype, "start");
				const interaction = await beginInteraction(f, verifier, { state, nonce });
				const saved = await new AuthorizationInteractionStore().find(interaction.handle);
				expect(saved?.authorization).toMatchObject({ state, nonce, redirectUri: REDIRECT,
					codeChallenge: pkceChallengeFromVerifier(verifier) });
				expect(JSON.stringify(saved)).not.toContain(invitationToken);
				const started = await startEmail(f, interaction, email);
				expect(started.statusCode, started.body).toBe(303);
				expect(f.delivery.messages[0]).toMatchObject({ destination: email, purpose });
				const done = await submitCode(f, interaction, f.delivery.messages[0].code);
				expect(done.statusCode, done.body).toBe(303);
				const callback = new URL(done.headers.location as string);
				expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT);
				expect([...callback.searchParams.keys()].sort()).toEqual(["code", "state"]);
				expect(callback.searchParams.get("state")).toBe(state);
				expect(rpReturns.get(callback.searchParams.get("state")!)).toBe(returnDestination);
				expect(done.headers.location).not.toContain(invitationToken);
				expect(await new AuthorizationInteractionStore().find(interaction.handle)).toBeNull();

				const subjects = await f.subjects.findByEmail(email);
				expect(subjects).toHaveLength(1);
				const canonical = subjects[0];
				expect(canonical).toMatchObject({ applicationId: f.applicationId, status: "ACTIVE",
					primaryProvider: "HAPI_EMAIL", primaryProviderSubject: email, email, emailVerified: true });
				if (purpose === "REGISTRATION") {
					expect(register).toHaveBeenCalledOnce();
					expect(f.repository.establish).not.toHaveBeenCalled();
				} else {
					expect(register).not.toHaveBeenCalled();
					expect(f.repository.establish).toHaveBeenCalledOnce();
					expect(canonical.id).toBe(f.subject.id);
					expect(canonical.oidcSubject).toBe(f.subject.oidcSubject);
				}
				const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
					payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!,
						redirect_uri: REDIRECT, code_verifier: verifier } });
				expect(token.statusCode, token.body).toBe(200);
				expect(decodeJwt(token.json().id_token)).toMatchObject({ sub: canonical.oidcSubject,
					email: canonical.email, email_verified: true, nonce, aud: CLIENT_ID, amr: ["email"] });
				const userinfo = await f.app.inject({ method: "GET", url: "/userinfo",
					headers: { authorization: `Bearer ${token.json().access_token}` } });
				expect(userinfo.statusCode, userinfo.body).toBe(200);
				expect(userinfo.json()).toMatchObject({ sub: canonical.oidcSubject,
					email: canonical.email, email_verified: true });
				expect(await f.subjects.findById(f.subject.id)).toEqual(f.subject);
				expect(await f.subjects.findById(canonical.id)).toEqual(canonical);
				expect(await inMemoryUserAuthenticatorRepository.findByProviderSubject(
					"privateid", existingAuthenticator.providerSubject)).toEqual(existingAuthenticator);
				if (purpose === "REGISTRATION") {
					expect(await inMemoryUserAuthenticatorRepository.findByUser(canonical.id)).toEqual([]);
				}
				expect(h5).not.toHaveBeenCalled();
				expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
				expect(JSON.stringify(canonical)).not.toContain(invitationToken);
				expect(f.logs.join("\n")).not.toContain(invitationToken);
				expect(f.logs.join("\n")).not.toContain(returnDestination);
				const replay = await submitCode(f, interaction, f.delivery.messages[0].code);
				expect(replay.statusCode).toBe(400);
			} finally { f.lookup.mockRestore(); await f.app.close(); }
		});

	it("fails generically for a PrivateID email without attempting H3 or changing that identity", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const legacyEmail = "legacy@example.com";
			const legacy = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId: f.applicationId,
				primaryProvider: "PrivateID", primaryProviderSubject: `legacy-${randomUUID()}`, email: legacyEmail,
				emailVerified: true, status: "ACTIVE" });
			const interaction = await beginInteraction(f, "legacy-user-verifier-" + randomUUID());
			const started = await startEmail(f, interaction, legacyEmail);
			expect(started.statusCode).toBe(303);
			expect(f.delivery.messages.at(-1)).toMatchObject({ purpose: "AUTHENTICATION", destination: legacyEmail });
			const challenge = f.challenges.inspect().challenges.find(item => item.destinationNormalized === legacyEmail);
			const before = await f.subjects.list();
			const response = await submitCode(f, interaction, f.delivery.messages.at(-1)!.code);
			expect(response.statusCode).toBe(401);
			expect(response.body).toContain("sign you in with that code");
			expect(await f.subjects.list()).toHaveLength(before.length);
			expect(await f.subjects.findByOidcSubject(legacy.oidcSubject)).toMatchObject({
				id: legacy.id, oidcSubject: legacy.oidcSubject, primaryProvider: "PrivateID", email: legacyEmail
			});
			expect(f.registrationRepository.auditLog()).toHaveLength(0);
			expect(challenge).toBeDefined();
			expect(await f.challenges.findById(challenge!.id)).toMatchObject({ purpose: "AUTHENTICATION", status: "CONSUMED" });
			expect(diagnosticEvents(f.logs).some(event => event.event === "EMAIL_FLOW_FAILED")).toBe(true);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("fails closed when multiple subjects claim the same normalized email", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const email = "collision@example.com";
			await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId: f.applicationId,
				primaryProvider: "HAPI_EMAIL", primaryProviderSubject: email, email: "different@example.com",
				emailVerified: true, status: "ACTIVE" });
			await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId: f.applicationId,
				primaryProvider: "PrivateID", primaryProviderSubject: `collision-${randomUUID()}`, email,
				emailVerified: true, status: "ACTIVE" });
			const interaction = await beginInteraction(f, "collision-verifier-" + randomUUID());
			const started = await startEmail(f, interaction, email);
			expect(started.statusCode).toBe(303);
			expect(f.delivery.messages.at(-1)).toMatchObject({ purpose: "AUTHENTICATION", destination: email });
			const count = (await f.subjects.list()).length;
			const response = await submitCode(f, interaction, f.delivery.messages.at(-1)!.code);
			expect(response.statusCode).toBe(401);
			expect(response.body).toContain("sign you in with that code");
			expect(await f.subjects.list()).toHaveLength(count);
			expect(f.registrationRepository.auditLog()).toHaveLength(0);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("keeps browser-visible email pages and safe failures uniform across the internal branches", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const legacyEmail = "legacy-enumeration@example.com";
			await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId: f.applicationId,
				primaryProvider: "PrivateID", primaryProviderSubject: `legacy-${randomUUID()}`, email: legacyEmail,
				emailVerified: true, status: "ACTIVE" });
			const returning = await beginInteraction(f, "returning-enum-" + randomUUID());
			const newUser = await beginInteraction(f, "new-enum-" + randomUUID());
			const legacy = await beginInteraction(f, "legacy-enum-" + randomUUID());
			const starts = await Promise.all([
				startEmail(f, returning, KNOWN_EMAIL),
				startEmail(f, newUser, "not-yet-registered@example.com"),
				startEmail(f, legacy, legacyEmail)
			]);
			expect(starts.map(response => [response.statusCode, response.headers.location]))
				.toEqual([[303, "/login/email/code"], [303, "/login/email/code"], [303, "/login/email/code"]]);

			const codePages = await Promise.all([returning, newUser, legacy].map(interaction =>
				f.app.inject({ method: "GET", url: "/login/email/code", headers: interaction.cookie })));
			expect(publicPage(codePages[0].body)).toBe(publicPage(codePages[1].body));
			expect(publicPage(codePages[1].body)).toBe(publicPage(codePages[2].body));
			expect(publicPage(codePages[0].body)).not.toMatch(/register|existing account|new account|H2|H3|H4|IdentitySubject/i);

			const messages = f.delivery.messages;
			const responses = await Promise.all([
				submitCode(f, returning, messages.find(message => message.destination === KNOWN_EMAIL)!.code),
				submitCode(f, newUser, messages.find(message => message.destination === "not-yet-registered@example.com")!.code),
				submitCode(f, legacy, messages.find(message => message.destination === legacyEmail)!.code)
			]);
			expect(responses[0].statusCode).toBe(303);
			expect(responses[1].statusCode).toBe(303);
			expect(responses[2].statusCode).toBe(401);
			const wrongCode = await beginInteraction(f, "wrong-enum-" + randomUUID());
			await startEmail(f, wrongCode, KNOWN_EMAIL);
			const wrong = await submitCode(f, wrongCode, "000000000");
			expect(wrong.statusCode).toBe(401);
			expect(publicPage(responses[2].body)).toBe(publicPage(wrong.body));
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("allows simultaneous first registrations to resolve to at most one canonical subject", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const email = "concurrent@example.com";
			const a = await beginInteraction(f, "concurrent-a-" + randomUUID());
			const b = await beginInteraction(f, "concurrent-b-" + randomUUID());
			expect((await startEmail(f, a, email)).statusCode).toBe(303);
			expect((await startEmail(f, b, email)).statusCode).toBe(303);
			const messages = f.delivery.messages.filter(message => message.destination === email);
			expect(messages).toHaveLength(2);
			expect(messages.every(message => message.purpose === "REGISTRATION")).toBe(true);
			const results = await Promise.all([submitCode(f, a, messages[0].code), submitCode(f, b, messages[1].code)]);
			expect(results.every(response => response.statusCode === 303)).toBe(true);
			expect(await f.subjects.findByEmail(email)).toHaveLength(1);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("rejects wrong client, wrong redirect_uri, CSRF mismatch, and missing interactions without creating sessions", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const wrongClient = await f.app.inject({ method: "GET", url: `/authorize?${authorizeQuery("w".repeat(43), { client_id: "attacker" })}` });
			expect(wrongClient.statusCode).toBe(400);
			expect(wrongClient.json()).toMatchObject({ error: "invalid_client" });
			expect(cookieFrom(wrongClient)).toBeUndefined();
			const wrongRedirect = await f.app.inject({ method: "GET",
				url: `/authorize?${authorizeQuery("w".repeat(43), { redirect_uri: "https://evil.example/callback" })}` });
			expect(wrongRedirect.statusCode).toBe(400);
			expect(wrongRedirect.headers.location).toBeUndefined();
			expect(cookieFrom(wrongRedirect)).toBeUndefined();
			const plain = await f.app.inject({ method: "GET", url: `/authorize?${authorizeQuery("w".repeat(43), { code_challenge_method: "plain" })}` });
			expect(plain.statusCode).toBe(400);

			const interaction = await beginInteraction(f, "w".repeat(43));
			const csrf = await f.app.inject({ method: "POST", url: "/login/email",
				payload: new URLSearchParams({ csrf: "forged", email: KNOWN_EMAIL }).toString(),
				headers: { ...form({}).headers, ...interaction.cookie } });
			expect(csrf.statusCode).toBe(400);
			expect(f.delivery.messages).toHaveLength(0);
			const faceCsrf = await f.app.inject({ method: "POST", url: "/login/face",
				payload: new URLSearchParams({ csrf: "forged" }).toString(), headers: { ...form({}).headers, ...interaction.cookie } });
			expect(faceCsrf.statusCode).toBe(400);
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
			const noCookie = await f.app.inject({ method: "GET", url: "/login" });
			expect(noCookie.statusCode).toBe(400);
			const forgedCookie = await f.app.inject({ method: "GET", url: "/login", headers: { cookie: `${COOKIE}=${"A".repeat(43)}` } });
			expect(forgedCookie.statusCode).toBe(400);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("rejects completion when the bound client is deregistered, its redirect is removed, or its application changes", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const redirectRemoved = await beginInteraction(f, "r".repeat(43));
			const original = f.oidcClient.redirect_uris;
			f.oidcClient.redirect_uris = ["https://rp.example/other"];
			const face = await f.app.inject({ method: "POST", url: "/login/face",
				payload: new URLSearchParams({ csrf: redirectRemoved.csrf }).toString(), headers: { ...form({}).headers, ...redirectRemoved.cookie } });
			expect(face.statusCode).toBe(400);
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
			f.oidcClient.redirect_uris = original;

			const moved = await beginInteraction(f, "m".repeat(43));
			const record = (await f.h1.clients.findByClientId(CLIENT_ID))!;
			await f.h1.clients.upsert({ ...record, applicationId: randomUUID() });
			const start = await startEmail(f, moved, KNOWN_EMAIL);
			expect(start.statusCode).toBe(400);
			expect(start.body).toContain("expired");
			expect(f.delivery.messages).toHaveLength(0);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("rejects an expired interaction", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "e".repeat(43));
			const realNow = Date.now();
			vi.spyOn(Date, "now").mockReturnValue(realNow + AUTHORIZATION_INTERACTION_TTL_MS + 1);
			const expired = await f.app.inject({ method: "GET", url: "/login", headers: interaction.cookie });
			expect(expired.statusCode).toBe(400);
			expect(expired.body).toContain("expired");
			expect(setCookies(expired).find(value => value.startsWith(COOKIE))).toContain("Max-Age=0");
			const face = await f.app.inject({ method: "POST", url: "/login/face",
				payload: new URLSearchParams({ csrf: interaction.csrf }).toString(), headers: { ...form({}).headers, ...interaction.cookie } });
			expect(face.statusCode).toBe(400);
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("resend rotates the OTP inside the same interaction-bound challenge", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "s".repeat(43));
			await startEmail(f, interaction, KNOWN_EMAIL);
			const early = await f.app.inject({ method: "POST", url: "/login/email/resend",
				payload: new URLSearchParams({ csrf: interaction.csrf }).toString(), headers: { ...form({}).headers, ...interaction.cookie } });
			expect(early.statusCode).toBe(429);
			f.advance(60_000);
			const resent = await f.app.inject({ method: "POST", url: "/login/email/resend",
				payload: new URLSearchParams({ csrf: interaction.csrf }).toString(), headers: { ...form({}).headers, ...interaction.cookie } });
			expect(resent.statusCode).toBe(200);
			expect(f.delivery.messages).toHaveLength(2);
			expect((await submitCode(f, interaction, f.delivery.messages[0].code)).statusCode).toBe(401);
			expect((await submitCode(f, interaction, f.delivery.messages[1].code)).statusCode).toBe(303);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("offers Face only when the client has no H1 email authority", async () => {
		setFlag(true);
		const f = await emailFixture({ emailInteractive: false });
		try {
			const { chooser, cookie } = await beginInteraction(f, "f".repeat(43));
			expect(chooser.body).not.toContain("Continue with Email");
			expect(chooser.body).toContain("Continue with Face");
			const emailPage = await f.app.inject({ method: "GET", url: "/login/email", headers: cookie });
			expect(emailPage.statusCode).toBe(303);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("POST /authorize H4 server-to-server handoff is unchanged by the flag", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const verifier = "ul-post-verifier-" + randomUUID();
			const authority = { context: { tenantId: f.tenantId, applicationId: f.applicationId }, clientId: CLIENT_ID };
			const started = await f.service.start(authority, KNOWN_EMAIL);
			const verified = await f.service.verify(authority, started.challengeId, f.delivery.messages[0].code);
			const payload = { client_id: CLIENT_ID, redirect_uri: REDIRECT, response_type: "code", scope: "openid email",
				nonce: "post-nonce", state: "post-state", code_challenge_method: "S256",
				code_challenge: pkceChallengeFromVerifier(verifier), authentication_result: verified.authenticationResult };
			const anonymous = await f.app.inject({ method: "POST", url: "/authorize", payload });
			expect(anonymous.statusCode, anonymous.body).toBe(401);
			const authorized = await f.app.inject({ method: "POST", url: "/authorize", headers: f.basic, payload });
			expect(authorized.statusCode, authorized.body).toBe(200);
			expect(authorized.headers["cache-control"]).toBe("no-store");
			expect(cookieFrom(authorized)).toBeUndefined();
			const redirect = new URL(authorized.json().redirectUri);
			expect(redirect.searchParams.get("state")).toBe("post-state");
			expect((await f.app.inject({ method: "POST", url: "/authorize", headers: f.basic, payload })).statusCode).toBe(401);
			const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code: redirect.searchParams.get("code")!, redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(token.statusCode).toBe(200);
			expect(decodeJwt(token.json().id_token)).toMatchObject({ sub: f.subject.oidcSubject, amr: ["email"], nonce: "post-nonce" });
			expect(f.provider.beginAsyncAuthentication).not.toHaveBeenCalled();
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});
});

describe("post-authentication passkey offer", () => {
	afterEach(() => {
		setFlag(undefined);
		vi.unstubAllEnvs();
		configuration.reload();
		vi.restoreAllMocks();
	});

	it.each([
		{ enabled: false, allowed: true },
		{ enabled: true, allowed: false }
	])("keeps email completion unchanged with enabled=$enabled and allowed=$allowed", async ({ enabled, allowed }) => {
		setFlag(true);
		vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", String(enabled));
		configuration.reload();
		const f = await emailFixture();
		try {
			if (allowed) {
				const application = (await f.h1.applications.findById(f.applicationId))!;
				await f.h1.applications.upsert({ ...application, allowedAuthenticationMethods: [...application.allowedAuthenticationMethods, "PASSKEY"] });
			}
			const interaction = await beginInteraction(f, "v".repeat(43));
			await startEmail(f, interaction, KNOWN_EMAIL);
			const done = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(done.statusCode, done.body).toBe(303);
			expect(new URL(done.headers.location as string).origin).toBe(new URL(REDIRECT).origin);
		} finally { await f.app.close(); }
	});

	it("requires both browser cookies, CSRF and origin, and issues only one code on concurrent skips", async () => {
		setFlag(true);
		vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", "true");
		configuration.reload();
		const redisPort = process.env.HAPI_PASSKEY_TEST_REDIS_PORT;
		const redis = redisPort ? new Redis({ host: "127.0.0.1", port: Number(redisPort) }) : undefined;
		const f = await emailFixture({ interactionStore: redis ? new AuthorizationInteractionStore(redis) : undefined });
		vi.spyOn(identityRegistry, "findById").mockImplementation(id => f.subjects.findById(id));
		try {
			const application = (await f.h1.applications.findById(f.applicationId))!;
			await f.h1.applications.upsert({ ...application, allowedAuthenticationMethods: [...application.allowedAuthenticationMethods, "PASSKEY"] });
			const verifier = "v".repeat(43);
			const interaction = await beginInteraction(f, verifier);
			await startEmail(f, interaction, KNOWN_EMAIL);
			const offered = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(offered.statusCode, offered.body).toBe(303);
			expect(offered.headers.location).toBe("/login/passkey");
			const proofCookie = setCookies(offered).find(value => value.startsWith("__Host-hapi_passkey="))!;
			expect(proofCookie).toMatch(/HttpOnly; Secure; SameSite=Lax/);
			const cookie = `${interaction.cookie.cookie}; ${proofCookie.split(";")[0]}`;
			expect((await f.app.inject({ method: "GET", url: "/login/passkey", headers: interaction.cookie })).statusCode).toBe(400);
			const page = await f.app.inject({ method: "GET", url: "/login/passkey", headers: { cookie } });
			expect(page.statusCode).toBe(200);
			expect(page.body).toContain("Not Now");
			const sendSkip = (csrf: string, origin: string, cookies = cookie) => f.app.inject({
				method: "POST", url: "/login/passkey/skip", ...form({ csrf }),
				headers: { ...form({}).headers, cookie: cookies, origin }
			});
			expect((await sendSkip(interaction.csrf, "https://evil.example")).statusCode).toBe(403);
			expect((await sendSkip("wrong", resolveConfiguredIssuer())).statusCode).toBe(400);
			expect((await sendSkip(interaction.csrf, resolveConfiguredIssuer(), interaction.cookie.cookie)).statusCode).toBe(400);
			const results = await Promise.all(Array.from({ length: 5 }, () => sendSkip(interaction.csrf, resolveConfiguredIssuer())));
			const successes = results.filter(result => result.statusCode === 303);
			expect(successes).toHaveLength(1);
			expect(results.filter(result => result.statusCode !== 303)).toHaveLength(4);
			const callback = new URL(successes[0].headers.location as string);
			const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!,
					redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(token.statusCode, token.body).toBe(200);
			expect(decodeJwt(token.json().id_token).sub).toBe(f.subject.oidcSubject);
			expect((await sendSkip(interaction.csrf, resolveConfiguredIssuer())).statusCode).toBe(400);
		} finally { await f.app.close(); if (redis) await redis.quit(); }
	});
});

const passkeyDatabaseUrl = process.env.HAPI_PASSKEY_TEST_DATABASE_URL;
const passkeyRedisPort = process.env.HAPI_PASSKEY_TEST_REDIS_PORT;
const stagingOrigin = "https://id-staging.hapiinc.com";

describe.skipIf(!passkeyDatabaseUrl || !passkeyRedisPort)("passkey enrollment (PostgreSQL, Redis and Chromium)", () => {
	const schema = `passkey_${randomUUID().replaceAll("-", "")}`;
	const admin = new pg.Pool({ connectionString: passkeyDatabaseUrl });
	const pool = new pg.Pool({ connectionString: passkeyDatabaseUrl, options: `-c search_path=${schema}` });
	let browser: Browser;

	beforeAll(async () => {
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		const ddl = readFileSync(new URL("../src/identity/schema-passkeys.sql", import.meta.url), "utf8");
		await pool.query(ddl);
		await pool.query(ddl);
		browser = await chromium.launch({ headless: true });
	});

	afterAll(async () => {
		await browser?.close();
		await pool.end();
		await admin.query(`DROP SCHEMA ${schema} CASCADE`);
		await admin.end();
	});

	afterEach(() => {
		setFlag(undefined);
		vi.unstubAllEnvs();
		configuration.reload();
		vi.restoreAllMocks();
	});

	async function setup(realOidcPersistence = false) {
		vi.spyOn(OIDCRateLimiter.prototype, "assertWithinLimits").mockResolvedValue();
		setFlag(true);
		vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", "true");
		vi.stubEnv("OIDC_ISSUER", stagingOrigin);
		vi.stubEnv("OIDC_ALLOWED_ISSUERS", stagingOrigin);
		configuration.reload();
		const redis = new Redis({ host: "127.0.0.1", port: Number(passkeyRedisPort) });
		if (realOidcPersistence) vi.spyOn(redisInfrastructure, "getRedisClient").mockReturnValue(redis);
		const store = new AuthorizationInteractionStore(redis);
		const credentials = new PostgresPasskeyCredentialRepository(pool);
		const f = await emailFixture({ interactionStore: store, passkeyCredentials: credentials });
		const postgresSubjects = new PostgresIdentitySubjectRepository(pool);
		vi.spyOn(identityRegistry, "findById").mockImplementation(id =>
			realOidcPersistence ? postgresSubjects.findById(id) : f.subjects.findById(id));
		if (realOidcPersistence) f.lookup.mockImplementation(sub => postgresSubjects.findByOidcSubject(sub));
		await pool.query(`INSERT INTO identity_subjects
			(id, oidc_subject, primary_provider, primary_provider_subject, status, created_at, updated_at)
			VALUES ($1, $2, 'HAPI_EMAIL', $3, 'ACTIVE', now(), now())`,
			[f.subject.id, f.subject.oidcSubject, `test-${f.subject.id}`]);
		const application = (await f.h1.applications.findById(f.applicationId))!;
		await f.h1.applications.upsert({ ...application, allowedAuthenticationMethods: [...application.allowedAuthenticationMethods, "PASSKEY"] });
		const interaction = await beginInteraction(f, "v".repeat(43));
		await startEmail(f, interaction, KNOWN_EMAIL);
		const offered = await submitCode(f, interaction, f.delivery.messages[0].code);
		expect(offered.headers.location).toBe("/login/passkey");
		const proofCookie = setCookies(offered).find(value => value.startsWith("__Host-hapi_passkey="))!;
		const cookie = `${interaction.cookie.cookie}; ${proofCookie.split(";")[0]}`;
		const headers = { cookie, origin: stagingOrigin };
		const options = () => f.app.inject({ method: "POST", url: "/login/passkey/options",
			headers, payload: { csrf: interaction.csrf } });
		const verify = (credential: RegistrationResponseJSON) => f.app.inject({ method: "POST", url: "/login/passkey/verify",
			headers, payload: { csrf: interaction.csrf, credential } });
		const close = async () => { await f.app.close(); await redis.quit(); };
		return { f, redis, store, credentials, interaction, headers, options, verify, close };
	}

	async function authenticator(synchronized = false): Promise<{ page: Page; close: () => Promise<void> }> {
		const context = await browser.newContext();
		const page = await context.newPage();
		await page.route(`${stagingOrigin}/**`, route => route.fulfill({ status: 200, contentType: "text/html", body: "<html></html>" }));
		await page.goto(stagingOrigin);
		const cdp = await context.newCDPSession(page);
		await cdp.send("WebAuthn.enable");
		await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
			protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
			isUserVerified: true, automaticPresenceSimulation: true, defaultBackupEligibility: synchronized
		} });
		await page.addScriptTag({ path: "node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js" });
		return { page, close: () => context.close() };
	}

	async function createCredential(page: Page, options: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON> {
		return page.evaluate(async opts => {
			const webauthn = (globalThis as typeof globalThis & {
				SimpleWebAuthnBrowser: { startRegistration(input: { optionsJSON: typeof opts }): Promise<RegistrationResponseJSON> }
			}).SimpleWebAuthnBrowser;
			return webauthn.startRegistration({ optionsJSON: opts });
		}, options);
	}

	async function createAssertion(page: Page, options: PublicKeyCredentialRequestOptionsJSON): Promise<AuthenticationResponseJSON> {
		return page.evaluate(async opts => {
			const webauthn = (globalThis as typeof globalThis & {
				SimpleWebAuthnBrowser: { startAuthentication(input: { optionsJSON: typeof opts }): Promise<AuthenticationResponseJSON> }
			}).SimpleWebAuthnBrowser;
			return webauthn.startAuthentication({ optionsJSON: opts });
		}, options);
	}

	async function enroll(t: Awaited<ReturnType<typeof setup>>, page: Page) {
		const options = await t.options();
		expect(options.statusCode, options.body).toBe(200);
		const credential = await createCredential(page, options.json());
		expect((await t.verify(credential)).statusCode).toBe(200);
		return credential;
	}

	async function beginPasskeyLogin(t: Awaited<ReturnType<typeof setup>>) {
		const interaction = await beginInteraction(t.f, "p".repeat(43));
		const headers = { ...interaction.cookie, origin: stagingOrigin };
		const options = (purpose?: "manage") => t.f.app.inject({ method: "POST", url: "/login/passkey/auth/options",
			headers, payload: { csrf: interaction.csrf, ...(purpose ? { purpose } : {}) } });
		const verify = (credential: AuthenticationResponseJSON) => t.f.app.inject({ method: "POST", url: "/login/passkey/auth/verify",
			headers, payload: { csrf: interaction.csrf, credential } });
		return { interaction, headers, options, verify };
	}

	it("enrolls and signs in twice with a passkey, PKCE, a signed ID token and matching UserInfo", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const credential = await enroll(t, a.page);
			const owner = await pool.query<{ identity_subject_id: string }>(
				"SELECT identity_subject_id FROM passkey_credentials WHERE credential_id = $1", [credential.id]);
			expect(owner.rows).toEqual([{ identity_subject_id: t.f.subject.id }]);
			const emailCount = t.f.delivery.messages.length;
			t.f.oidcClient.grant_types = ["authorization_code", "refresh_token"];
			vi.stubEnv("HAPI_PERSISTENT_SESSIONS_ENABLED", "true");
			vi.stubEnv("HAPI_REFRESH_GRANT_ENABLED", "true");
			configuration.reload();
			for (let attempt = 0; attempt < 2; attempt++) {
				const login = await beginPasskeyLogin(t);
				expect(login.interaction.chooser.body).toContain("Continue with Passkey");
				const response = await login.options();
				expect(response.statusCode, response.body).toBe(200);
				const options = response.json<PublicKeyCredentialRequestOptionsJSON>();
				expect(options.userVerification).toBe("required");
				expect(options.allowCredentials ?? []).toHaveLength(0);
				const assertion = await createAssertion(a.page, options);
				const results = await Promise.all(Array.from({ length: 8 }, () => login.verify(assertion)));
				const success = results.filter(result => result.statusCode === 200);
				expect(success).toHaveLength(1);
				expect(setCookies(success[0]).some(value => value.startsWith("__Host-hapi_session="))).toBe(false);
				const callback = new URL(success[0].json().redirect);
				const token = await t.f.app.inject({ method: "POST", url: "/token", headers: t.f.basic,
					payload: { grant_type: "authorization_code", code: callback.searchParams.get("code")!,
						redirect_uri: REDIRECT, code_verifier: "p".repeat(43) } });
				expect(token.statusCode, token.body).toBe(200);
				expect(token.json().refresh_token).toBeUndefined();
				const idToken = token.json().id_token;
				const jwks = (await t.f.app.inject({ method: "GET", url: "/jwks" })).json().keys;
				const jwk = jwks.find((key: { kid?: string }) => key.kid === decodeProtectedHeader(idToken).kid);
				const verified = await jwtVerify(idToken, await importJWK(jwk, "RS256"), { issuer: stagingOrigin, audience: CLIENT_ID });
				expect(verified.payload).toMatchObject({ sub: t.f.subject.oidcSubject, amr: ["passkey"],
					email: KNOWN_EMAIL, email_verified: true });
				const userinfo = await t.f.app.inject({ method: "GET", url: "/userinfo",
					headers: { authorization: `Bearer ${token.json().access_token}` } });
				expect(userinfo.statusCode, userinfo.body).toBe(200);
				const info = userinfo.json();
				expect(info).toMatchObject({ sub: verified.payload.sub, email: KNOWN_EMAIL, email_verified: true });
				expect(validateStagingConsoleUserInfo(verified.payload, info, KNOWN_EMAIL, t.f.subject.oidcSubject)).toBe(true);
				expect(validateStagingConsoleUserInfo(verified.payload, { ...info, sub: randomUUID() },
					KNOWN_EMAIL, t.f.subject.oidcSubject)).toBe(false);
				expect((await login.verify(assertion)).statusCode).not.toBe(200);
			}
			expect(t.f.delivery.messages).toHaveLength(emailCount);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("redeems a passkey authorization code once with real Redis OIDC storage and PostgreSQL identity resolution", async () => {
		const t = await setup(true);
		const a = await authenticator();
		try {
			await enroll(t, a.page);
			const login = await beginPasskeyLogin(t);
			const assertion = await createAssertion(a.page, (await login.options()).json());
			const verified = await login.verify(assertion);
			expect(verified.statusCode, verified.body).toBe(200);
			const code = new URL(verified.json().redirect).searchParams.get("code")!;
			expect(await t.redis.get(oidcRedisKey(`auth_code:${code}`))).not.toBeNull();
			const tokens = await Promise.all(Array.from({ length: 5 }, () => t.f.app.inject({
				method: "POST", url: "/token", headers: t.f.basic,
				payload: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "p".repeat(43) }
			})));
			const success = tokens.filter(response => response.statusCode === 200);
			expect(success).toHaveLength(1);
			const token = success[0].json();
			const jwks = (await t.f.app.inject({ method: "GET", url: "/jwks" })).json().keys;
			const jwk = jwks.find((key: { kid?: string }) => key.kid === decodeProtectedHeader(token.id_token).kid);
			const signed = await jwtVerify(token.id_token, await importJWK(jwk, "RS256"), { issuer: stagingOrigin, audience: CLIENT_ID });
			expect(signed.payload).toMatchObject({ sub: t.f.subject.oidcSubject, amr: ["passkey"] });
			expect(await t.redis.get(oidcRedisKey(`access_token:${token.access_token}`))).not.toBeNull();
			const userinfo = await t.f.app.inject({ method: "GET", url: "/userinfo",
				headers: { authorization: `Bearer ${token.access_token}` } });
			expect(userinfo.statusCode, userinfo.body).toBe(200);
			expect(userinfo.json().sub).toBe(t.f.subject.oidcSubject);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it.each(["challenge", "origin", "rp", "signature", "user verification", "unknown", "user handle"] as const)(
		"rejects an assertion with invalid %s", async kind => {
			const t = await setup();
			const a = await authenticator();
			try {
				await enroll(t, a.page);
				const login = await beginPasskeyLogin(t);
				const opts = await login.options();
				const assertion = await createAssertion(a.page, opts.json());
				if (kind === "origin" || kind === "challenge") {
					const data = JSON.parse(Buffer.from(assertion.response.clientDataJSON, "base64url").toString("utf8"));
					if (kind === "origin") data.origin = "https://evil.example";
					else data.challenge = randomBytes(32).toString("base64url");
					assertion.response.clientDataJSON = Buffer.from(JSON.stringify(data)).toString("base64url");
				} else if (kind === "rp" || kind === "user verification") {
					const data = Buffer.from(assertion.response.authenticatorData, "base64url");
					if (kind === "rp") data[0] ^= 1;
					else data[32] &= ~0x04;
					assertion.response.authenticatorData = data.toString("base64url");
				} else if (kind === "signature") {
					const data = Buffer.from(assertion.response.signature, "base64url");
					data[data.length - 1] ^= 1;
					assertion.response.signature = data.toString("base64url");
				} else if (kind === "unknown") {
					assertion.id = randomBytes(32).toString("base64url");
					assertion.rawId = assertion.id;
				} else {
					assertion.response.userHandle = randomBytes(32).toString("base64url");
				}
				expect((await login.verify(assertion)).statusCode).toBe(401);
				expect((await login.verify(assertion)).statusCode).not.toBe(200);
			} finally { await a.close(); await t.close(); }
		}, 30_000);

	it("enforces single-device counters while allowing non-monotonic synchronized passkey counters", async () => {
		for (const synced of [false, true]) {
			const t = await setup();
			const a = await authenticator(synced);
			try {
				const credential = await enroll(t, a.page);
				await pool.query("UPDATE passkey_credentials SET signature_counter = 100 WHERE credential_id = $1", [credential.id]);
				const login = await beginPasskeyLogin(t);
				const assertion = await createAssertion(a.page, (await login.options()).json());
				const result = await login.verify(assertion);
				expect(result.statusCode, result.body).toBe(synced ? 200 : 401);
				const row = (await pool.query("SELECT signature_counter, backup_eligible FROM passkey_credentials WHERE credential_id = $1", [credential.id])).rows[0];
				expect(Number(row.signature_counter)).toBe(100);
				expect(row.backup_eligible).toBe(synced);
			} finally { await a.close(); await t.close(); vi.restoreAllMocks(); }
		}
	}, 30_000);

	it("runs the actual passkey login chooser and browser ceremony", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			await enroll(t, a.page);
			const login = await beginPasskeyLogin(t);
			await a.page.unroute(`${stagingOrigin}/**`);
			await a.page.context().addCookies([{ name: "__Host-hapi_login", value: login.interaction.handle, url: stagingOrigin, secure: true }]);
			await a.page.route(`${stagingOrigin}/**`, async route => {
				const request = route.request();
				const url = new URL(request.url());
				const response = await t.f.app.inject({ method: request.method() as "GET" | "POST",
					url: `${url.pathname}${url.search}`, headers: await request.allHeaders(),
					...(request.postData() ? { payload: request.postData()! } : {}) });
				const headers: Record<string, string> = {};
				for (const name of ["content-type", "content-security-policy", "cache-control"]) {
					const value = response.headers[name];
					if (typeof value === "string") headers[name] = value;
				}
				await route.fulfill({ status: response.statusCode, headers, body: response.body });
			});
			await a.page.route("https://rp.example/**", route => route.fulfill({ status: 200, body: "completed" }));
			await a.page.goto(`${stagingOrigin}/login`);
			await a.page.getByRole("button", { name: "Continue with Passkey" }).click();
			await a.page.waitForURL("https://rp.example/**", { timeout: 10_000 });
			expect(new URL(a.page.url()).searchParams.has("code")).toBe(true);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("requires fresh subject-bound management and rejects revoked or foreign credentials", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const credential = await enroll(t, a.page);
			const other = randomUUID();
			const otherSub = randomUUID();
			await pool.query(`INSERT INTO identity_subjects
				(id, oidc_subject, primary_provider, primary_provider_subject, status, created_at, updated_at)
				VALUES ($1, $2, 'HAPI_EMAIL', $3, 'ACTIVE', now(), now())`, [other, otherSub, `test-${other}`]);
			const foreign = randomBytes(32).toString("base64url");
			await t.credentials.insert({ subjectId: other, oidcSubject: otherSub, userHandle: await t.credentials.userHandle(other),
				authorityRef: randomUUID(), expiresAt: Date.now() + 60_000,
				credential: { id: foreign, publicKey: Uint8Array.from([1]), counter: 0 }, backupEligible: false, backupState: false });
			const login = await beginPasskeyLogin(t);
			expect((await t.f.app.inject({ method: "GET", url: "/login/passkey/manage", headers: login.headers })).statusCode).not.toBe(200);
			const opts = await login.options("manage");
			const assertion = await createAssertion(a.page, opts.json());
			const verified = await login.verify(assertion);
			expect(verified.statusCode, verified.body).toBe(200);
			expect(verified.json().redirect).toBe("/login/passkey/manage");
			const proof = setCookies(verified).find(value => value.startsWith("__Host-hapi_passkey="))!.split(";")[0];
			const headers = { ...login.headers, cookie: `${login.headers.cookie}; ${proof}` };
			const management = await t.f.app.inject({ method: "GET", url: "/login/passkey/manage", headers });
			expect(management.statusCode, management.body).toBe(200);
			expect(management.body).toContain(credential.id);
			expect(management.body).not.toContain(foreign);
			const revoke = (id: string, csrf = login.interaction.csrf, origin = stagingOrigin) =>
				t.f.app.inject({ method: "POST", url: "/login/passkey/revoke", headers: { ...headers, origin },
					payload: { csrf, credential_id: id } });
			expect((await revoke(foreign, "wrong")).statusCode).toBe(400);
			expect((await revoke(foreign, login.interaction.csrf, "https://evil.example")).statusCode).toBe(403);
			expect((await revoke(foreign)).statusCode).toBe(404);
			expect((await pool.query("SELECT revoked_at FROM passkey_credentials WHERE credential_id = $1", [foreign])).rows[0].revoked_at).toBeNull();
			expect((await revoke(credential.id)).statusCode).toBe(200);
			expect((await t.f.app.inject({ method: "GET", url: "/login/passkey/manage", headers })).statusCode).toBe(403);
			const retry = await beginPasskeyLogin(t);
			const retryAssertion = await createAssertion(a.page, (await retry.options()).json());
			expect((await retry.verify(retryAssertion)).statusCode).toBe(401);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it.each(["GOOGLE", "HAPI_EMAIL"] as const)("rejects management and additional enrollment without fresh %s authentication", async method => {
		const t = await setup();
		const a = await authenticator();
		try {
			await enroll(t, a.page);
			const login = await beginPasskeyLogin(t);
			const interaction = (await t.store.find(login.interaction.handle))!;
			const offered = await t.store.offerPasskeyEnrollment(login.interaction.handle, interaction, {
				id: t.f.subject.id, sub: t.f.subject.oidcSubject, authenticationMethod: method,
				authenticatedAt: new Date(Date.now() - (method === "HAPI_EMAIL" ? 300_001 : 0)).toISOString()
			});
			const headers = { ...login.headers, cookie: `${login.headers.cookie}; __Host-hapi_passkey=${offered!.browserProof}` };
			expect((await t.f.app.inject({ method: "GET", url: "/login/passkey/manage", headers })).statusCode).toBe(403);
			expect((await t.f.app.inject({ method: "POST", url: "/login/passkey/options",
				headers, payload: { csrf: login.interaction.csrf } })).statusCode).toBe(403);
			const handle = await t.credentials.userHandle(t.f.subject.id);
			await expect(t.credentials.insert({ subjectId: t.f.subject.id, oidcSubject: t.f.subject.oidcSubject,
				userHandle: handle, authorityRef: randomUUID(), expiresAt: Date.now() + 60_000,
				credential: { id: randomBytes(32).toString("base64url"), publicKey: Uint8Array.from([1]), counter: 0 },
				backupEligible: false, backupState: false })).rejects.toThrow("Fresh authentication required");
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("runs passkey reauthentication and self-revocation from the browser", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const credential = await enroll(t, a.page);
			const login = await beginPasskeyLogin(t);
			await a.page.unroute(`${stagingOrigin}/**`);
			await a.page.context().addCookies([{ name: "__Host-hapi_login", value: login.interaction.handle, url: stagingOrigin, secure: true }]);
			await a.page.route(`${stagingOrigin}/**`, async route => {
				const request = route.request();
				const url = new URL(request.url());
				const response = await t.f.app.inject({ method: request.method() as "GET" | "POST",
					url: `${url.pathname}${url.search}`, headers: await request.allHeaders(),
					...(request.postData() ? { payload: request.postData()! } : {}) });
				const headers: Record<string, string> = {};
				for (const name of ["content-type", "content-security-policy", "cache-control", "location", "set-cookie"]) {
					const value = response.headers[name];
					if (typeof value === "string") headers[name] = value;
				}
				await route.fulfill({ status: response.statusCode, headers, body: response.body });
			});
			await a.page.goto(`${stagingOrigin}/login`);
			await a.page.getByRole("button", { name: "Manage passkeys" }).click();
			await a.page.waitForURL(`${stagingOrigin}/login/passkey/manage`, { timeout: 10_000 });
			await a.page.getByRole("button", { name: "Revoke passkey 1" }).click();
			await a.page.getByText("Your passkey was revoked. Start sign-in again using another method.").waitFor();
			expect((await pool.query("SELECT revoked_at FROM passkey_credentials WHERE credential_id = $1", [credential.id])).rows[0].revoked_at).not.toBeNull();
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("rejects incorrect PKCE and a credential revoked before code redemption", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const credential = await enroll(t, a.page);
			for (const failure of ["pkce", "revoked"] as const) {
				const login = await beginPasskeyLogin(t);
				const assertion = await createAssertion(a.page, (await login.options()).json());
				const verified = await login.verify(assertion);
				expect(verified.statusCode).toBe(200);
				const code = new URL(verified.json().redirect).searchParams.get("code")!;
				if (failure === "revoked") {
					expect(await t.credentials.revoke(t.f.subject.id, t.f.subject.oidcSubject, credential.id, Date.now() + 60_000)).toBe(true);
				}
				const token = await t.f.app.inject({ method: "POST", url: "/token", headers: t.f.basic,
					payload: { grant_type: "authorization_code", code, redirect_uri: REDIRECT,
						code_verifier: failure === "pkce" ? "x".repeat(43) : "p".repeat(43) } });
				expect(token.statusCode).toBe(400);
			}
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("adds a second credential after passkey reauthentication and preserves its owner", async () => {
		const t = await setup();
		const first = await authenticator();
		const second = await authenticator();
		try {
			const initial = await enroll(t, first.page);
			const login = await beginPasskeyLogin(t);
			const assertion = await createAssertion(first.page, (await login.options("manage")).json());
			const verified = await login.verify(assertion);
			const proof = setCookies(verified).find(value => value.startsWith("__Host-hapi_passkey="))!.split(";")[0];
			const headers = { ...login.headers, cookie: `${login.headers.cookie}; ${proof}` };
			const options = await t.f.app.inject({ method: "POST", url: "/login/passkey/options",
				headers, payload: { csrf: login.interaction.csrf } });
			expect(options.statusCode, options.body).toBe(200);
			const additional = await createCredential(second.page, options.json());
			const result = await t.f.app.inject({ method: "POST", url: "/login/passkey/verify",
				headers, payload: { csrf: login.interaction.csrf, credential: additional } });
			expect(result.statusCode, result.body).toBe(200);
			const rows = await pool.query("SELECT credential_id, identity_subject_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id]);
			expect(rows.rows).toHaveLength(2);
			expect(rows.rows.map(row => row.credential_id)).toEqual(expect.arrayContaining([initial.id, additional.id]));
			expect(rows.rows.every(row => row.identity_subject_id === t.f.subject.id)).toBe(true);
		} finally { await second.close(); await first.close(); await t.close(); }
	}, 30_000);

	it("fails closed for expired challenges and Redis or PostgreSQL assertion failures", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			await enroll(t, a.page);
			const before = (await pool.query("SELECT signature_counter, last_used_at FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id])).rows[0];
			for (const failure of ["expired", "redis", "database"] as const) {
				const login = await beginPasskeyLogin(t);
				const assertion = await createAssertion(a.page, (await login.options()).json());
				if (failure === "expired") {
					const hash = createHash("sha256").update(login.interaction.handle).digest("base64url");
					await t.redis.pexpire(oidcRedisKey(`interaction_passkey_authentication:${hash}`), 1);
					await new Promise(resolve => setTimeout(resolve, 20));
				} else if (failure === "redis") {
					vi.spyOn(t.store, "claimPasskeyAuthentication").mockRejectedValueOnce(new Error("synthetic Redis failure"));
				} else {
					await pool.query(`CREATE FUNCTION reject_test_assertion() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN RAISE EXCEPTION 'synthetic assertion failure'; END $$`);
					await pool.query(`CREATE TRIGGER reject_test_assertion AFTER UPDATE ON passkey_credentials
						FOR EACH ROW EXECUTE FUNCTION reject_test_assertion()`);
				}
				const result = await login.verify(assertion);
				expect(result.statusCode, result.body).toBe(failure === "expired" ? 400 : 503);
			}
			const rows = await pool.query("SELECT signature_counter, last_used_at FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id]);
			expect(rows.rows[0]).toEqual(before);
		} finally {
			await pool.query("DROP TRIGGER IF EXISTS reject_test_assertion ON passkey_credentials");
			await pool.query("DROP FUNCTION IF EXISTS reject_test_assertion()");
			await a.close(); await t.close();
		}
	}, 30_000);

	it("fails closed on Redis and PostgreSQL errors while revoking", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const credential = await enroll(t, a.page);
			const login = await beginPasskeyLogin(t);
			const assertion = await createAssertion(a.page, (await login.options("manage")).json());
			const verified = await login.verify(assertion);
			const proof = setCookies(verified).find(value => value.startsWith("__Host-hapi_passkey="))!.split(";")[0];
			const headers = { ...login.headers, cookie: `${login.headers.cookie}; ${proof}` };
			const revoke = () => t.f.app.inject({ method: "POST", url: "/login/passkey/revoke",
				headers, payload: { csrf: login.interaction.csrf, credential_id: credential.id } });
			vi.spyOn(t.store, "transitionPasskeyEnrollment").mockRejectedValueOnce(new Error("synthetic Redis failure"));
			expect((await revoke()).statusCode).toBe(503);
			await pool.query(`CREATE FUNCTION reject_test_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'synthetic revocation failure'; END $$`);
			await pool.query(`CREATE TRIGGER reject_test_revoke AFTER UPDATE ON passkey_credentials
				FOR EACH ROW EXECUTE FUNCTION reject_test_revoke()`);
			expect((await revoke()).statusCode).toBe(503);
			expect((await pool.query("SELECT revoked_at FROM passkey_credentials WHERE credential_id = $1", [credential.id])).rows[0].revoked_at).toBeNull();
		} finally {
			await pool.query("DROP TRIGGER IF EXISTS reject_test_revoke ON passkey_credentials");
			await pool.query("DROP FUNCTION IF EXISTS reject_test_revoke()");
			await a.close(); await t.close();
		}
	}, 30_000);

	it("hides and rejects passkey login when the feature or application capability is disabled", async () => {
		const t = await setup();
		try {
			vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", "false");
			configuration.reload();
			const disabled = await beginPasskeyLogin(t);
			expect(disabled.interaction.chooser.body).not.toContain("Continue with Passkey");
			expect((await disabled.options()).statusCode).toBe(403);
			vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", "true");
			configuration.reload();
			const app = (await t.f.h1.applications.findById(t.f.applicationId))!;
			await t.f.h1.applications.upsert({ ...app, allowedAuthenticationMethods: app.allowedAuthenticationMethods.filter(method => method !== "PASSKEY") });
			const forbidden = await beginPasskeyLogin(t);
			expect(forbidden.interaction.chooser.body).not.toContain("Continue with Passkey");
			expect((await forbidden.options()).statusCode).toBe(403);
		} finally { await t.close(); }
	}, 30_000);

	it("persists a verified browser credential for the exact subject and completes OIDC once", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const offers = await Promise.all(Array.from({ length: 8 }, () => t.options()));
			const winner = offers.filter(result => result.statusCode === 200);
			expect(winner).toHaveLength(1);
			const options = winner[0].json<PublicKeyCredentialCreationOptionsJSON>();
			expect(options.rp).toEqual({ id: "id-staging.hapiinc.com", name: "HAPI ID Staging" });
			expect(options.user.id).not.toContain(KNOWN_EMAIL);
			expect(options.authenticatorSelection?.userVerification).toBe("required");
			const credential = await createCredential(a.page, options);
			const results = await Promise.all(Array.from({ length: 8 }, () => t.verify(credential)));
			const success = results.filter(result => result.statusCode === 200);
			expect(success).toHaveLength(1);
			const rows = await pool.query(`SELECT credential_id, identity_subject_id, user_handle, public_key, revoked_at
				FROM passkey_credentials WHERE identity_subject_id = $1`, [t.f.subject.id]);
			expect(rows.rows).toHaveLength(1);
			expect(rows.rows[0]).toMatchObject({ credential_id: credential.id, identity_subject_id: t.f.subject.id, revoked_at: null });
			expect(rows.rows[0].user_handle.toString("base64url")).toBe(options.user.id);
			expect(rows.rows[0].public_key.length).toBeGreaterThan(0);
			const callback = new URL(success[0].json().redirect);
			const code = callback.searchParams.get("code")!;
			const token = await t.f.app.inject({ method: "POST", url: "/token", headers: t.f.basic,
				payload: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "v".repeat(43) } });
			expect(token.statusCode, token.body).toBe(200);
			expect(decodeJwt(token.json().id_token).sub).toBe(t.f.subject.oidcSubject);
			expect((await t.verify(credential)).statusCode).not.toBe(200);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("runs the actual Add Passkey page and native browser ceremony", async () => {
		const t = await setup();
		const context = await browser.newContext();
		const page = await context.newPage();
		const proof = t.headers.cookie.split("; ").find(value => value.startsWith("__Host-hapi_passkey="))!.split("=")[1];
		try {
			await context.addCookies([
				{ name: "__Host-hapi_login", value: t.interaction.handle, url: stagingOrigin, secure: true },
				{ name: "__Host-hapi_passkey", value: proof, url: stagingOrigin, secure: true }
			]);
			await page.route(`${stagingOrigin}/**`, async route => {
				const request = route.request();
				const url = new URL(request.url());
				const response = await t.f.app.inject({ method: request.method() as "GET" | "POST",
					url: `${url.pathname}${url.search}`, headers: await request.allHeaders(),
					...(request.postData() ? { payload: request.postData()! } : {}) });
				const headers: Record<string, string> = {};
				for (const name of ["content-type", "content-security-policy", "cache-control"]) {
					const value = response.headers[name];
					if (typeof value === "string") headers[name] = value;
				}
				await route.fulfill({ status: response.statusCode, headers, body: response.body });
			});
			await page.route("https://rp.example/**", route => route.fulfill({ status: 200, body: "completed" }));
			const cdp = await context.newCDPSession(page);
			await cdp.send("WebAuthn.enable");
			await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
				protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
				isUserVerified: true, automaticPresenceSimulation: true
			} });
			await page.goto(`${stagingOrigin}/login/passkey`);
			await page.getByRole("button", { name: "Add Passkey" }).click();
			await page.waitForURL("https://rp.example/**", { timeout: 10_000 });
			expect(new URL(page.url()).searchParams.has("code")).toBe(true);
			const rows = await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id]);
			expect(rows.rows).toHaveLength(1);
		} finally { await context.close(); await t.close(); }
	}, 30_000);

	it.each(["challenge", "origin", "rp", "user verification"] as const)("rejects an invalid %s", async kind => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			expect(response.statusCode).toBe(200);
			const credential = await createCredential(a.page, response.json());
			if (kind === "challenge" || kind === "origin") {
				const data = JSON.parse(Buffer.from(credential.response.clientDataJSON, "base64url").toString("utf8"));
				if (kind === "challenge") data.challenge = randomBytes(32).toString("base64url");
				else data.origin = "https://other.example";
				credential.response.clientDataJSON = Buffer.from(JSON.stringify(data)).toString("base64url");
			} else {
				const attestation = Buffer.from(credential.response.attestationObject, "base64url");
				const index = attestation.indexOf(createHash("sha256").update("id-staging.hapiinc.com").digest());
				expect(index).toBeGreaterThan(-1);
				if (kind === "rp") attestation[index] ^= 1;
				else attestation[index + 32] &= ~0x04;
				credential.response.attestationObject = attestation.toString("base64url");
			}
			expect((await t.verify(credential)).statusCode).toBe(400);
			const rows = await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id]);
			expect(rows.rows).toHaveLength(0);
			const skip = await t.f.app.inject({ method: "POST", url: "/login/passkey/skip",
				...form({ csrf: t.interaction.csrf }), headers: { ...form({}).headers, ...t.headers } });
			expect(skip.statusCode).toBe(303);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("rolls back a failed PostgreSQL insert and never reports enrollment success", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			const credential = await createCredential(a.page, response.json());
			await pool.query(`CREATE FUNCTION reject_test_passkey() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'synthetic insert failure'; END $$`);
			await pool.query(`CREATE TRIGGER reject_test_passkey AFTER INSERT ON passkey_credentials
				FOR EACH ROW EXECUTE FUNCTION reject_test_passkey()`);
			expect((await t.verify(credential)).statusCode).toBe(503);
			const rows = await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id]);
			expect(rows.rows).toHaveLength(0);
			const skip = await t.f.app.inject({ method: "POST", url: "/login/passkey/skip",
				...form({ csrf: t.interaction.csrf }), headers: { ...form({}).headers, ...t.headers } });
			expect(skip.statusCode).toBe(303);
		} finally {
			await pool.query("DROP TRIGGER IF EXISTS reject_test_passkey ON passkey_credentials");
			await pool.query("DROP FUNCTION IF EXISTS reject_test_passkey()");
			await a.close();
			await t.close();
		}
	}, 30_000);

	it("requires the flag, client capability, CSRF, origin, and matching authenticated subject", async () => {
		const t = await setup();
		try {
			const call = (csrf: string, origin: string) => t.f.app.inject({ method: "POST", url: "/login/passkey/options",
				headers: { ...t.headers, origin }, payload: { csrf } });
			expect((await call("wrong", stagingOrigin)).statusCode).toBe(400);
			expect((await call(t.interaction.csrf, "https://evil.example")).statusCode).toBe(403);
			vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", "false");
			configuration.reload();
			expect((await t.options()).statusCode).toBe(403);
			const disabledPage = await t.f.app.inject({ method: "GET", url: "/login/passkey", headers: t.headers });
			expect(disabledPage.body).not.toContain('id="passkey-add"');
			expect(disabledPage.body).toContain("Not Now");
			vi.stubEnv("HAPI_PASSKEY_AUTHENTICATION_ENABLED", "true");
			configuration.reload();
			const app = (await t.f.h1.applications.findById(t.f.applicationId))!;
			await t.f.h1.applications.upsert({ ...app, allowedAuthenticationMethods: app.allowedAuthenticationMethods.filter(method => method !== "PASSKEY") });
			expect((await t.options()).statusCode).toBe(403);
			await t.f.h1.applications.upsert(app);
			vi.mocked(identityRegistry.findById).mockResolvedValueOnce({ ...t.f.subject, oidcSubject: randomUUID() });
			expect((await t.options()).statusCode).toBe(400);
			expect((await pool.query("SELECT user_handle FROM passkey_user_handles WHERE identity_subject_id = $1", [t.f.subject.id])).rows).toHaveLength(0);
			const skip = await t.f.app.inject({ method: "POST", url: "/login/passkey/skip",
				...form({ csrf: t.interaction.csrf }), headers: { ...form({}).headers, ...t.headers } });
			expect(skip.statusCode).toBe(303);
		} finally { await t.close(); }
	}, 30_000);

	it("fails closed when Redis cannot claim verification", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			const credential = await createCredential(a.page, response.json());
			vi.spyOn(t.redis, "eval").mockRejectedValueOnce(new Error("synthetic Redis failure"));
			expect((await t.verify(credential)).statusCode).toBe(503);
			const rows = await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id]);
			expect(rows.rows).toHaveLength(0);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("does not commit when the PostgreSQL subject becomes inactive", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			const credential = await createCredential(a.page, response.json());
			await pool.query("UPDATE identity_subjects SET status = 'LOCKED' WHERE id = $1", [t.f.subject.id]);
			expect((await t.verify(credential)).statusCode).toBe(503);
			expect((await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id])).rows).toHaveLength(0);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("retains the correct committed credential if Redis fails before completion", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			const credential = await createCredential(a.page, response.json());
			vi.spyOn(t.store, "transitionPasskeyEnrollment").mockRejectedValueOnce(new Error("synthetic Redis failure"));
			expect((await t.verify(credential)).statusCode).toBe(503);
			const rows = await pool.query("SELECT credential_id, identity_subject_id FROM passkey_credentials WHERE credential_id = $1", [credential.id]);
			expect(rows.rows).toEqual([{ credential_id: credential.id, identity_subject_id: t.f.subject.id }]);
			expect((await t.verify(credential)).statusCode).not.toBe(200);
			expect((await pool.query("SELECT credential_id FROM passkey_credentials WHERE credential_id = $1", [credential.id])).rows).toHaveLength(1);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("retains a committed credential when the browser never follows the completion redirect", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			const credential = await createCredential(a.page, response.json());
			expect((await t.verify(credential)).statusCode).toBe(200);
			const rows = await pool.query("SELECT credential_id, identity_subject_id FROM passkey_credentials WHERE credential_id = $1", [credential.id]);
			expect(rows.rows).toEqual([{ credential_id: credential.id, identity_subject_id: t.f.subject.id }]);
			expect((await t.verify(credential)).statusCode).not.toBe(200);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("rejects an authority whose Redis lifetime expires before verification", async () => {
		const t = await setup();
		const a = await authenticator();
		try {
			const response = await t.options();
			const credential = await createCredential(a.page, response.json());
			const hash = createHash("sha256").update(t.interaction.handle).digest("base64url");
			await t.redis.pexpire(oidcRedisKey(`interaction_passkey_enrollment_live:${hash}`), 1);
			await new Promise(resolve => setTimeout(resolve, 20));
			expect((await t.verify(credential)).statusCode).not.toBe(200);
			expect((await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [t.f.subject.id])).rows).toHaveLength(0);
		} finally { await a.close(); await t.close(); }
	}, 30_000);

	it("enforces credential and authority uniqueness under real PostgreSQL races", async () => {
		const t = await setup();
		try {
			const other = randomUUID();
			const otherSub = randomUUID();
			await pool.query(`INSERT INTO identity_subjects
				(id, oidc_subject, primary_provider, primary_provider_subject, status, created_at, updated_at)
				VALUES ($1, $2, 'HAPI_EMAIL', $3, 'ACTIVE', now(), now())`, [other, otherSub, `test-${other}`]);
			const handles = await Promise.all(Array.from({ length: 5 }, () => t.credentials.userHandle(t.f.subject.id)));
			expect(new Set(handles.map(handle => handle.toString("base64url"))).size).toBe(1);
			const otherHandle = await t.credentials.userHandle(other);
			const credential = { id: randomBytes(32).toString("base64url"), publicKey: Uint8Array.from([1]), counter: 0 };
			const inputs = [
				{ subjectId: t.f.subject.id, oidcSubject: t.f.subject.oidcSubject, userHandle: handles[0], authorityRef: randomUUID() },
				{ subjectId: other, oidcSubject: otherSub, userHandle: otherHandle, authorityRef: randomUUID() }
			];
			const results = await Promise.allSettled(inputs.map(input => t.credentials.insert({ ...input,
				expiresAt: Date.now() + 60_000, credential, backupEligible: false, backupState: false })));
			expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
			expect(results.filter(result => result.status === "rejected")).toHaveLength(1);
			const row = (await pool.query("SELECT identity_subject_id, enrollment_authority_ref FROM passkey_credentials WHERE credential_id = $1", [credential.id])).rows[0];
			const winner = inputs.find(input => input.subjectId === row.identity_subject_id)!;
			await expect(t.credentials.insert({ ...winner, authorityRef: row.enrollment_authority_ref,
				expiresAt: Date.now() + 60_000, additionalEnrollmentExpiresAt: Date.now() + 60_000,
				credential: { ...credential, id: randomBytes(32).toString("base64url") },
				backupEligible: false, backupState: false })).rejects.toMatchObject({ code: "23505" });
			expect((await pool.query("SELECT credential_id FROM passkey_credentials WHERE enrollment_authority_ref = $1",
				[row.enrollment_authority_ref])).rows).toHaveLength(1);
			await t.credentials.insert({ ...winner, authorityRef: randomUUID(), expiresAt: Date.now() + 60_000,
				additionalEnrollmentExpiresAt: Date.now() + 60_000,
				credential: { ...credential, id: randomBytes(32).toString("base64url") }, backupEligible: false, backupState: false });
			expect((await pool.query("SELECT credential_id FROM passkey_credentials WHERE identity_subject_id = $1", [winner.subjectId])).rows).toHaveLength(2);
			const expiredId = randomBytes(32).toString("base64url");
			await expect(t.credentials.insert({ ...winner, authorityRef: randomUUID(), expiresAt: Date.now() - 1,
				additionalEnrollmentExpiresAt: Date.now() + 60_000,
				credential: { ...credential, id: expiredId }, backupEligible: false, backupState: false }))
				.rejects.toThrow("authority expired");
			expect((await pool.query("SELECT credential_id FROM passkey_credentials WHERE credential_id = $1", [expiredId])).rows).toHaveLength(0);
		} finally { await t.close(); }
	}, 30_000);
});

describe("H6 Universal Login → existing PrivateID Face", () => {
	afterEach(() => { setFlag(undefined); vi.restoreAllMocks(); });

	async function faceApp() {
		ensureOidcTestEnvironment();
		setFlag(true);
		const { ensureBookwrmApplicationSeed } = await import("../src/adapters/base44/Base44ApplicationSeed.js");
		await ensureBookwrmApplicationSeed();
		const { inMemoryApplicationRepository } = await import("../src/identity/InMemoryApplicationRepository.js");
		const { BOOKWRM_APPLICATION_ID } = await import("../src/identity/WellKnownIdentities.js");
		const application = (await inMemoryApplicationRepository.findById(BOOKWRM_APPLICATION_ID))!;
		await inMemoryApplicationRepository.upsert({ ...application, allowedAuthenticationMethods: ["HAPI_EMAIL", "PRIVATEID_FACE"] });
		const { oidcService } = await import("../src/oidc/oidcServiceInstance.js");
		const { registerPrivateIdRoutes } = await import("../src/routes/privateid.js");
		const logs: string[] = [];
		const app = Fastify({ logger: { level: "info", stream: new Writable({ write(chunk, _enc, done) { logs.push(String(chunk)); done(); } }) } });
		await app.register(formbody);
		await registerPrivateIdRoutes(app);
		await oidcService.registerEndpoints(app);
		await app.ready();
		return { app, logs };
	}

	it("Face: authorization → Universal Login → PrivateID → canonical subject → callback → token; H5 never invoked", async () => {
		const h5Start = vi.spyOn(HapiFaceEnrollmentService.prototype, "start");
		const h5Webhook = vi.spyOn(HapiFaceEnrollmentService.prototype, "webhook");
		const h5Callback = vi.spyOn(HapiFaceEnrollmentService.prototype, "callback");
		const { app, logs } = await faceApp();
		try {
			const verifier = "ul-face-verifier-" + randomUUID();
			const query = new URLSearchParams({ response_type: "code", client_id: "base44-web", redirect_uri: "https://example.com/callback",
				scope: "openid profile email", state: "face-state-xyz", nonce: "face-nonce-abc",
				code_challenge_method: "S256", code_challenge: pkceChallengeFromVerifier(verifier) });
			const authorize = await app.inject({ method: "GET", url: `/authorize?${query}` });
			expect(authorize.statusCode, authorize.body).toBe(302);
			expect(authorize.headers.location).toBe("/login");
			const handle = cookieFrom(authorize)!;
			const chooser = await app.inject({ method: "GET", url: "/login", headers: { cookie: `${COOKIE}=${handle}` } });
			expect(chooser.body).toContain("Continue with Face");
			expect(chooser.body).not.toMatch(/enrol/i);
			const before = getCurrentPrivateIDSessionRecord()?.session.sessionId;

			const face = await app.inject({ method: "POST", url: "/login/face",
				payload: new URLSearchParams({ csrf: csrfFrom(chooser.body) }).toString(),
				headers: { "content-type": "application/x-www-form-urlencoded", cookie: `${COOKIE}=${handle}` } });
			expect(face.statusCode, face.body).toBe(302);
			expect(face.headers.location).toBeTruthy();
			expect(face.headers.location).not.toBe("/login");
			const cookies = setCookies(face);
			expect(cookies.find(value => value.startsWith(COOKIE))).toContain("Max-Age=0");
			expect(cookies.some(value => value.startsWith("hapi_privateid_oidc_return="))).toBe(true);
			const replay = await app.inject({ method: "POST", url: "/login/face",
				payload: new URLSearchParams({ csrf: csrfFrom(chooser.body) }).toString(),
				headers: { "content-type": "application/x-www-form-urlencoded", cookie: `${COOKIE}=${handle}` } });
			expect(replay.statusCode).toBe(400);

			const record = getCurrentPrivateIDSessionRecord()!;
			expect(record.session.sessionId).not.toBe(before);
			const puid = `puid-${randomUUID()}`;
			const email = `face-login-${randomUUID()}@bookwrm.local`;
			const user = await identityRegistry.resolveOrCreate({ provider: "HAPI_EMAIL", providerSubject: email,
				email, emailVerified: true });
			await inMemoryUserAuthenticatorRepository.create({ id: randomUUID(), userId: user.id, provider: "privateid",
				providerSubject: puid, authenticatorType: "face", status: "active" });
			const webhook = await app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", sessionId: record.session.sessionId, transactionId: record.session.transactionId, puid } });
			expect(webhook.statusCode, webhook.body).toBe(200);
			const callback = await app.inject({ method: "GET",
				url: `/privateid/callback?reason=success&sessionId=${encodeURIComponent(record.session.sessionId)}&transactionId=${encodeURIComponent(record.session.transactionId)}` });
			expect(callback.statusCode, callback.body).toBe(302);
			const redirect = new URL(callback.headers.location as string);
			expect(`${redirect.origin}${redirect.pathname}`).toBe("https://example.com/callback");
			expect(redirect.searchParams.get("state")).toBe("face-state-xyz");

			const token = await app.inject({ method: "POST", url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({ grant_type: "authorization_code", code: redirect.searchParams.get("code")!,
					redirect_uri: "https://example.com/callback", client_id: "base44-web", client_secret: "base44-secret", code_verifier: verifier }).toString() });
			expect(token.statusCode, token.body).toBe(200);
			const claims = decodeJwt(token.json().id_token);
			expect(claims).toMatchObject({ sub: user.oidcSubject, nonce: "face-nonce-abc", amr: ["face", "privateid"] });
			expect(typeof claims.auth_time).toBe("number");

			expect(h5Start).not.toHaveBeenCalled();
			expect(h5Webhook).not.toHaveBeenCalled();
			expect(h5Callback).not.toHaveBeenCalled();
			expect(configuration.getFeatureFlag("HAPI_FACE_ENROLLMENT_ENABLED", false)).toBe(false);
			// Privacy patch: raw PrivateID provider subjects (PUIDs) are never logged.
			const logged = logs.join("\n");
			expect(logged).not.toContain(puid);
			expect(logged).not.toContain(puid.slice(0, 8) + "...");
			expect(logged).toContain("providerSubjectPresent");
			expect(logged).toContain("resolvedUserIdPresent");
		} finally { await app.close(); }
	});
});

describe("H6.5B Universal Login safe lifecycle diagnostics", () => {
	afterEach(() => { setFlag(undefined); vi.restoreAllMocks(); });

	const SENSITIVE_MARKERS = (handle: string, csrf: string, email: string, code: string, state: string, nonce: string) =>
		[handle, csrf, email, code, state, nonce];

	it("logs COOKIE_MISSING with no cookie sent and no sensitive data", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const response = await f.app.inject({ method: "GET", url: "/login" });
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const loaded = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_LOADED");
			expect(loaded).toMatchObject({ reasonCode: "COOKIE_MISSING", cookiePresent: false, interactionFound: false, route: "GET /login" });
			expect(loaded!.correlationId).toBeUndefined();
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs INTERACTION_NOT_FOUND for a forged/unknown handle", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const forged = "F".repeat(43);
			const response = await f.app.inject({ method: "GET", url: "/login", headers: { cookie: `${COOKIE}=${forged}` } });
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const loaded = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_LOADED");
			expect(loaded).toMatchObject({ reasonCode: "INTERACTION_NOT_FOUND", cookiePresent: true, interactionFound: false });
			expect(loaded!.correlationId).toBe(diagnosticCorrelationId(forged));
			expect(f.logs.join("\n")).not.toContain(forged);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs INTERACTION_NOT_FOUND once the Redis-side PX TTL has physically elapsed (true wall-clock expiry)", async () => {
		// Our own logical expiresAt check in find()/inspect() and the Redis PX TTL are anchored to the
		// same 600s window and the same clock. Once wall-clock time truly advances past that window,
		// the Redis GET itself returns null (physical eviction) before our logical comparison ever runs,
		// so true TTL expiry surfaces as INTERACTION_NOT_FOUND with an "unknown" bucket -- not a
		// distinguishable INTERACTION_EXPIRED state. This is the real, observable production behavior.
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "x".repeat(43));
			const realNow = Date.now();
			vi.spyOn(Date, "now").mockReturnValue(realNow + AUTHORIZATION_INTERACTION_TTL_MS + 1);
			const response = await f.app.inject({ method: "GET", url: "/login", headers: interaction.cookie });
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const loaded = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_LOADED" && e.route === "GET /login" && e.interactionFound === false);
			expect(loaded).toMatchObject({ reasonCode: "INTERACTION_NOT_FOUND", cookiePresent: true, interactionFound: false, remainingTtlBucket: "unknown" });
			expect(loaded!.correlationId).toBe(diagnosticCorrelationId(interaction.handle));
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs INTERACTION_EXPIRED when our logical expiry fires ahead of Redis's own physical eviction", async () => {
		// Narrow edge case / clock-skew window: our expiresAt check can fire slightly before Redis's own
		// PX-based eviction (e.g. a request lands in the last millisecond of the TTL). We simulate that
		// here by stubbing find()'s result directly to isolate the branch without relying on Redis timing.
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "k".repeat(43));
			vi.spyOn(AuthorizationInteractionStore.prototype, "find").mockResolvedValueOnce(null);
			vi.spyOn(AuthorizationInteractionStore.prototype, "inspect").mockResolvedValueOnce({ state: "expired", remainingMs: -1 });
			const response = await f.app.inject({ method: "GET", url: "/login", headers: interaction.cookie });
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const loaded = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_LOADED" && e.reasonCode === "INTERACTION_EXPIRED");
			expect(loaded).toMatchObject({ reasonCode: "INTERACTION_EXPIRED", cookiePresent: true, interactionFound: false, remainingTtlBucket: "expired" });
			expect(loaded!.correlationId).toBe(diagnosticCorrelationId(interaction.handle));
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs CSRF_MISMATCH for a forged csrf token", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "y".repeat(43));
			const response = await f.app.inject({ method: "POST", url: "/login/email",
				payload: new URLSearchParams({ csrf: "forged-csrf", email: KNOWN_EMAIL }).toString(),
				headers: { ...form({}).headers, ...interaction.cookie } });
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const failed = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_FAILED" && e.reasonCode === "CSRF_MISMATCH");
			expect(failed).toMatchObject({ reasonCode: "CSRF_MISMATCH", csrfValid: false, route: "POST /login/email" });
			expect(f.logs.join("\n")).not.toContain("forged-csrf");
			expect(f.logs.join("\n")).not.toContain(interaction.csrf);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs AUTHORITY_INVALID when the bound application changes mid-flow", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "z".repeat(43));
			const record = (await f.h1.clients.findByClientId(CLIENT_ID))!;
			await f.h1.clients.upsert({ ...record, applicationId: randomUUID() });
			const response = await startEmail(f, interaction, KNOWN_EMAIL);
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const failed = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_FAILED" && e.reasonCode === "AUTHORITY_INVALID");
			expect(failed).toMatchObject({ reasonCode: "AUTHORITY_INVALID", authorityValid: false, route: "POST /login/email" });
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs CLIENT_INVALID when the registered redirect_uri is removed", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "r".repeat(43));
			f.oidcClient.redirect_uris = ["https://rp.example/other"];
			const response = await f.app.inject({ method: "POST", url: "/login/face",
				payload: new URLSearchParams({ csrf: interaction.csrf }).toString(), headers: { ...form({}).headers, ...interaction.cookie } });
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const failed = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_FAILED" && e.reasonCode === "CLIENT_INVALID");
			expect(failed).toMatchObject({ reasonCode: "CLIENT_INVALID", clientValid: false, route: "POST /login/face" });
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs INTERACTION_SAVE_FAILED when the interaction cannot be persisted mid-flow", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "s".repeat(43));
			vi.spyOn(AuthorizationInteractionStore.prototype, "save").mockResolvedValueOnce(false);
			const response = await startEmail(f, interaction, KNOWN_EMAIL);
			expect(response.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			const failed = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_FAILED" && e.reasonCode === "INTERACTION_SAVE_FAILED");
			expect(failed).toMatchObject({ reasonCode: "INTERACTION_SAVE_FAILED", authorityValid: true, route: "POST /login/email" });
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("logs INTERACTION_ALREADY_CONSUMED on replay after a successful completion", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const interaction = await beginInteraction(f, "q".repeat(43));
			await startEmail(f, interaction, KNOWN_EMAIL);
			const done = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(done.statusCode).toBe(303);
			const replay = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(replay.statusCode).toBe(400);
			const events = diagnosticEvents(f.logs);
			expect(events.some(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_CONSUMED")).toBe(true);
			expect(events.some(e => e.event === "UNIVERSAL_LOGIN_OIDC_REDIRECT_ISSUED")).toBe(true);
			// The replay's own load() call detects the consumed marker (the main key is already
			// deleted by consume()), so it surfaces on the LOADED event rather than a route-specific FAILED one.
			const replayed = events.find(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_LOADED" && e.reasonCode === "INTERACTION_ALREADY_CONSUMED");
			expect(replayed).toBeDefined();
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("correlates events for the same interaction and distinguishes different interactions", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const a = await beginInteraction(f, "a".repeat(43));
			const b = await beginInteraction(f, "b".repeat(43));
			await f.app.inject({ method: "GET", url: "/login", headers: a.cookie });
			await f.app.inject({ method: "GET", url: "/login", headers: b.cookie });
			const events = diagnosticEvents(f.logs).filter(e => e.event === "UNIVERSAL_LOGIN_INTERACTION_LOADED" && e.interactionFound === true);
			const idsForA = new Set(events.filter(e => e.correlationId === diagnosticCorrelationId(a.handle)).map(e => e.correlationId));
			const idsForB = new Set(events.filter(e => e.correlationId === diagnosticCorrelationId(b.handle)).map(e => e.correlationId));
			expect(idsForA.size).toBe(1);
			expect(idsForB.size).toBe(1);
			expect([...idsForA][0]).not.toBe([...idsForB][0]);
			expect([...idsForA][0]).toMatch(/^[0-9a-f]{16}$/);
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});

	it("never logs the raw handle, cookie, csrf, email, OTP, state/nonce/PKCE, or tokens across a full successful flow", async () => {
		setFlag(true);
		const f = await emailFixture();
		try {
			const verifier = "diag-privacy-verifier-" + randomUUID();
			const interaction = await beginInteraction(f, verifier);
			await startEmail(f, interaction, KNOWN_EMAIL);
			const done = await submitCode(f, interaction, f.delivery.messages[0].code);
			expect(done.statusCode).toBe(303);
			const callback = new URL(done.headers.location as string);
			const code = callback.searchParams.get("code")!;
			const token = await f.app.inject({ method: "POST", url: "/token", headers: f.basic,
				payload: { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier } });
			expect(token.statusCode).toBe(200);
			const idToken = token.json().id_token as string;
			const accessToken = token.json().access_token as string;

			const events = diagnosticEvents(f.logs);
			expect(events.length).toBeGreaterThan(0);
			// state/nonce are part of the GET /authorize querystring and are captured by Fastify's own
			// default "incoming request" access logging regardless of this diagnostics feature; that
			// pre-existing behavior is out of scope here. What H6.5B must guarantee is that the new
			// diagnostic event stream never carries any of these values, which we check explicitly below.
			const diagnosticText = JSON.stringify(events);
			for (const sensitive of [interaction.handle, interaction.csrf, KNOWN_EMAIL, f.delivery.messages[0].code,
				"ul-state-Ω+/=&", "ul-nonce-123", verifier, code, idToken, accessToken, CLIENT_SECRET]) {
				expect(diagnosticText).not.toContain(sensitive);
			}
			const logged = f.logs.join("\n");
			for (const sensitive of [interaction.handle, interaction.csrf, KNOWN_EMAIL, f.delivery.messages[0].code,
				verifier, code, idToken, accessToken, CLIENT_SECRET]) {
				expect(logged).not.toContain(sensitive);
			}
		} finally { f.lookup.mockRestore(); await f.app.close(); }
	});
});
