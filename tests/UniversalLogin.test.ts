import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from "fastify";
import formbody from "@fastify/formbody";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { configuration } from "../src/config/ConfigurationService.js";
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
import { getRedisClient } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import { ensureOidcTestEnvironment, pkceChallengeFromVerifier } from "./oidcTestHarness.js";
import { diagnosticCorrelationId } from "../src/oidc/UniversalLoginDiagnostics.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { InMemoryRegistrationRepository } from "../src/registration/InMemoryRegistrationRepository.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";

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

async function emailFixture(options: { emailInteractive?: boolean } = {}) {
	ensureOidcTestEnvironment();
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const tenants = new InMemoryTenantRepository();
	const applications = new InMemoryApplicationRepository();
	const clients = new InMemoryOIDCClientRepository();
	await tenants.upsert({ id: tenantId, name: "Bookwrm", slug: `bookwrm-${tenantId}`, status: "active" });
	await applications.upsert({ id: applicationId, tenantId, name: "Bookwrm Web", slug: "web", status: "active" });
	await clients.upsert({ id: randomUUID(), applicationId, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
		redirectUris: [REDIRECT], scopes: ["openid", "profile", "email"], grantTypes: ["authorization_code"],
		responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
	const h1 = { clients, applications, tenants };
	const oidcClient: OIDCClient = { client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uris: [REDIRECT],
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
		primaryProvider: "HAPI_EMAIL", primaryProviderSubject: KNOWN_EMAIL, email: KNOWN_EMAIL,
		emailVerified: true, status: "ACTIVE" });
	const results = new Map<string, EmailPrincipal & { context: string }>();
	const created: string[] = [];
	const repository: EmailAuthenticationRepository = {
		audit: vi.fn(async () => {}),
		establish: vi.fn(async (authority, challengeId) => {
			const challenge = await challenges.findById(challengeId);
			if (challenge?.destinationNormalized.toLowerCase() !== KNOWN_EMAIL) throw new EmailAuthenticationError();
			const authenticatedAt = new Date(now).toISOString();
			const authenticationResult = randomBytes(32).toString("base64url");
			results.set(authenticationResult, { id: subject.id, sub: subject.oidcSubject, email: KNOWN_EMAIL, emailVerified: true,
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
	const oidc = new OIDCService({ authenticationProvider: provider, clients: [oidcClient], oidcClients: clients });
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
	const app = Fastify({ logger: { level: "info", stream: new Writable({ write(chunk, _enc, done) { logs.push(String(chunk)); done(); } }) } });
	await app.register(formbody);
	await oidc.registerEndpoints(app);
	await app.ready();
	const lookup = vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
	const basic = { authorization: "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64") };
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
});

describe("H6 Universal Login", () => {
	afterEach(() => { setFlag(undefined); vi.restoreAllMocks(); });

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
			expect(codeForm.body).not.toMatch(/register|existing account|new account|H2|H3|H4|IdentitySubject/i);

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
			const publicPage = (html: string) => html.replace(/nonce="[^"]+"/g, 'nonce=""')
				.replace(/name="csrf" value="[^"]+"/g, 'name="csrf" value=""');
			expect(publicPage(codePages[0].body)).toBe(publicPage(codePages[1].body));
			expect(publicPage(codePages[1].body)).toBe(publicPage(codePages[2].body));
			expect(codePages[0].body).not.toMatch(/register|existing account|new account|H2|H3|H4|IdentitySubject/i);

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

describe("H6 Universal Login → existing PrivateID Face", () => {
	afterEach(() => { setFlag(undefined); vi.restoreAllMocks(); });

	async function faceApp() {
		ensureOidcTestEnvironment();
		setFlag(true);
		const { ensureBookwrmApplicationSeed } = await import("../src/adapters/base44/Base44ApplicationSeed.js");
		await ensureBookwrmApplicationSeed();
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
			const user = await identityRegistry.resolveOrCreate({ provider: "PrivateID", providerSubject: `seed-${randomUUID()}`,
				email: "dev.user@bookwrm.local", emailVerified: true });
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
