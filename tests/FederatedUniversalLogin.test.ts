import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";
import { randomBytes, randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from "fastify";
import formbody from "@fastify/formbody";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { OIDCService, type OIDCClient } from "../src/oidc/OIDCService.js";
import type { AuthenticationProvider, PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { InMemoryExternalIdentityRepository } from "../src/identity/InMemoryExternalIdentityRepository.js";
import { IdentityFederationService } from "../src/identity/IdentityFederationService.js";
import { identityRegistry, IdentityRegistry } from "../src/identity/IdentityRegistry.js";
import { AppleIdentityTokenVerifier, APPLE_ISSUER } from "../src/identity/federation/AppleIdentityTokenVerifier.js";
import { GoogleIdentityTokenVerifier, GOOGLE_ISSUER } from "../src/identity/federation/GoogleIdentityTokenVerifier.js";
import {
		APPLE_AUTHORIZATION_ENDPOINT,
		APPLE_TOKEN_ENDPOINT,
		FederatedAuthorizationService,
		GOOGLE_AUTHORIZATION_ENDPOINT,
		GOOGLE_TOKEN_ENDPOINT,
		HttpAuthorizationCodeExchanger,
		type AuthorizationCodeExchanger
} from "../src/identity/federation/FederatedAuthorizationService.js";
import { FederationTransactionStore } from "../src/identity/federation/FederationTransactionStore.js";
import { FederatedIdentityResolutionService } from "../src/identity/federation/FederatedIdentityResolutionService.js";
import { HapiSessionService, HAPI_SESSION_COOKIE, hashSessionToken } from "../src/identity/sessions/HapiSessionService.js";
import { InMemoryHapiSessionRepository } from "../src/identity/sessions/InMemoryHapiSessionRepository.js";
import type { AuthenticationMethod } from "../src/models/Application.js";
import { ensureOidcTestEnvironment, pkceChallengeFromVerifier } from "./oidcTestHarness.js";
import { serializeRequestForLog } from "../src/security/RequestLogging.js";
import { AuthorizationInteractionStore } from "../src/oidc/AuthorizationInteractionStore.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { InMemoryVerificationChallengeRepository } from "../src/email/InMemoryVerificationChallengeRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import { EmailAuthenticationError, type EmailAuthenticationRepository, type EmailPrincipal } from "../src/authentication/email/EmailAuthenticationTypes.js";
import { interactiveEmailAuthentication } from "../src/adapters/email/EmailVerificationComposition.js";
import { InMemoryRegistrationRepository } from "../src/registration/InMemoryRegistrationRepository.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";
import { getRedisClient, oidcRedisKey } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import pg from "pg";
import { PostgresExternalIdentityRepository } from "../src/identity/PostgresExternalIdentityRepository.js";

// HAPI ID V2-D Phases 4/6: HAPI-hosted Apple/Google Universal Login certification. Every provider
// artifact (keys, codes, tokens, endpoints) is synthetic; no live provider is ever contacted.

const REDIRECT = "https://rp.example/callback";
const CLIENT_ID = "fed-client";
const CLIENT_SECRET = "fed-client-secret";
const COOKIE = "__Host-hapi_login";
const APPLE_CLIENT = "com.hapi.id.synthetic";
const GOOGLE_CLIENT = "synthetic.apps.googleusercontent.com";
const APPLE_CALLBACK = "https://id.example.test/federation/apple/callback";
const GOOGLE_CALLBACK = "https://id.example.test/federation/google/callback";

let appleKey: CryptoKey | import("node:crypto").KeyObject;
let appleJwks: JSONWebKeySet;
let googleKey: CryptoKey | import("node:crypto").KeyObject;
let googleJwks: JSONWebKeySet;

beforeAll(async () => {
	const apple = await generateKeyPair("RS256");
	appleKey = apple.privateKey;
	appleJwks = { keys: [{ ...(await exportJWK(apple.publicKey)), kid: "a1", alg: "RS256", use: "sig" }] };
	const google = await generateKeyPair("RS256");
	googleKey = google.privateKey;
	googleJwks = { keys: [{ ...(await exportJWK(google.publicKey)), kid: "g1", alg: "RS256", use: "sig" }] };
});

function setFlags(flags: Record<string, boolean | undefined>): void {
	for (const [key, value] of Object.entries(flags)) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = String(value);
	}
	configuration.reload();
}

const DEFAULT_FLAGS = {
	HAPI_UNIVERSAL_LOGIN_ENABLED: true,
	HAPI_APPLE_FEDERATION_ENABLED: true,
	HAPI_GOOGLE_FEDERATION_ENABLED: true
};

function cookieFrom(response: LightMyRequestResponse, name = COOKIE): string | undefined {
	const header = response.headers["set-cookie"];
	const cookies = Array.isArray(header) ? header : header ? [header] : [];
	return cookies.find(value => value.startsWith(`${name}=`))?.split(";")[0].slice(name.length + 1) || undefined;
}

function csrfFrom(html: string): string {
	const match = /name="csrf" value="([^"]+)"/.exec(html);
	if (!match) throw new Error("csrf field missing");
	return match[1];
}

function form(payload: Record<string, string>, cookie?: string): { headers: Record<string, string>; payload: string } {
	return {
		headers: { "content-type": "application/x-www-form-urlencoded", ...(cookie ? { cookie } : {}) },
		payload: new URLSearchParams(payload).toString()
	};
}

type ProviderIdentity = { sub: string; email?: string; emailVerified?: unknown; isPrivateEmail?: unknown };

async function federatedFixture(options: {
	allowExternal?: boolean;
	flags?: Record<string, boolean | undefined>;
	appleClientSecret?: () => Promise<string>;
	appleExchanger?: AuthorizationCodeExchanger;
} = {}) {
	ensureOidcTestEnvironment();
	setFlags({ ...DEFAULT_FLAGS, ...(options.flags ?? {}) });
	await getRedisClient().del(oidcRedisKey("ratelimit:ip:127.0.0.1"), oidcRedisKey(`ratelimit:client:${CLIENT_ID}`));

	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const tenants = new InMemoryTenantRepository();
	const applications = new InMemoryApplicationRepository();
	const clients = new InMemoryOIDCClientRepository();
	const allowed: AuthenticationMethod[] = options.allowExternal === false
		? ["HAPI_EMAIL", "PRIVATEID_FACE"] : ["HAPI_EMAIL", "EXTERNAL_OIDC", "PRIVATEID_FACE"];
	await tenants.upsert({ id: tenantId, name: "Bookwrm", slug: `bookwrm-${tenantId}`, status: "active" });
	await applications.upsert({ id: applicationId, tenantId, name: "Bookwrm Web", slug: "web", status: "active",
		allowedAuthenticationMethods: allowed });
	await clients.upsert({ id: randomUUID(), applicationId, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
		redirectUris: [REDIRECT], scopes: ["openid", "profile", "email"], grantTypes: ["authorization_code"],
		responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
	const h1 = { clients, applications, tenants };
	const oidcClient: OIDCClient = { client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uris: [REDIRECT],
		scope: "openid profile email", grant_types: ["authorization_code"], response_types: ["code"],
		token_endpoint_auth_method: "client_secret_basic", require_pkce: true };

	// Authoritative in-memory identity registry shared by federation resolution and /token claims.
	const subjects = new InMemoryIdentitySubjectRepository();
	const registry = new IdentityRegistry(subjects);
	const externalRepository = new InMemoryExternalIdentityRepository(async (id) => subjects.findById(id));
	const federation = new IdentityFederationService(externalRepository);
	const resolution = new FederatedIdentityResolutionService(federation, registry);
	const transactions = new FederationTransactionStore();
	const sessionRepository = new InMemoryHapiSessionRepository();
	const sessions = new HapiSessionService(sessionRepository);

	// Synthetic providers: authorization codes registered by the test, id_tokens minted on exchange.
	const identities: Record<"APPLE" | "GOOGLE", ProviderIdentity> = {
		APPLE: { sub: "001234.synthetic.5678", email: "apple-user@example.com", emailVerified: "true" },
		GOOGLE: { sub: "110000000000000000001", email: "google-user@example.com", emailVerified: true }
	};
	const codes = new Map<string, { provider: "APPLE" | "GOOGLE"; nonce: string }>();
	const mintProviderToken = async (provider: "APPLE" | "GOOGLE", nonce: string) => {
		const identity = identities[provider];
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({ sub: identity.sub, nonce,
			...(identity.email !== undefined ? { email: identity.email } : {}),
			...(identity.emailVerified !== undefined ? { email_verified: identity.emailVerified } : {}),
			...(identity.isPrivateEmail !== undefined ? { is_private_email: identity.isPrivateEmail } : {}) })
			.setProtectedHeader({ alg: "RS256", kid: provider === "APPLE" ? "a1" : "g1" })
			.setIssuer(provider === "APPLE" ? APPLE_ISSUER : GOOGLE_ISSUER)
			.setAudience(provider === "APPLE" ? APPLE_CLIENT : GOOGLE_CLIENT)
			.setIssuedAt(now).setExpirationTime(now + 600)
			.sign(provider === "APPLE" ? appleKey : googleKey);
	};
	const exchanger = (provider: "APPLE" | "GOOGLE"): AuthorizationCodeExchanger => ({
		async exchange(_endpoint, params) {
			const redeemed = codes.get(params.get("code") ?? "");
			if (!redeemed || redeemed.provider !== provider) throw new Error("invalid_grant");
			codes.delete(params.get("code") ?? "");
			return { idToken: await mintProviderToken(provider, redeemed.nonce) };
		}
	});
	const apple = new FederatedAuthorizationService(
		{ provider: "APPLE", clientId: APPLE_CLIENT, redirectUri: APPLE_CALLBACK, scope: "name email",
			authorizationEndpoint: APPLE_AUTHORIZATION_ENDPOINT, tokenEndpoint: APPLE_TOKEN_ENDPOINT,
			responseMode: "form_post", clientSecret: options.appleClientSecret ?? (async () => "synthetic-apple-secret") },
		new AppleIdentityTokenVerifier({ expectedAudiences: [APPLE_CLIENT], jwks: appleJwks }),
		transactions, options.appleExchanger ?? exchanger("APPLE"));
	const google = new FederatedAuthorizationService(
		{ provider: "GOOGLE", clientId: GOOGLE_CLIENT, redirectUri: GOOGLE_CALLBACK, scope: "openid email profile",
			authorizationEndpoint: GOOGLE_AUTHORIZATION_ENDPOINT, tokenEndpoint: GOOGLE_TOKEN_ENDPOINT,
			clientSecret: async () => "synthetic-google-secret" },
		new GoogleIdentityTokenVerifier({ expectedAudiences: [GOOGLE_CLIENT], jwks: googleJwks }),
		transactions, exchanger("GOOGLE"));

	const provider: AuthenticationProvider = {
		authenticate: vi.fn(async () => { throw new Error("must not authenticate synchronously"); }),
		cancel: vi.fn(async () => {}), status: vi.fn(async () => ({ state: "idle" as const })), logout: vi.fn(async () => {}),
		setPendingAuthorizationContext: vi.fn((_context: PendingAuthorizationContext) => {}),
		beginAsyncAuthentication: vi.fn(async (correlationId: string) => ({
			sessionId: `face-${correlationId}`, launchUrl: "https://privateid.example.com/launch" }))
	} as unknown as AuthenticationProvider;
	const oidc = new OIDCService({ authenticationProvider: provider, clients: [oidcClient], oidcClients: clients,
		clientAuthority: h1, federation: { apple, google, transactions, resolution, sessions } });
	const logs: string[] = [];
	const app = Fastify({ logger: { level: "info",
		stream: new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }),
		serializers: { req: serializeRequestForLog } } });
	await app.register(formbody);
	await oidc.registerEndpoints(app);
	await app.ready();

	// /token and session continuation consult the global registry singleton; route them to this
	// fixture's subjects store.
	vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
	vi.spyOn(identityRegistry, "findById").mockImplementation(id => subjects.findById(id));

	return { app, oidc, h1, subjects, registry, federation, externalRepository, transactions, sessions, sessionRepository,
		identities, codes, tenantId, applicationId, logs };
}

type Fixture = Awaited<ReturnType<typeof federatedFixture>>;

async function enableEmail(f: Fixture) {
	const email = "existing@example.test";
	const subject = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId: f.applicationId,
		primaryProvider: "HAPI_EMAIL", primaryProviderSubject: email, email, emailVerified: true, status: "ACTIVE" });
	const challenges = new InMemoryVerificationChallengeRepository();
	const delivery = new InMemoryEmailDeliveryProvider();
	const verification = new EmailVerificationService(challenges, delivery,
		new VerificationSecrets("synthetic-secret".repeat(4)), defaultVerificationPolicy);
	const results = new Map<string, EmailPrincipal>();
	const repository: EmailAuthenticationRepository = {
		audit: async () => {},
		async establish(_authority, challengeId) {
			const challenge = await challenges.findById(challengeId);
			if (challenge?.destinationNormalized !== email) throw new EmailAuthenticationError();
			const authenticatedAt = new Date().toISOString();
			const authenticationResult = randomBytes(32).toString("base64url");
			results.set(authenticationResult, { id: subject.id, sub: subject.oidcSubject, email, emailVerified: true,
				authenticationMethod: "HAPI_EMAIL", authenticatedAt, assurance: "email_otp" });
			return { authenticated: true, subject: subject.oidcSubject, authenticationResult, expiresIn: 60,
				authenticationMethod: "HAPI_EMAIL", authenticatedAt, assurance: "email_otp" };
		},
		async consumeResult(_authority, result) {
			const principal = results.get(result);
			results.delete(result);
			if (!principal) throw new EmailAuthenticationError();
			return principal;
		}
	};
	const authentication = new EmailAuthenticationService(verification, challenges, repository);
	const registration = new RegistrationService(new InMemoryRegistrationRepository(challenges, f.subjects));
	const interactive = interactiveEmailAuthentication(authentication, f.h1, {
		verification, challenges, registration, subjects: f.registry
	});
	f.oidc.configureEmailAuthentication({
		interactive,
		consume: async () => { throw new Error("unexpected legacy email flow"); }
	});
	return { email, subject, delivery, interactive };
}

async function chooseAppleEmail(f: Fixture, interaction: Awaited<ReturnType<typeof beginInteraction>>) {
	const { state, code } = await launchProvider(f, interaction, "APPLE");
	const choice = await appleCallback(f, { state, code });
	expect(choice.statusCode).toBe(200);
	expect(choice.body).toContain("Finish setting up your account");
	expect(choice.body).toContain("confirm that you want to connect Apple");
	const selected = await f.app.inject({ method: "POST", url: "/login/federated/complete",
		...form({ csrf: interaction.csrf, choice: "email" }, interaction.cookie) });
	expect(selected.statusCode).toBe(303);
}

async function startLinkEmail(f: Fixture, interaction: Awaited<ReturnType<typeof beginInteraction>>, email: string) {
	return f.app.inject({ method: "POST", url: "/login/email",
		...form({ csrf: interaction.csrf, email }, interaction.cookie) });
}

async function submitLinkCode(f: Fixture, interaction: Awaited<ReturnType<typeof beginInteraction>>,
	code: string, consent = true) {
	return f.app.inject({ method: "POST", url: "/login/email/code",
		...form({ csrf: interaction.csrf, code, ...(consent ? { connect_apple: "yes" } : {}) }, interaction.cookie) });
}

async function beginInteraction(f: Pick<Fixture, "app">, verifier: string, extraCookies = "") {
	const query = new URLSearchParams({
		response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT,
		scope: "openid profile email", state: "rp-state", nonce: "rp-nonce",
		code_challenge_method: "S256", code_challenge: pkceChallengeFromVerifier(verifier)
	}).toString();
	const authorize = await f.app.inject({ method: "GET", url: `/authorize?${query}` });
	expect(authorize.statusCode, authorize.body).toBe(302);
	const handle = cookieFrom(authorize)!;
	const cookie = `${COOKIE}=${handle}${extraCookies}`;
	const chooser = await f.app.inject({ method: "GET", url: "/login", headers: { cookie } });
	expect(chooser.statusCode).toBe(200);
	return { handle, cookie, chooser, csrf: csrfFrom(chooser.body) };
}

// Launches the provider flow and returns the redirect URL + a registered synthetic code.
async function launchProvider(f: Fixture, interaction: Awaited<ReturnType<typeof beginInteraction>>,
	provider: "APPLE" | "GOOGLE") {
	const started = await f.app.inject({ method: "POST", url: `/login/federated/${provider.toLowerCase()}`,
		...form({ csrf: interaction.csrf }, interaction.cookie) });
	expect(started.statusCode, started.body).toBe(303);
	const url = new URL(started.headers.location as string);
	const state = url.searchParams.get("state")!;
	const nonce = url.searchParams.get("nonce")!;
	const code = `provider-code-${randomUUID()}`;
	f.codes.set(code, { provider, nonce });
	return { url, state, nonce, code };
}

async function appleCallback(f: Fixture, params: Record<string, string>) {
	// Apple form_post arrives WITHOUT cookies (cross-site POST): no cookie header on purpose.
	return f.app.inject({ method: "POST", url: "/federation/apple/callback", ...form(params) });
}

async function exchangeCode(f: Fixture, location: string, verifier: string) {
	const code = new URL(location).searchParams.get("code")!;
	return f.app.inject({ method: "POST", url: "/token",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		payload: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT,
			client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: verifier }).toString() });
}

function decodeJwt(token: string): Record<string, unknown> {
	return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")) as Record<string, unknown>;
}

afterEach(() => {
	setFlags({ HAPI_UNIVERSAL_LOGIN_ENABLED: undefined, HAPI_APPLE_FEDERATION_ENABLED: undefined,
		HAPI_GOOGLE_FEDERATION_ENABLED: undefined, HAPI_PERSISTENT_SESSIONS_ENABLED: undefined });
	vi.restoreAllMocks();
});

describe("V2-D federated Universal Login (synthetic providers)", () => {
	it("links Apple only after email OTP and explicit consent, and returns the same subject on later Apple login", async () => {
		const f = await federatedFixture();
		const email = await enableEmail(f);
		const verifier = "verifier-apple-existing";
		const interaction = await beginInteraction(f, verifier);
		await chooseAppleEmail(f, interaction);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(0);
		expect((await startLinkEmail(f, interaction, email.email)).statusCode).toBe(303);
		const page = await f.app.inject({ method: "GET", url: "/login/email/code", headers: { cookie: interaction.cookie } });
		expect(page.body).toContain("I authorize connecting this Apple sign-in");
		const missing = await submitLinkCode(f, interaction, email.delivery.messages[0].code, false);
		expect(missing.statusCode).toBe(400);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(0);
		const completed = await submitLinkCode(f, interaction, email.delivery.messages[0].code);
		expect(completed.statusCode).toBe(303);
		const token = await exchangeCode(f, completed.headers.location as string, verifier);
		expect(token.statusCode).toBe(200);
		expect(decodeJwt(token.json().id_token).sub).toBe(email.subject.oidcSubject);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toMatchObject([{
			provider: "APPLE", providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub, status: "linked"
		}]);
		expect((await submitLinkCode(f, interaction, email.delivery.messages[0].code)).statusCode).toBe(400);
		const returning = await beginInteraction(f, "verifier-apple-return");
		const next = await launchProvider(f, returning, "APPLE");
		const callback = await appleCallback(f, { state: next.state, code: next.code });
		expect(callback.statusCode).toBe(303);
		expect(callback.body).not.toContain("Finish setting up your account");
		const repeat = await exchangeCode(f, callback.headers.location as string, "verifier-apple-return");
		expect(repeat.statusCode).toBe(200);
		expect(decodeJwt(repeat.json().id_token).sub).toBe(email.subject.oidcSubject);
		expect(email.delivery.messages).toHaveLength(1);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(1);
	});

	it("rejects bad OTP and does not create an account for an unknown email", async () => {
		const f = await federatedFixture();
		const email = await enableEmail(f);
		const interaction = await beginInteraction(f, "verifier-bad-otp");
		await chooseAppleEmail(f, interaction);
		await startLinkEmail(f, interaction, email.email);
		const wrongCode = email.delivery.messages[0].code === "000000" ? "999999" : "000000";
		expect((await submitLinkCode(f, interaction, wrongCode)).statusCode).toBe(401);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(0);

		const unknown = await beginInteraction(f, "verifier-unknown-email");
		await chooseAppleEmail(f, unknown);
		await startLinkEmail(f, unknown, "unknown@example.test");
		expect(email.delivery.messages.at(-1)?.purpose).toBe("AUTHENTICATION");
		expect((await submitLinkCode(f, unknown, email.delivery.messages.at(-1)!.code)).statusCode).toBe(401);
		expect(await f.registry.findByProvider("HAPI_EMAIL", "unknown@example.test")).toBeUndefined();
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(0);
	});

	it("rejects a conflicting binding and never reports success on a database failure", async () => {
		for (const scenario of ["conflict", "failure"] as const) {
			const f = await federatedFixture();
			const email = await enableEmail(f);
			const interaction = await beginInteraction(f, `verifier-${scenario}`);
			await chooseAppleEmail(f, interaction);
			await startLinkEmail(f, interaction, email.email);
			if (scenario === "conflict") {
				const other = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
					primaryProvider: "PrivateID", primaryProviderSubject: randomUUID(), status: "ACTIVE" });
				await f.federation.linkExternalIdentity({ identitySubjectId: other.id, provider: "APPLE",
					providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });
			} else {
				vi.spyOn(f.externalRepository, "link").mockRejectedValue(new Error("synthetic database failure"));
			}
			const result = await submitLinkCode(f, interaction, email.delivery.messages[0].code);
			expect(result.statusCode).toBe(scenario === "conflict" ? 409 : 503);
			expect(result.headers.location).toBeUndefined();
			expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(0);
			expect((await submitLinkCode(f, interaction, email.delivery.messages[0].code)).statusCode).toBe(400);
		}
	});

	it("accepts an identical binding committed by the same subject during verification without duplicating it", async () => {
		const f = await federatedFixture();
		const email = await enableEmail(f);
		const interaction = await beginInteraction(f, "verifier-idempotent-link");
		await chooseAppleEmail(f, interaction);
		await startLinkEmail(f, interaction, email.email);
		await f.federation.linkExternalIdentity({ identitySubjectId: email.subject.id, provider: "APPLE",
			providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });
		expect((await submitLinkCode(f, interaction, email.delivery.messages[0].code)).statusCode).toBe(303);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(1);
	});

	it.each(["commit", "rollback"] as const)("waits for PostgreSQL %s before responding", async outcome => {
		const f = await federatedFixture();
		const email = await enableEmail(f);
		const interaction = await beginInteraction(f, `verifier-transaction-${outcome}`);
		await chooseAppleEmail(f, interaction);
		await startLinkEmail(f, interaction, email.email);
		const pool = new pg.Pool();
		const client = Object.assign(new pg.Client(), { release: vi.fn() });
		const statements: string[] = [];
		let commitStarted!: () => void;
		const atCommit = new Promise<void>(resolve => { commitStarted = resolve; });
		let finishCommit!: () => void;
		const commitGate = new Promise<void>(resolve => { finishCommit = resolve; });
		vi.spyOn(pool, "connect").mockResolvedValue(client);
		vi.spyOn(client, "query").mockImplementation(async (text, values) => {
			if (typeof text !== "string") throw new Error("unexpected query");
			const statement = text.trim();
			statements.push(statement);
			if (statement === "COMMIT") {
				commitStarted();
				await commitGate;
				if (outcome === "rollback") throw new Error("synthetic commit failure");
			}
			if (statement.includes("FROM identity_subjects")) {
				return { rows: [{ id: email.subject.id, status: "ACTIVE", primary_provider: "HAPI_EMAIL", email_verified: true }] };
			}
			if (statement.startsWith("INSERT INTO external_identities")) {
				const now = new Date();
				return { rows: [{ id: values![0], identity_subject_id: values![1], provider: values![2],
					provider_issuer: values![3], provider_subject: values![4], provider_client_context: values![5],
					status: "linked", linked_at: now, revoked_at: null, last_authenticated_at: null, created_at: now, updated_at: now }] };
			}
			return { rows: [] };
		});
		const postgres = new PostgresExternalIdentityRepository(pool);
		vi.spyOn(f.externalRepository, "link").mockImplementation(command => postgres.link(command));
		let responded = false;
		const response = submitLinkCode(f, interaction, email.delivery.messages[0].code).then(result => {
			responded = true;
			return result;
		});
		await atCommit;
		expect(responded).toBe(false);
		expect(statements.some(sql => sql.startsWith("INSERT INTO identity_authentication_methods"))).toBe(true);
		expect(statements.some(sql => sql.startsWith("INSERT INTO identity_link_audit"))).toBe(true);
		finishCommit();
		const result = await response;
		expect(result.statusCode).toBe(outcome === "commit" ? 303 : 503);
		expect(statements.includes("ROLLBACK")).toBe(outcome === "rollback");
		expect(client.release).toHaveBeenCalledOnce();
		await pool.end();
	});

	it("rejects forged CSRF, expired interactions and creation after choosing an existing account", async () => {
		const f = await federatedFixture();
		const email = await enableEmail(f);
		const interaction = await beginInteraction(f, "verifier-expired-link");
		await chooseAppleEmail(f, interaction);
		const forged = await f.app.inject({ method: "POST", url: "/login/email",
			...form({ csrf: "forged", email: email.email }, interaction.cookie) });
		expect(forged.statusCode).toBe(400);
		const create = await f.app.inject({ method: "POST", url: "/login/federated/complete",
			...form({ csrf: interaction.csrf, choice: "create" }, interaction.cookie) });
		expect(create.statusCode).toBe(400);
		await startLinkEmail(f, interaction, email.email);
		const store = new AuthorizationInteractionStore();
		const saved = await store.find(interaction.handle);
		expect(saved).not.toBeNull();
		vi.spyOn(Date, "now").mockReturnValue(saved!.expiresAt + 1);
		expect((await submitLinkCode(f, interaction, email.delivery.messages[0].code)).statusCode).toBe(400);
		expect(await f.federation.listExternalIdentities(email.subject.id)).toHaveLength(0);
	});

	it("keeps federation invisible and inert while the default-off flags are off", async () => {
		const f = await federatedFixture({ flags: {
			HAPI_APPLE_FEDERATION_ENABLED: undefined, HAPI_GOOGLE_FEDERATION_ENABLED: undefined } });
		const interaction = await beginInteraction(f, "verifier-flags-off");
		expect(interaction.chooser.body).not.toContain("Continue with Apple");
		expect(interaction.chooser.body).not.toContain("Continue with Google");
		const started = await f.app.inject({ method: "POST", url: "/login/federated/apple",
			...form({ csrf: interaction.csrf }, interaction.cookie) });
		expect(started.statusCode).toBe(404);
		const callback = await appleCallback(f, { state: "F".repeat(43), code: "x" });
		expect(callback.statusCode).toBe(404);
	});

	it("offers Apple and Google only when the application allows EXTERNAL_OIDC", async () => {
		const f = await federatedFixture();
		const interaction = await beginInteraction(f, "verifier-buttons");
		expect(interaction.chooser.body).toContain("Continue with Apple");
		expect(interaction.chooser.body).toContain("Continue with Google");

		const restricted = await federatedFixture({ allowExternal: false });
		const restrictedInteraction = await beginInteraction(restricted, "verifier-restricted");
		expect(restrictedInteraction.chooser.body).not.toContain("Continue with Apple");
		const started = await restricted.app.inject({ method: "POST", url: "/login/federated/apple",
			...form({ csrf: restrictedInteraction.csrf }, restrictedInteraction.cookie) });
		expect(started.statusCode).toBe(403);
	});

	it("launches Apple with exact registered values, form_post, and server-generated state/nonce", async () => {
		const f = await federatedFixture();
		const interaction = await beginInteraction(f, "verifier-launch");
		const { url, state, nonce } = await launchProvider(f, interaction, "APPLE");
		expect(`${url.origin}${url.pathname}`).toBe(APPLE_AUTHORIZATION_ENDPOINT);
		expect(url.searchParams.get("client_id")).toBe(APPLE_CLIENT);
		expect(url.searchParams.get("redirect_uri")).toBe(APPLE_CALLBACK);
		expect(url.searchParams.get("response_mode")).toBe("form_post");
		expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
		// CSRF protection on the launch itself.
		const forged = await f.app.inject({ method: "POST", url: "/login/federated/apple",
			...form({ csrf: "forged" }, interaction.cookie) });
		expect(forged.statusCode).toBe(400);
	});

	it("signs in a returning linked Apple identity end-to-end with honest amr/auth_time claims", async () => {
		const f = await federatedFixture();
		// Pre-link the provider identity to an existing HAPI subject.
		const subject = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "member@example.com",
			email: "member@example.com", emailVerified: true, status: "ACTIVE" });
		const linked = await f.federation.linkExternalIdentity({ identitySubjectId: subject.id, provider: "APPLE",
			providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });
		expect(linked.status).toBe("linked");

		const verifier = "verifier-linked-login";
		const interaction = await beginInteraction(f, verifier);
		const { state, code } = await launchProvider(f, interaction, "APPLE");
		const callback = await appleCallback(f, { state, code });
		expect(callback.statusCode, callback.body).toBe(303);
		const location = callback.headers.location as string;
		expect(location.startsWith(REDIRECT)).toBe(true);
		expect(new URL(location).searchParams.get("state")).toBe("rp-state");

		const token = await exchangeCode(f, location, verifier);
		expect(token.statusCode, token.body).toBe(200);
		const idToken = decodeJwt(JSON.parse(token.body).id_token);
		expect(idToken.sub).toBe(subject.oidcSubject);
		expect(idToken.amr).toEqual(["apple", "fed"]);
		expect(idToken.nonce).toBe("rp-nonce");
		expect(idToken.email).toBe("member@example.com");

		// The link records the authentication.
		const identities = await f.federation.listExternalIdentities(subject.id);
		expect(identities[0].lastAuthenticatedAt).toBeDefined();
	});

	it("offers explicit account choice for an unknown provider identity and registers a NEW subject on consent", async () => {
		const f = await federatedFixture();
		// An existing HAPI subject with the SAME email: it must never be merged or resolved.
		const existing = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "google-user@example.com",
			email: "google-user@example.com", emailVerified: true, status: "ACTIVE" });

		const verifier = "verifier-first-time";
		const interaction = await beginInteraction(f, verifier);
		const { state, code } = await launchProvider(f, interaction, "GOOGLE");
		const callback = await f.app.inject({ method: "GET",
			url: `/federation/google/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}` });
		expect(callback.statusCode, callback.body).toBe(200);
		expect(callback.body).toContain("isn't connected to an account here yet");

		const completed = await f.app.inject({ method: "POST", url: "/login/federated/complete",
			...form({ csrf: interaction.csrf, choice: "create" }, interaction.cookie) });
		expect(completed.statusCode, completed.body).toBe(303);
		const token = await exchangeCode(f, completed.headers.location as string, verifier);
		expect(token.statusCode, token.body).toBe(200);
		const idToken = decodeJwt(JSON.parse(token.body).id_token);
		expect(idToken.amr).toEqual(["google", "fed"]);
		// A brand-new subject was minted; the email-matching subject was never touched.
		expect(idToken.sub).not.toBe(existing.oidcSubject);
		const created = await f.subjects.findByOidcSubject(idToken.sub as string);
		expect(created?.primaryProvider).toBe("Google");
		expect(created?.id).not.toBe(existing.id);
		const linkedIdentities = await f.federation.listExternalIdentities(created!.id);
		expect(linkedIdentities[0]).toMatchObject({ provider: "GOOGLE", providerSubject: f.identities.GOOGLE.sub, status: "linked" });
		const googleLog = f.logs.map(line => JSON.parse(line)).find(entry =>
			entry.event === "APPLICATION_AUTHENTICATION" && entry.authenticationMethod === "GOOGLE" && entry.result === "success");
		expect(googleLog).toBeDefined();
		expect(googleLog).not.toHaveProperty("appleExchangeCategory");
	});

	it("keeps the Google switch to email sign-in unchanged", async () => {
		const f = await federatedFixture();
		const interaction = await beginInteraction(f, "verifier-switch-email");
		const { state, code } = await launchProvider(f, interaction, "GOOGLE");
		await f.app.inject({ method: "GET",
			url: `/federation/google/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}` });
		const completed = await f.app.inject({ method: "POST", url: "/login/federated/complete",
			...form({ csrf: interaction.csrf, choice: "email" }, interaction.cookie) });
		expect(completed.statusCode).toBe(303);
		expect(completed.headers.location).toBe("/login/email");
		// The pending identity is gone: a create retry fails safe.
		const retried = await f.app.inject({ method: "POST", url: "/login/federated/complete",
			...form({ csrf: interaction.csrf, choice: "create" }, interaction.cookie) });
		expect(retried.statusCode).toBe(400);
	});

	it("requires the interaction CSRF token to complete account creation", async () => {
		const f = await federatedFixture();
		const interaction = await beginInteraction(f, "verifier-csrf");
		const { state, code } = await launchProvider(f, interaction, "APPLE");
		await appleCallback(f, { state, code });
		const forged = await f.app.inject({ method: "POST", url: "/login/federated/complete",
			...form({ csrf: "forged", choice: "create" }, interaction.cookie) });
		expect(forged.statusCode).toBe(400);
		// No subject was registered.
		expect((await f.subjects.list()).length).toBe(0);
	});

	it("fails closed on state replay, forged states, and link-purpose transactions at the login callback", async () => {
		const f = await federatedFixture();
		const subject = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "replay@example.com",
			email: "replay@example.com", emailVerified: true, status: "ACTIVE" });
		await f.federation.linkExternalIdentity({ identitySubjectId: subject.id, provider: "APPLE",
			providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });
		const interaction = await beginInteraction(f, "verifier-replay");
		const { state, code } = await launchProvider(f, interaction, "APPLE");
		const first = await appleCallback(f, { state, code });
		expect(first.statusCode).toBe(303);
		// Replaying the captured callback (same state) is rejected.
		const replay = await appleCallback(f, { state, code });
		expect(replay.statusCode).toBe(400);
		// Forged state is rejected.
		expect((await appleCallback(f, { state: "F".repeat(43), code })).statusCode).toBe(400);
		// A link-purpose transaction cannot complete a login.
		const linkTxn = await f.transactions.create({ purpose: "link", provider: "APPLE",
			identitySubjectId: subject.id, sessionId: randomUUID() });
		f.codes.set("link-code", { provider: "APPLE", nonce: linkTxn.nonce });
		expect((await appleCallback(f, { state: linkTxn.state, code: "link-code" })).statusCode).toBe(400);
	});

	it("recovers gracefully from provider denial, exchange failure, and nonce-mismatched tokens", async () => {
		const f = await federatedFixture();
		const interaction = await beginInteraction(f, "verifier-recovery");

		// User cancelled at the provider: back to the chooser with a friendly message.
		const denied = await launchProvider(f, interaction, "APPLE");
		const deniedCallback = await appleCallback(f, { state: denied.state, error: "user_cancelled_authorize" });
		expect(deniedCallback.statusCode).toBe(400);
		expect(deniedCallback.body).toContain("Sign-in was cancelled");
		expect(deniedCallback.body).toContain("Continue with Apple");

		// Invalid/stolen code fails the server-side exchange.
		const exchange = await launchProvider(f, interaction, "APPLE");
		const exchangeCallback = await appleCallback(f, { state: exchange.state, code: "stolen-code" });
		expect(exchangeCallback.statusCode).toBe(400);
		expect(exchangeCallback.body).toContain("Choose another way to continue.");

		// A token bound to a different nonce (callback injection) fails verification.
		const injected = await launchProvider(f, interaction, "APPLE");
		f.codes.set("injected-code", { provider: "APPLE", nonce: "attacker-nonce" });
		const injectedCallback = await appleCallback(f, { state: injected.state, code: "injected-code" });
		expect(injectedCallback.statusCode).toBe(400);
		// The interaction survives: the user can still sign in with email.
		const chooser = await f.app.inject({ method: "GET", url: "/login", headers: { cookie: interaction.cookie } });
		expect(chooser.statusCode).toBe(200);
	});

	it.each([
		{ name: "signing", category: "signing", signingFails: true },
		{ name: "network", category: "network", networkFails: true },
		{ name: "Apple rejection", category: "provider_rejection", status: 400, oauthError: "invalid_client" },
		{ name: "invalid grant", category: "provider_rejection", status: 400, oauthError: "invalid_grant" },
		{ name: "unknown Apple error", category: "provider_rejection", status: 401, responseError: "private-response-value" },
		{ name: "non-JSON rejection", category: "provider_rejection", status: 503, body: "private-response-value" },
		{ name: "malformed JSON", category: "malformed_response", status: 200, body: "private-response-value" },
		{ name: "missing id_token", category: "malformed_response", status: 200, body: "{}" }
	])("logs sanitized Apple exchange diagnostics for $name", async (scenario) => {
		const sensitive = ["private-key-value", "client-secret-value", "authorization-code-value",
			"access-token-value", "id-token-value", "private-response-value", "private-user@example.com", "private-subject-value"];
		const fetchImpl = vi.fn<typeof fetch>(async () => {
			if (scenario.networkFails) throw new Error(sensitive.join(" "));
			return new Response(scenario.body ?? JSON.stringify({
				error: scenario.oauthError ?? scenario.responseError,
				error_description: sensitive.join(" "),
				access_token: "access-token-value",
				id_token: "id-token-value",
				email: "private-user@example.com",
				sub: "private-subject-value"
			}), { status: scenario.status ?? 200 });
		});
		const f = await federatedFixture({
			appleClientSecret: async () => {
				if (scenario.signingFails) throw new Error(sensitive.join(" "));
				return "client-secret-value";
			},
			appleExchanger: new HttpAuthorizationCodeExchanger(fetchImpl)
		});
		const interaction = await beginInteraction(f, `verifier-diagnostic-${scenario.name}`);
		const { state } = await launchProvider(f, interaction, "APPLE");
		const logStart = f.logs.length;
		const callback = await appleCallback(f, { state, code: "authorization-code-value" });
		expect(callback.statusCode).toBe(400);
		expect(callback.body).toContain("We couldn&#39;t complete that sign-in. Choose another way to continue.");
		const callbackLogs = f.logs.slice(logStart);
		const authenticationLog = callbackLogs.map(line => JSON.parse(line)).find(entry =>
			entry.event === "APPLICATION_AUTHENTICATION" && entry.reasonCode === "code_exchange_failed");
		expect(authenticationLog).toMatchObject({
			event: "APPLICATION_AUTHENTICATION", authenticationMethod: "APPLE", result: "rejected",
			reasonCode: "code_exchange_failed", appleExchangeCategory: scenario.category,
			...(scenario.category === "provider_rejection" ? { appleExchangeStatus: scenario.status } : {}),
			...(scenario.oauthError ? { appleOAuthError: scenario.oauthError } : {})
		});
		if (!scenario.oauthError) expect(authenticationLog).not.toHaveProperty("appleOAuthError");
		for (const value of sensitive) {
			expect(callbackLogs.join("")).not.toContain(value);
			expect(callback.body).not.toContain(value);
		}
		expect(fetchImpl).toHaveBeenCalledTimes(scenario.signingFails ? 0 : 1);
		expect((await appleCallback(f, { state, code: "authorization-code-value" })).statusCode).toBe(400);
	});

	it("refuses linked identities whose HAPI subject is locked or disabled", async () => {
		const f = await federatedFixture();
		const subject = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "locked@example.com",
			email: "locked@example.com", emailVerified: true, status: "ACTIVE" });
		await f.federation.linkExternalIdentity({ identitySubjectId: subject.id, provider: "APPLE",
			providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });
		await f.subjects.update(subject.oidcSubject, { status: "LOCKED" });

		const interaction = await beginInteraction(f, "verifier-locked");
		const { state, code } = await launchProvider(f, interaction, "APPLE");
		const callback = await appleCallback(f, { state, code });
		expect(callback.statusCode).toBe(403);
		expect(callback.body).toContain("unavailable");
	});

	it("fails authorization-code redemption when the provider link is revoked before /token (revocation handling)", async () => {
		const f = await federatedFixture();
		const subject = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "revoked@example.com",
			email: "revoked@example.com", emailVerified: true, status: "ACTIVE" });
		const linked = await f.federation.linkExternalIdentity({ identitySubjectId: subject.id, provider: "APPLE",
			providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });
		if (linked.status !== "linked") throw new Error("expected linked");

		const verifier = "verifier-revoked";
		const interaction = await beginInteraction(f, verifier);
		const { state, code } = await launchProvider(f, interaction, "APPLE");
		const callback = await appleCallback(f, { state, code });
		expect(callback.statusCode).toBe(303);

		// Unlink (user- or provider-initiated revocation) between code issuance and redemption.
		await f.federation.unlinkExternalIdentity({ identitySubjectId: subject.id,
			externalIdentityId: linked.externalIdentity.id });
		const token = await exchangeCode(f, callback.headers.location as string, verifier);
		expect(token.statusCode).toBe(400);
		expect(JSON.parse(token.body).error).toBe("invalid_grant");
	});

	it("establishes a fixation-safe persistent session and supports returning-user continuation", async () => {
		const f = await federatedFixture({ flags: { HAPI_PERSISTENT_SESSIONS_ENABLED: true } });
		const subject = await f.subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "returning@example.com",
			email: "returning@example.com", emailVerified: true, status: "ACTIVE" });
		await f.federation.linkExternalIdentity({ identitySubjectId: subject.id, provider: "APPLE",
			providerIssuer: APPLE_ISSUER, providerSubject: f.identities.APPLE.sub });

		// A pre-planted (attacker-chosen) session that must never become authenticated.
		const planted = await f.sessions.establishSession({ identitySubjectId: subject.id,
			authenticationMethod: "HAPI_EMAIL" });

		const verifier = "verifier-session";
		const interaction = await beginInteraction(f, verifier,
			`; ${HAPI_SESSION_COOKIE}=${planted.sessionToken}`);
		const { state, code } = await launchProvider(f, interaction, "APPLE");
		const callback = await appleCallback(f, { state, code });
		expect(callback.statusCode).toBe(303);
		const sessionToken = cookieFrom(callback, HAPI_SESSION_COOKIE);
		expect(sessionToken).toBeDefined();
		expect(sessionToken).not.toBe(planted.sessionToken);

		// NOTE: the cross-site Apple form_post carries no cookies, so the planted token cannot be
		// superseded there; it is still revoked the moment it is presented on a same-site login.
		const session = await f.sessionRepository.findByTokenHash(hashSessionToken(sessionToken!));
		expect(session).toMatchObject({ identitySubjectId: subject.id, authenticationMethod: "APPLE", status: "active" });

		// Returning user: a NEW authorization shows "Continue as" from the live session.
		const next = await beginInteraction(f, "verifier-continue", `; ${HAPI_SESSION_COOKIE}=${sessionToken}`);
		expect(next.chooser.body).toContain("Continue as returning@example.com");
		const continued = await f.app.inject({ method: "POST", url: "/login/continue",
			...form({ csrf: next.csrf }, `${next.cookie}; ${HAPI_SESSION_COOKIE}=${sessionToken}`) });
		expect(continued.statusCode, continued.body).toBe(303);
		const token = await exchangeCode(f, continued.headers.location as string, "verifier-continue");
		expect(token.statusCode, token.body).toBe(200);
		const idToken = decodeJwt(JSON.parse(token.body).id_token);
		expect(idToken.sub).toBe(subject.oidcSubject);
		// Honest claims: the ORIGINAL federated authentication, not the continuation.
		expect(idToken.amr).toEqual(["apple", "fed"]);
		expect(idToken.auth_time).toBe(Math.floor(Date.parse(session!.authenticatedAt) / 1000));

		// A stale/revoked session cannot continue.
		await f.sessions.revokeAllSessions(subject.id, "test_revoked");
		const stale = await beginInteraction(f, "verifier-stale", `; ${HAPI_SESSION_COOKIE}=${sessionToken}`);
		expect(stale.chooser.body).not.toContain("Continue as");
		const refused = await f.app.inject({ method: "POST", url: "/login/continue",
			...form({ csrf: stale.csrf }, `${stale.cookie}; ${HAPI_SESSION_COOKIE}=${sessionToken}`) });
		expect(refused.statusCode).toBe(401);
	});

	it("keeps the pre-federation chooser surface operational alongside federation", async () => {
		const f = await federatedFixture();
		const interaction = await beginInteraction(f, "verifier-email-coexists");
		// The pre-existing non-federated option still renders with the same interaction CSRF, and
		// the email route remains reachable (full OTP coverage lives in UniversalLogin.test.ts).
		expect(interaction.chooser.body).toContain("Continue with Face");
		const emailPage = await f.app.inject({ method: "GET", url: "/login/email",
			headers: { cookie: interaction.cookie } });
		expect([200, 303]).toContain(emailPage.statusCode);
	});
});
