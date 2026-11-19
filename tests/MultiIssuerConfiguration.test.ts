import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { randomUUID } from "node:crypto";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import {
	DEFAULT_OIDC_ISSUER,
	enforceDeploymentIssuerPin,
	parseExactHttpsOrigin,
	recordIssuerAccepted,
	resolveConfiguredIssuer
} from "../src/config/IssuerPolicy.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { RedisOIDCStore } from "../src/oidc/infrastructure/RedisOIDCStore.js";
import { InMemoryRefreshTokenFamilyRepository } from "../src/oidc/refresh/InMemoryRefreshTokenFamilyRepository.js";
import { REFRESH_LIFETIMES, RefreshTokenRotationService } from "../src/oidc/refresh/RefreshTokenRotationService.js";
import { PrivateIDClient } from "../src/privateid/PrivateIDClient.js";
import type { AuthenticationProvider } from "../src/authentication/AuthenticationProvider.js";
import {
	authorizeAndGetCode,
	buildOidcTestApp,
	ensureOidcTestEnvironment,
	exchangeAuthorizationCode,
	pkceChallengeFromVerifier
} from "./oidcTestHarness.js";

// HAPI ID V2-E Stage 0 Phase 2: multi-issuer configuration certification. Every issuer below is
// an explicitly configured synthetic test environment; no production configuration is touched.
const BOOKWRM_ISSUER = "https://identity.bookwrm.com";
const STAGING_ISSUER = "https://id-staging.hapiinc.com";
const PRODUCTION_ISSUER = "https://id.hapiinc.com";

const ISSUER_ENV_KEYS = ["OIDC_ISSUER", "OIDC_ALLOWED_ISSUERS", "CORS_TRUSTED_ORIGINS", "HAPI_REFRESH_GRANT_ENABLED"] as const;

function setIssuerEnv(issuer?: string): void {
	if (issuer === undefined) {
		delete process.env.OIDC_ISSUER;
	} else {
		process.env.OIDC_ISSUER = issuer;
	}
	configuration.reload();
}

function mockAuthenticationProvider(): AuthenticationProvider {
	return {
		authenticate: vi.fn(async () => { throw new Error("Interactive provider must not run"); }),
		cancel: vi.fn(async () => {}),
		logout: vi.fn(async () => {}),
		status: vi.fn(async () => ({ state: "idle" as const })),
		beginAsyncAuthentication: vi.fn(async () => ({ sessionId: "mock", launchUrl: "https://provider.example/launch" }))
	};
}

async function fetchDiscovery(app: Awaited<ReturnType<typeof buildOidcTestApp>>["app"]): Promise<Record<string, unknown>> {
	const response = await app.inject({ method: "GET", url: "/.well-known/openid-configuration" });
	expect(response.statusCode).toBe(200);
	return response.json() as Record<string, unknown>;
}

describe("V2-E Stage 0 — issuer configuration validation (fail closed)", () => {
	afterEach(() => {
		for (const key of ISSUER_ENV_KEYS) delete process.env[key];
		configuration.reload();
	});

	it("defaults to the Bookwrm issuer and accepts the explicit staging and canonical issuers", () => {
		expect(resolveConfiguredIssuer()).toBe(BOOKWRM_ISSUER);
		setIssuerEnv(STAGING_ISSUER);
		expect(resolveConfiguredIssuer()).toBe(STAGING_ISSUER);
		setIssuerEnv(PRODUCTION_ISSUER);
		expect(resolveConfiguredIssuer()).toBe(PRODUCTION_ISSUER);
	});

	it("rejects malformed, non-https, wildcard, suffix, path-bearing, and credentialed issuers", () => {
		for (const bad of [
			"not-a-url",
			"http://id.hapiinc.com",
			"https://*.hapiinc.com",
			"https://id.hapiinc.com/",
			"https://id.hapiinc.com/oidc",
			"https://id.hapiinc.com?x=1",
			"https://id.hapiinc.com#frag",
			"https://user:pass@id.hapiinc.com"
		]) {
			setIssuerEnv(bad);
			expect(() => resolveConfiguredIssuer(), bad).toThrow();
		}

		// A blank OIDC_ISSUER is treated as unset: the default Bookwrm issuer applies.
		setIssuerEnv(" ");
		expect(resolveConfiguredIssuer()).toBe(BOOKWRM_ISSUER);
	});

	it("never performs suffix or wildcard matching on exact origins", () => {
		expect(() => parseExactHttpsOrigin("https://id.hapiinc.com.attacker.example", "issuer")).not.toThrow();
		expect(parseExactHttpsOrigin("https://id.hapiinc.com.attacker.example", "issuer"))
			.not.toBe(PRODUCTION_ISSUER);
		expect(() => parseExactHttpsOrigin("https://*.hapiinc.com", "issuer")).toThrow();
	});

	it("fails closed on conflicting or empty OIDC_ALLOWED_ISSUERS configuration", () => {
		process.env.OIDC_ALLOWED_ISSUERS = PRODUCTION_ISSUER;
		setIssuerEnv(STAGING_ISSUER);
		expect(() => resolveConfiguredIssuer()).toThrow(/not present in OIDC_ALLOWED_ISSUERS/);

		process.env.OIDC_ALLOWED_ISSUERS = `${STAGING_ISSUER},${PRODUCTION_ISSUER}`;
		configuration.reload();
		expect(resolveConfiguredIssuer()).toBe(STAGING_ISSUER);

		process.env.OIDC_ALLOWED_ISSUERS = "";
		configuration.reload();
		expect(() => resolveConfiguredIssuer()).toThrow(/contains no origins/);
	});

	it("discovery generation fails closed for an invalid injected issuer", () => {
		ensureOidcTestEnvironment();
		const invalid = new OIDCService({ authenticationProvider: mockAuthenticationProvider(), issuer: "https://id.hapiinc.com/" });
		expect(() => invalid.getDiscoveryConfiguration()).toThrow();
		const http = new OIDCService({ authenticationProvider: mockAuthenticationProvider(), issuer: "http://id.hapiinc.com" });
		expect(() => http.getDiscoveryConfiguration()).toThrow();
	});

	it("legacy issuer-less stored records are honored only by the default Bookwrm issuer", () => {
		expect(recordIssuerAccepted(undefined, DEFAULT_OIDC_ISSUER)).toBe(true);
		expect(recordIssuerAccepted(undefined, STAGING_ISSUER)).toBe(false);
		expect(recordIssuerAccepted(STAGING_ISSUER, STAGING_ISSUER)).toBe(true);
		expect(recordIssuerAccepted(STAGING_ISSUER, PRODUCTION_ISSUER)).toBe(false);
	});
});

// HAPI ID V2-E Stage 1: boot-time deployment pin. Any non-default issuer service (staging or the
// future canonical production issuer) must be explicitly pinned to exactly its own issuer and
// must carry an explicit CORS allowlist; the default Bookwrm issuer behavior is unchanged.
describe("V2-E Stage 1 — deployment issuer pin (fail closed at boot)", () => {
	afterEach(() => {
		for (const key of ISSUER_ENV_KEYS) delete process.env[key];
		configuration.reload();
	});

	it("keeps the default Bookwrm issuer bootable without an allowlist or CORS override (production unchanged)", () => {
		expect(enforceDeploymentIssuerPin()).toBe(BOOKWRM_ISSUER);
		setIssuerEnv(BOOKWRM_ISSUER);
		expect(enforceDeploymentIssuerPin()).toBe(BOOKWRM_ISSUER);
	});

	it("refuses to boot a non-default issuer without an OIDC_ALLOWED_ISSUERS pin", () => {
		setIssuerEnv(STAGING_ISSUER);
		expect(() => enforceDeploymentIssuerPin()).toThrow(/OIDC_ALLOWED_ISSUERS must be configured/);
	});

	it("refuses to boot the staging issuer when the allowlist also names another issuer", () => {
		process.env.OIDC_ALLOWED_ISSUERS = `${STAGING_ISSUER},${PRODUCTION_ISSUER}`;
		process.env.CORS_TRUSTED_ORIGINS = "https://staging-app.hapiinc.com";
		setIssuerEnv(STAGING_ISSUER);
		expect(() => enforceDeploymentIssuerPin()).toThrow(/must allow only the configured issuer/);

		process.env.OIDC_ALLOWED_ISSUERS = `${STAGING_ISSUER},${BOOKWRM_ISSUER}`;
		configuration.reload();
		expect(() => enforceDeploymentIssuerPin()).toThrow(/must allow only the configured issuer/);
	});

	it("refuses to boot a non-default issuer without an explicit CORS_TRUSTED_ORIGINS allowlist", () => {
		process.env.OIDC_ALLOWED_ISSUERS = STAGING_ISSUER;
		setIssuerEnv(STAGING_ISSUER);
		expect(() => enforceDeploymentIssuerPin()).toThrow(/CORS_TRUSTED_ORIGINS must be explicitly configured/);
	});

	it("boots the staging issuer only under an exact single-issuer pin plus explicit CORS origins", () => {
		process.env.OIDC_ALLOWED_ISSUERS = STAGING_ISSUER;
		process.env.CORS_TRUSTED_ORIGINS = "https://id-staging.hapiinc.com,https://staging-app.hapiinc.com";
		setIssuerEnv(STAGING_ISSUER);
		expect(enforceDeploymentIssuerPin()).toBe(STAGING_ISSUER);

		// The same rule governs the future canonical production issuer.
		process.env.OIDC_ALLOWED_ISSUERS = PRODUCTION_ISSUER;
		setIssuerEnv(PRODUCTION_ISSUER);
		expect(enforceDeploymentIssuerPin()).toBe(PRODUCTION_ISSUER);
	});
});

describe("V2-E Stage 0 — per-issuer discovery certification", () => {
	afterEach(() => {
		for (const key of ISSUER_ENV_KEYS) delete process.env[key];
		configuration.reload();
	});

	for (const issuer of [BOOKWRM_ISSUER, STAGING_ISSUER, PRODUCTION_ISSUER]) {
		it(`advertises exact issuer and issuer-anchored endpoints for ${issuer}`, async () => {
			const { app } = await buildOidcTestApp();
			try {
				setIssuerEnv(issuer === BOOKWRM_ISSUER ? undefined : issuer);
				const discovery = await fetchDiscovery(app);
				expect(discovery.issuer).toBe(issuer);
				expect(discovery.authorization_endpoint).toBe(`${issuer}/authorize`);
				expect(discovery.token_endpoint).toBe(`${issuer}/token`);
				expect(discovery.userinfo_endpoint).toBe(`${issuer}/userinfo`);
				expect(discovery.jwks_uri).toBe(`${issuer}/jwks`);
				// Feature flags remain default-off: no refresh grant is advertised anywhere.
				expect(discovery.grant_types_supported).toEqual(["authorization_code"]);
			} finally {
				await app.close();
			}
		});
	}

	it("preserves the existing Bookwrm discovery document byte-for-byte under default configuration", async () => {
		const { app } = await buildOidcTestApp();
		try {
			const discovery = await fetchDiscovery(app);
			expect(discovery.issuer).toBe(BOOKWRM_ISSUER);
			expect(discovery.authorization_endpoint).toBe(`${BOOKWRM_ISSUER}/authorize`);
			expect(discovery.token_endpoint).toBe(`${BOOKWRM_ISSUER}/token`);
			expect(discovery.userinfo_endpoint).toBe(`${BOOKWRM_ISSUER}/userinfo`);
			expect(discovery.jwks_uri).toBe(`${BOOKWRM_ISSUER}/jwks`);
			expect(discovery.response_types_supported).toEqual(["code"]);
			expect(discovery.code_challenge_methods_supported).toEqual(["S256"]);
			expect(discovery.grant_types_supported).toEqual(["authorization_code"]);
		} finally {
			await app.close();
		}
	});
});

describe("V2-E Stage 0 — cross-issuer token and code isolation", () => {
	afterEach(() => {
		for (const key of ISSUER_ENV_KEYS) delete process.env[key];
		configuration.reload();
	});

	it("issues staging-issuer ID tokens with exact iss, client-specific aud, and a verifiable JWKS", async () => {
		const { app } = await buildOidcTestApp();
		try {
			setIssuerEnv(STAGING_ISSUER);
			const verifier = "v".repeat(43);
			const code = await authorizeAndGetCode(app, verifier);
			const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
			expect(tokenResponse.statusCode).toBe(200);
			const body = tokenResponse.json() as Record<string, string>;

			const claims = decodeJwt(body.id_token);
			expect(claims.iss).toBe(STAGING_ISSUER);
			expect(claims.aud).toBe("base44-web");

			const jwksResponse = await app.inject({ method: "GET", url: "/jwks" });
			expect(jwksResponse.statusCode).toBe(200);
			const jwks = createLocalJWKSet(jwksResponse.json());
			const verified = await jwtVerify(body.id_token, jwks, { issuer: STAGING_ISSUER, audience: "base44-web" });
			expect(verified.payload.iss).toBe(STAGING_ISSUER);

			// An RP pinned to a different issuer must reject the token outright.
			await expect(jwtVerify(body.id_token, jwks, { issuer: PRODUCTION_ISSUER, audience: "base44-web" }))
				.rejects.toThrow();
			// Audience stays client-specific: a different client audience is rejected.
			await expect(jwtVerify(body.id_token, jwks, { issuer: STAGING_ISSUER, audience: "another-client" }))
				.rejects.toThrow();
		} finally {
			await app.close();
		}
	});

	it("rejects cross-issuer authorization codes while honoring same-issuer codes", async () => {
		const { app } = await buildOidcTestApp();
		try {
			setIssuerEnv(STAGING_ISSUER);
			const verifier = "w".repeat(43);
			const stagingCode = await authorizeAndGetCode(app, verifier);

			// The code was minted by the staging issuer; the production issuer must refuse it.
			setIssuerEnv(PRODUCTION_ISSUER);
			const crossIssuer = await exchangeAuthorizationCode(app, stagingCode, verifier);
			expect(crossIssuer.statusCode).toBe(400);
			expect((crossIssuer.json() as Record<string, string>).error).toBe("invalid_grant");

			// Control: a code minted and redeemed under the same issuer succeeds.
			const productionCode = await authorizeAndGetCode(app, verifier);
			const sameIssuer = await exchangeAuthorizationCode(app, productionCode, verifier);
			expect(sameIssuer.statusCode).toBe(200);
			expect((decodeJwt((sameIssuer.json() as Record<string, string>).id_token)).iss).toBe(PRODUCTION_ISSUER);
		} finally {
			await app.close();
		}
	});

	it("staging access tokens cannot authenticate against the production issuer's UserInfo", async () => {
		const { app } = await buildOidcTestApp();
		try {
			setIssuerEnv(STAGING_ISSUER);
			const verifier = "x".repeat(43);
			const code = await authorizeAndGetCode(app, verifier);
			const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
			expect(tokenResponse.statusCode).toBe(200);
			const accessToken = (tokenResponse.json() as Record<string, string>).access_token;

			// Same issuer: UserInfo serves the identity context minted by this issuer.
			const sameIssuer = await app.inject({ method: "GET", url: "/userinfo", headers: { authorization: `Bearer ${accessToken}` } });
			expect(sameIssuer.statusCode).toBe(200);
			expect((sameIssuer.json() as Record<string, unknown>).sub).toBeDefined();

			// Cross issuer: the production issuer must reject the staging token.
			setIssuerEnv(PRODUCTION_ISSUER);
			const crossIssuer = await app.inject({ method: "GET", url: "/userinfo", headers: { authorization: `Bearer ${accessToken}` } });
			expect(crossIssuer.statusCode).toBe(401);
			expect((crossIssuer.json() as Record<string, string>).error).toBe("invalid_token");
		} finally {
			await app.close();
		}
	});

	it("honors pre-Stage-0 issuer-less access tokens only on the default Bookwrm issuer", async () => {
		const { app } = await buildOidcTestApp();
		try {
			const subject = await identityRegistry.resolveOrCreate({
				provider: "HAPI_EMAIL",
				providerSubject: `legacy-${randomUUID()}@bookwrm.local`,
				email: `legacy-${randomUUID()}@bookwrm.local`,
				emailVerified: true
			});
			const store = new RedisOIDCStore();
			const legacyToken = `legacy-${randomUUID()}`;
			// Simulates a token minted before Stage 0 deployed: no issuer binding on the record.
			await store.storeAccessToken(legacyToken, {
				sub: subject.oidcSubject, clientId: "base44-web", nonce: "n", scope: "openid"
			}, 300_000);

			const onDefault = await app.inject({ method: "GET", url: "/userinfo", headers: { authorization: `Bearer ${legacyToken}` } });
			expect(onDefault.statusCode).toBe(200);

			setIssuerEnv(STAGING_ISSUER);
			const onStaging = await app.inject({ method: "GET", url: "/userinfo", headers: { authorization: `Bearer ${legacyToken}` } });
			expect(onStaging.statusCode).toBe(401);
		} finally {
			await app.close();
		}
	});

	it("keeps redirect URI validation exact under a non-default issuer", async () => {
		const { app } = await buildOidcTestApp();
		try {
			setIssuerEnv(STAGING_ISSUER);
			for (const redirectUri of [
				"https://example.com/callback/",
				"https://example.com/other",
				"https://example.com.attacker.example/callback"
			]) {
				const params = new URLSearchParams({
					response_type: "code",
					client_id: "base44-web",
					redirect_uri: redirectUri,
					scope: "openid profile email",
					state: "s",
					nonce: "n",
					code_challenge_method: "S256",
					code_challenge: pkceChallengeFromVerifier("y".repeat(43))
				});
				const response = await app.inject({ method: "GET", url: `/authorize?${params.toString()}` });
				expect(response.statusCode, redirectUri).toBe(400);
			}
		} finally {
			await app.close();
		}
	});
});

describe("V2-E Stage 0 — cross-issuer refresh-token isolation (isolated synthetic clients)", () => {
	afterEach(() => {
		for (const key of ISSUER_ENV_KEYS) delete process.env[key];
		configuration.reload();
	});

	async function issuerEnvironment(issuer: string) {
		const tenants = new InMemoryTenantRepository();
		const applications = new InMemoryApplicationRepository();
		const clients = new InMemoryOIDCClientRepository();
		const tenantId = randomUUID();
		await tenants.upsert({ id: tenantId, name: "Synthetic", slug: tenantId, status: "active" });
		await applications.upsert({
			id: "SYNTH_APP", tenantId, name: "SYNTH_APP", slug: "synth-app", applicationKey: "SYNTH_APP",
			status: "active", allowedAuthenticationMethods: ["HAPI_EMAIL"], allowedIdentityProviders: []
		});
		await clients.upsert({
			id: randomUUID(), applicationId: "SYNTH_APP", clientId: "synthetic-web", clientSecret: "synthetic-secret",
			redirectUris: ["https://rp.example/callback"], scopes: ["openid", "profile", "email"],
			grantTypes: ["authorization_code", "refresh_token"], responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_post", requirePkce: true
		});
		const rotation = new RefreshTokenRotationService(new InMemoryRefreshTokenFamilyRepository(), REFRESH_LIFETIMES);
		const oidc = new OIDCService({
			authenticationProvider: mockAuthenticationProvider(),
			issuer,
			oidcClients: clients,
			clientAuthority: { tenants, applications, clients },
			refreshTokenRotation: rotation
		});
		const app = Fastify();
		await app.register(formbody);
		await oidc.registerEndpoints(app);
		await app.ready();
		return { app, rotation };
	}

	it("a staging-issued refresh token is rejected by the production issuer and rotates only at home", async () => {
		ensureOidcTestEnvironment();
		process.env.HAPI_REFRESH_GRANT_ENABLED = "true";
		configuration.reload();

		const staging = await issuerEnvironment(STAGING_ISSUER);
		const production = await issuerEnvironment(PRODUCTION_ISSUER);
		try {
			const email = `refresh-${randomUUID()}@bookwrm.local`;
			const subject = await identityRegistry.resolveOrCreate({
				provider: "HAPI_EMAIL", providerSubject: email, email, emailVerified: true
			});
			const issued = await staging.rotation.issueFamily({
				identitySubjectId: subject.id,
				clientId: "synthetic-web",
				scope: "openid profile email",
				clientProfile: "confidential_web"
			});

			const refreshRequest = (app: typeof staging.app, refreshToken: string) => app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
					client_id: "synthetic-web",
					client_secret: "synthetic-secret"
				}).toString()
			});

			// Cross-issuer: the production issuer's token endpoint must reject the staging family.
			const crossIssuer = await refreshRequest(production.app, issued.refreshToken);
			expect(crossIssuer.statusCode).toBe(400);
			expect((crossIssuer.json() as Record<string, string>).error).toBe("invalid_grant");

			// Control: the issuing environment rotates the same token successfully.
			const sameIssuer = await refreshRequest(staging.app, issued.refreshToken);
			expect(sameIssuer.statusCode).toBe(200);
			const rotated = sameIssuer.json() as Record<string, string>;
			expect(rotated.refresh_token).toBeDefined();
			expect(rotated.refresh_token).not.toBe(issued.refreshToken);
			expect(rotated.access_token).toBeDefined();
		} finally {
			await staging.app.close();
			await production.app.close();
		}
	});

	it("keeps grant_type=refresh_token disabled by default on every issuer (flags default-off)", async () => {
		ensureOidcTestEnvironment();
		const staging = await issuerEnvironment(STAGING_ISSUER);
		try {
			const response = await staging.app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: "hrt_anything",
					client_id: "synthetic-web",
					client_secret: "synthetic-secret"
				}).toString()
			});
			expect(response.statusCode).toBe(400);
			expect((response.json() as Record<string, string>).error).toBe("unsupported_grant_type");
		} finally {
			await staging.app.close();
		}
	});
});

describe("V2-E Stage 0 — PrivateID callback configuration", () => {
	const ENV_KEYS = ["PRIVATEID_CALLBACK_URL", "PRIVATEID_ALLOWED_CALLBACK_ORIGINS", "PRIVATEID_MOCK_MODE"] as const;
	const saved: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {};

	function sessionApiFetchMock() {
		return vi.fn(async () => new Response(JSON.stringify({
			sessionId: `api-session-${randomUUID()}`,
			status: "created",
			launchUrl: "https://privateid.example.com/launch/abc123",
			expires: Date.now() + 300_000,
			created: Date.now()
		}), { status: 200, headers: { "content-type": "application/json" } }));
	}

	async function callbackUrlSentToPrivateID(): Promise<string> {
		const fetchMock = sessionApiFetchMock();
		const originalFetch = global.fetch;
		global.fetch = fetchMock as unknown as typeof fetch;
		try {
			await new PrivateIDClient().createAuthenticationSession();
			const requestInit = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
			const body = JSON.parse(String(requestInit?.body)) as { callback: { url: string } };
			return body.callback.url;
		} finally {
			global.fetch = originalFetch;
		}
	}

	async function expectSessionCreationRejected(): Promise<void> {
		const fetchMock = sessionApiFetchMock();
		const originalFetch = global.fetch;
		global.fetch = fetchMock as unknown as typeof fetch;
		try {
			await expect(new PrivateIDClient().createAuthenticationSession()).rejects.toThrow(/PRIVATEID_CALLBACK_URL/);
			expect(fetchMock).not.toHaveBeenCalled();
		} finally {
			global.fetch = originalFetch;
		}
	}

	function applyEnvironment(overrides: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>): void {
		ensureOidcTestEnvironment();
		process.env.PRIVATEID_MOCK_MODE = "false";
		for (const [key, value] of Object.entries(overrides)) {
			if (value === undefined) delete process.env[key]; else process.env[key] = value;
		}
		configuration.reload();
	}

	for (const key of ENV_KEYS) saved[key] = process.env[key];

	afterEach(() => {
		for (const key of ENV_KEYS) {
			if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key];
		}
		configuration.reload();
	});

	it("preserves the production webhook callback by default and accepts the supported issuer hosts", async () => {
		applyEnvironment({ PRIVATEID_CALLBACK_URL: undefined, PRIVATEID_ALLOWED_CALLBACK_ORIGINS: undefined });
		expect(await callbackUrlSentToPrivateID()).toBe("https://identity.bookwrm.com/privateid/webhook");

		for (const host of ["https://identity.bookwrm.com", "https://id-staging.hapiinc.com", "https://id.hapiinc.com"]) {
			applyEnvironment({ PRIVATEID_CALLBACK_URL: `${host}/privateid/webhook`, PRIVATEID_ALLOWED_CALLBACK_ORIGINS: undefined });
			expect(await callbackUrlSentToPrivateID()).toBe(`${host}/privateid/webhook`);
		}
	});

	it("rejects malformed, non-https, decorated, or unexpected callback origins before any session is created", async () => {
		for (const bad of [
			"not-a-url",
			"http://identity.bookwrm.com/privateid/webhook",
			"https://identity.bookwrm.com/privateid/webhook?x=1",
			"https://identity.bookwrm.com/privateid/webhook#frag",
			"https://user:pass@identity.bookwrm.com/privateid/webhook",
			"https://evil.example/privateid/webhook",
			"https://id.hapiinc.com.attacker.example/privateid/webhook"
		]) {
			applyEnvironment({ PRIVATEID_CALLBACK_URL: bad, PRIVATEID_ALLOWED_CALLBACK_ORIGINS: undefined });
			await expectSessionCreationRejected();
		}
	});

	it("supports explicitly allowlisted additional callback origins with exact matching only", async () => {
		applyEnvironment({
			PRIVATEID_CALLBACK_URL: "https://id-dev.hapiinc.com/privateid/webhook",
			PRIVATEID_ALLOWED_CALLBACK_ORIGINS: "https://id-dev.hapiinc.com"
		});
		expect(await callbackUrlSentToPrivateID()).toBe("https://id-dev.hapiinc.com/privateid/webhook");

		// The extra allowlist itself is validated: wildcards fail closed.
		applyEnvironment({
			PRIVATEID_CALLBACK_URL: "https://id-dev.hapiinc.com/privateid/webhook",
			PRIVATEID_ALLOWED_CALLBACK_ORIGINS: "https://*.hapiinc.com"
		});
		await expect(new PrivateIDClient().createAuthenticationSession()).rejects.toThrow(/wildcard/i);
	});
});
