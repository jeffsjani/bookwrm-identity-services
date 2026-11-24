// HAPI ID V2-C Phase 2/5: grant_type=refresh_token behind the default-off
// HAPI_REFRESH_GRANT_ENABLED gate. With the gate off, every observable /token and discovery
// behavior is byte-identical to V2-B; with it on, refresh exchanges rotate one-time-use family
// generations with replay (reuse) detection and family revocation.
import { afterEach, describe, expect, it, vi } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { inMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { oidcService } from "../src/oidc/oidcServiceInstance.js";
import {
		authorizeAndGetCode,
		buildOidcTestApp,
		exchangeAuthorizationCode
} from "./oidcTestHarness.js";
import type { FastifyInstance } from "fastify";

function mockIdentityContextFetch(): void {
		vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: vi.fn().mockResolvedValue({
								success: true,
								requestId: "v2c-refresh-grant",
								version: "v1",
								data: {
										userId: "dev-user-1",
										confidence: 0.95,
										risk: 0.1,
										securityLevel: "high",
										verified: true,
										trustedDevice: true,
										verificationRequired: false
								}
						})
				} as unknown as Response)
		);
}

function enableRefreshGrant(): void {
		process.env.HAPI_REFRESH_GRANT_ENABLED = "true";
		configuration.reload();
}

function disableRefreshGrant(): void {
		delete process.env.HAPI_REFRESH_GRANT_ENABLED;
		configuration.reload();
}

async function refreshExchange(
		app: FastifyInstance,
		refreshToken: string,
		overrides: { clientId?: string; clientSecret?: string } = {}
) {
		const body = new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: overrides.clientId ?? "base44-web",
				client_secret: overrides.clientSecret ?? "base44-secret"
		});
		return app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
		});
}

async function loginAndGetRefreshToken(app: FastifyInstance): Promise<string> {
		const verifier = "v2c-refresh-grant-verifier-123456";
		const code = await authorizeAndGetCode(app, verifier);
		const response = await exchangeAuthorizationCode(app, code, verifier);
		expect(response.statusCode).toBe(200);
		const refreshToken = response.json().refresh_token as string;
		expect(typeof refreshToken).toBe("string");
		return refreshToken;
}

describe("V2-C refresh grant: default-off gate preserves V2-B behavior exactly", () => {
		afterEach(() => {
				disableRefreshGrant();
				vi.unstubAllGlobals();
		});

		it("rejects grant_type=refresh_token with the V2-B message while the gate is off", async () => {
				const { app } = await buildOidcTestApp();
				const response = await refreshExchange(app, "hrt_anything");
				expect(response.statusCode).toBe(400);
				expect(response.json()).toEqual({
						error: "unsupported_grant_type",
						error_description: "Only grant_type=authorization_code is supported"
				});
				await app.close();
		});

		it("advertises only authorization_code in discovery while the gate is off", async () => {
				await buildOidcTestApp();
				const discovery = oidcService.getDiscoveryConfiguration();
				expect(discovery.grant_types_supported).toEqual(["authorization_code"]);
		});

		it("keeps issuing the legacy (non-family) refresh token to the Bookwrm client while the gate is off", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const refreshToken = await loginAndGetRefreshToken(app);
				// Legacy opaque token, not a V2-C family token.
				expect(refreshToken.startsWith("hrt_")).toBe(false);
				await app.close();
		});
});

describe("V2-C refresh grant: enabled gate", () => {
		afterEach(() => {
				disableRefreshGrant();
				vi.unstubAllGlobals();
		});

		it("advertises refresh_token in discovery only while the gate is on", async () => {
				await buildOidcTestApp();
				enableRefreshGrant();
				expect(oidcService.getDiscoveryConfiguration().grant_types_supported)
						.toEqual(["authorization_code", "refresh_token"]);
				disableRefreshGrant();
				expect(oidcService.getDiscoveryConfiguration().grant_types_supported)
						.toEqual(["authorization_code"]);
		});

		it("issues a family refresh token at code exchange and rotates it on refresh", async () => {
				mockIdentityContextFetch();
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const firstRefreshToken = await loginAndGetRefreshToken(app);
				expect(firstRefreshToken).toMatch(/^hrt_[A-Za-z0-9_-]{43}$/);

				const response = await refreshExchange(app, firstRefreshToken);
				expect(response.statusCode).toBe(200);
				const payload = response.json();
				expect(payload.token_type).toBe("Bearer");
				expect(typeof payload.access_token).toBe("string");
				expect(payload.refresh_token).toMatch(/^hrt_[A-Za-z0-9_-]{43}$/);
				expect(payload.refresh_token).not.toBe(firstRefreshToken);
				expect(payload.scope).toBe("openid profile email");
				// Refresh responses never carry an ID Token nonce transaction; no id_token is minted.
				expect(payload.id_token).toBeUndefined();
				await app.close();
		});

		it("rejects replay of a consumed refresh token and revokes the whole family", async () => {
				mockIdentityContextFetch();
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const firstRefreshToken = await loginAndGetRefreshToken(app);

				const rotation = await refreshExchange(app, firstRefreshToken);
				expect(rotation.statusCode).toBe(200);
				const successor = rotation.json().refresh_token as string;

				// Replay of the consumed token: invalid_grant, no token material echoed.
				const replay = await refreshExchange(app, firstRefreshToken);
				expect(replay.statusCode).toBe(400);
				expect(replay.json()).toEqual({
						error: "invalid_grant",
						error_description: "Refresh token is invalid, expired, or revoked"
				});
				expect(replay.body).not.toContain(firstRefreshToken.slice(4));

				// Family revocation: the legitimate successor is dead as well.
				const afterReplay = await refreshExchange(app, successor);
				expect(afterReplay.statusCode).toBe(400);
				expect(afterReplay.json()).toMatchObject({ error: "invalid_grant" });
				await app.close();
		});

		it("rejects a refresh exchange with invalid client credentials without consuming the token", async () => {
				mockIdentityContextFetch();
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const refreshToken = await loginAndGetRefreshToken(app);

				const wrongSecret = await refreshExchange(app, refreshToken, { clientSecret: "wrong-secret" });
				expect(wrongSecret.statusCode).toBe(400);
				expect(wrongSecret.json()).toMatchObject({ error: "invalid_client" });

				const unknownClient = await refreshExchange(app, refreshToken, { clientId: "unknown-client" });
				expect(unknownClient.statusCode).toBe(400);
				expect(unknownClient.json()).toMatchObject({ error: "invalid_client" });

				// Failed client authentication never consumed the token.
				const legitimate = await refreshExchange(app, refreshToken);
				expect(legitimate.statusCode).toBe(200);
				await app.close();
		});

		it("enforces the registered method on refresh without consuming the token", async () => {
				mockIdentityContextFetch();
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const refreshToken = await loginAndGetRefreshToken(app);
				const record = await inMemoryOIDCClientRepository.findByClientId("base44-web");
				if (!record) throw new Error("OIDC test client was not seeded");
				await inMemoryOIDCClientRepository.upsert({ ...record, tokenEndpointAuthMethod: "client_secret_basic" });
				const rejected = await refreshExchange(app, refreshToken);
				expect(rejected.json()).toMatchObject({ error: "invalid_client" });
				const credentials = Buffer.from("base44-web:base44-secret").toString("base64");
				const response = await app.inject({ method: "POST", url: "/token",
						headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${credentials}` },
						payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }).toString() });
				expect(response.statusCode).toBe(200);
				await app.close();
		});

		it("rejects clients whose registration does not include the refresh_token grant", async () => {
				mockIdentityContextFetch();
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const refreshToken = await loginAndGetRefreshToken(app);

				const record = await inMemoryOIDCClientRepository.findByClientId("base44-web");
				if (!record) throw new Error("OIDC test client was not seeded");
				try {
						await inMemoryOIDCClientRepository.upsert({ ...record, grantTypes: ["authorization_code"] });
						const response = await refreshExchange(app, refreshToken);
						expect(response.statusCode).toBe(400);
						expect(response.json()).toMatchObject({ error: "unauthorized_client" });
				} finally {
						await inMemoryOIDCClientRepository.upsert(record);
				}
				await app.close();
		});

		it("rejects a refresh exchange without a refresh_token parameter", async () => {
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const body = new URLSearchParams({
						grant_type: "refresh_token",
						client_id: "base44-web",
						client_secret: "base44-secret"
				});
				const response = await app.inject({
						method: "POST",
						url: "/token",
						headers: { "content-type": "application/x-www-form-urlencoded" },
						payload: body.toString()
				});
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "invalid_request" });
				await app.close();
		});

		it("keeps the authorization_code flow contract unchanged with the gate on", async () => {
				mockIdentityContextFetch();
				enableRefreshGrant();
				const { app } = await buildOidcTestApp();
				const verifier = "v2c-code-flow-regression-123456";
				const code = await authorizeAndGetCode(app, verifier);
				const response = await exchangeAuthorizationCode(app, code, verifier);
				expect(response.statusCode).toBe(200);
				const payload = response.json();
				expect(payload.token_type).toBe("Bearer");
				expect(typeof payload.access_token).toBe("string");
				expect(typeof payload.id_token).toBe("string");
				expect(payload.expires_in).toBe(300);
				await app.close();
		});
});
