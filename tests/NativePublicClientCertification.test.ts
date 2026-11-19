// HAPI ID V2-B Phase 3: native public-client certification (isolated development/test clients
// only; no production client is registered or activated here). Certifies the OIDC properties a
// native Elite+ client will depend on: token_endpoint_auth_method=none, Authorization Code grant,
// mandatory PKCE S256, exact redirect URI matching, single-use codes, wrong-client rejection, and
// authorization-code expiration.
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";

import { inMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { authorizeAndGetCode, buildOidcTestApp, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

const CLIENT_ID = "base44-web";
const REDIRECT_URI = "https://example.com/callback";

function mockIdentityContextFetch(): void {
		vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: vi.fn().mockResolvedValue({
								success: true,
								requestId: "native-public-client-cert",
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

// Reconfigures the seeded test client as a secretless native-style public client with PKCE required.
async function buildPublicClientApp(): Promise<{ app: FastifyInstance }> {
		mockIdentityContextFetch();
		const { app } = await buildOidcTestApp();
		const record = await inMemoryOIDCClientRepository.findByClientId(CLIENT_ID);
		if (!record) throw new Error("OIDC test client was not seeded");
		await inMemoryOIDCClientRepository.upsert({
				...record,
				clientSecret: "",
				tokenEndpointAuthMethod: "none",
				requirePkce: true
		});
		return { app };
}

// Token exchange exactly as a native public client performs it: no client secret anywhere.
function exchangeAsPublicClient(
		app: FastifyInstance,
		input: { code: string; verifier?: string; clientId?: string; redirectUri?: string }
) {
		const body = new URLSearchParams({
				grant_type: "authorization_code",
				code: input.code,
				redirect_uri: input.redirectUri ?? REDIRECT_URI,
				client_id: input.clientId ?? CLIENT_ID,
				...(input.verifier !== undefined ? { code_verifier: input.verifier } : {})
		});
		return app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
		});
}

describe("V2-B Phase 3: native public-client certification", () => {
		afterEach(() => {
				vi.useRealTimers();
				vi.unstubAllGlobals();
		});

		it("completes the Authorization Code + PKCE S256 flow with token_endpoint_auth_method=none and no secret", async () => {
				const { app } = await buildPublicClientApp();
				const verifier = "native-public-happy-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const response = await exchangeAsPublicClient(app, { code, verifier });

				expect(response.statusCode).toBe(200);
				const payload = response.json();
				expect(payload).toMatchObject({ token_type: "Bearer" });
				expect(typeof payload.access_token).toBe("string");
				expect(typeof payload.id_token).toBe("string");
				await app.close();
		});

		it("requires PKCE at authorization and rejects an invalid verifier at token exchange", async () => {
				const { app } = await buildPublicClientApp();

				const missingChallenge = await app.inject({
						method: "GET",
						url: `/authorize?${new URLSearchParams({
								response_type: "code",
								client_id: CLIENT_ID,
								redirect_uri: REDIRECT_URI,
								scope: "openid profile email",
								state: "native-cert-state",
								nonce: "native-cert-nonce"
						})}`
				});
				expect(missingChallenge.statusCode).toBe(400);
				expect(missingChallenge.json()).toMatchObject({ error: "invalid_request" });

				const verifier = "native-public-pkce-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier, {
						codeChallenge: pkceChallengeFromVerifier(verifier)
				});

				const wrongVerifier = await exchangeAsPublicClient(app, { code, verifier: "a-different-verifier-123456" });
				expect(wrongVerifier.statusCode).toBe(400);
				expect(wrongVerifier.json()).toMatchObject({ error: "invalid_grant" });

				const missingVerifier = await exchangeAsPublicClient(app, { code });
				expect(missingVerifier.statusCode).toBe(400);
				await app.close();
		});

		it("rejects authorization-code replay: the second exchange of the same code fails closed", async () => {
				const { app } = await buildPublicClientApp();
				const verifier = "native-public-replay-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const first = await exchangeAsPublicClient(app, { code, verifier });
				expect(first.statusCode).toBe(200);

				const replay = await exchangeAsPublicClient(app, { code, verifier });
				expect(replay.statusCode).toBe(400);
				expect(replay.json()).toMatchObject({ error: "invalid_grant" });
				await app.close();
		});

		it("rejects token exchange by a client other than the one the code was issued to", async () => {
				const { app } = await buildPublicClientApp();
				const verifier = "native-public-wrong-client-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const response = await exchangeAsPublicClient(app, {
						code,
						verifier,
						clientId: "some-other-native-client"
				});

				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "invalid_client" });
				await app.close();
		});

		it("enforces exact redirect URI matching at authorization and token exchange", async () => {
				const { app } = await buildPublicClientApp();
				const verifier = "native-public-redirect-verifier-123456";

				// A near-miss variant of the registered URI is rejected up front at /authorize.
				const nearMiss = await app.inject({
						method: "GET",
						url: `/authorize?${new URLSearchParams({
								response_type: "code",
								client_id: CLIENT_ID,
								redirect_uri: `${REDIRECT_URI}/`,
								scope: "openid profile email",
								state: "native-cert-state",
								nonce: "native-cert-nonce",
								code_challenge: pkceChallengeFromVerifier(verifier),
								code_challenge_method: "S256"
						})}`
				});
				expect(nearMiss.statusCode).toBe(400);

				const code = await authorizeAndGetCode(app, verifier);
				const mismatched = await exchangeAsPublicClient(app, {
						code,
						verifier,
						redirectUri: `${REDIRECT_URI}/`
				});
				expect(mismatched.statusCode).toBe(400);
				expect(mismatched.json()).toMatchObject({ error: "invalid_grant" });
				await app.close();
		});

		it("rejects an expired authorization code", async () => {
				const { app } = await buildPublicClientApp();
				const verifier = "native-public-expiry-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				// Advance only Date past the 60s code TTL; the stored record is still present, so this
				// exercises the server-side expiresAt check rather than storage eviction.
				vi.useFakeTimers({ now: Date.now(), toFake: ["Date"] });
				vi.setSystemTime(Date.now() + 61_000);

				const response = await exchangeAsPublicClient(app, { code, verifier });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "invalid_grant" });
				await app.close();
		});
});
