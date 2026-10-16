import { afterEach, describe, expect, it, vi } from "vitest";

import { inMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { authorizeAndGetCode, buildOidcTestApp, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

const BASE44_CLIENT_ID = "base44-web";
const BASE44_CLIENT_SECRET = "base44-secret";
const BASE44_REDIRECT_URI = "https://example.com/callback";

function basicAuthHeader(clientId: string, clientSecret: string): string {
		return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

function mockIdentityContextFetch(): void {
		vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: vi.fn().mockResolvedValue({
								success: true,
								requestId: "identity-token-auth",
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

describe("OIDC /token client authentication", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("authenticates via client_secret_basic Authorization header without body client_id", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "token-auth-basic-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const body = new URLSearchParams({
						grant_type: "authorization_code",
						code,
						redirect_uri: BASE44_REDIRECT_URI,
						code_verifier: verifier
				});

				const response = await app.inject({
						method: "POST",
						url: "/token",
						headers: {
								"content-type": "application/x-www-form-urlencoded",
								authorization: basicAuthHeader(BASE44_CLIENT_ID, BASE44_CLIENT_SECRET)
						},
						payload: body.toString()
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload.token_type).toBe("Bearer");
				expect(typeof payload.access_token).toBe("string");

				await app.close();
		});

		it("authenticates via client_secret_post body credentials", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "token-auth-post-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const body = new URLSearchParams({
						grant_type: "authorization_code",
						code,
						redirect_uri: BASE44_REDIRECT_URI,
						client_id: BASE44_CLIENT_ID,
						client_secret: BASE44_CLIENT_SECRET,
						code_verifier: verifier
				});

				const response = await app.inject({
						method: "POST",
						url: "/token",
						headers: {
								"content-type": "application/x-www-form-urlencoded"
						},
						payload: body.toString()
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload.token_type).toBe("Bearer");

				await app.close();
		});

		it("returns invalid_client when neither Authorization header nor body client_id are present", async () => {
				const { app } = await buildOidcTestApp();
				const verifier = "token-auth-missing-client-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const body = new URLSearchParams({
						grant_type: "authorization_code",
						code,
						redirect_uri: BASE44_REDIRECT_URI,
						code_verifier: verifier
				});

				const response = await app.inject({
						method: "POST",
						url: "/token",
						headers: {
								"content-type": "application/x-www-form-urlencoded"
						},
						payload: body.toString()
				});

				expect(response.statusCode).toBe(400);
				const payload = response.json() as Record<string, unknown>;
				expect(payload.error).toBe("invalid_client");

				await app.close();
		});

		it("does not require body client_id when Authorization: Basic is present", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "token-auth-basic-no-body-id-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const body = new URLSearchParams({
						grant_type: "authorization_code",
						code,
						redirect_uri: BASE44_REDIRECT_URI,
						code_verifier: verifier
				});
				expect(body.has("client_id")).toBe(false);

				const response = await app.inject({
						method: "POST",
						url: "/token",
						headers: {
								"content-type": "application/x-www-form-urlencoded",
								authorization: basicAuthHeader(BASE44_CLIENT_ID, BASE44_CLIENT_SECRET)
						},
						payload: body.toString()
				});

				expect(response.statusCode).toBe(200);

				await app.close();
		});

		it("still validates PKCE when authenticating via client_secret_basic", async () => {
				const { app } = await buildOidcTestApp();
				const verifier = "token-auth-pkce-valid-verifier-123";
				const code = await authorizeAndGetCode(app, verifier, {
						codeChallenge: pkceChallengeFromVerifier(verifier),
						codeChallengeMethod: "S256"
				});

				const body = new URLSearchParams({
						grant_type: "authorization_code",
						code,
						redirect_uri: BASE44_REDIRECT_URI,
						code_verifier: "wrong-verifier-does-not-match"
				});

				const response = await app.inject({
						method: "POST",
						url: "/token",
						headers: {
								"content-type": "application/x-www-form-urlencoded",
								authorization: basicAuthHeader(BASE44_CLIENT_ID, BASE44_CLIENT_SECRET)
						},
						payload: body.toString()
				});

				expect(response.statusCode).toBe(400);
				const payload = response.json() as Record<string, unknown>;
				expect(payload.error_description).toContain("PKCE validation failed");

				await app.close();
		});

		it("rejects a confidential client with a wrong supplied secret", async () => {
			const { app } = await buildOidcTestApp();
			const verifier = "token-auth-wrong-secret-verifier-123";
			const code = await authorizeAndGetCode(app, verifier);
			const body = new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: BASE44_REDIRECT_URI,
				client_id: BASE44_CLIENT_ID,
				client_secret: "incorrect-secret",
				code_verifier: verifier
			});

			const response = await app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
			});

			expect(response.statusCode).toBe(400);
			expect(response.json()).toMatchObject({ error: "invalid_client" });
			await app.close();
		});

		it("rejects a confidential client when the supplied secret is absent", async () => {
			const { app } = await buildOidcTestApp();
			const verifier = "token-auth-missing-secret-verifier-123";
			const code = await authorizeAndGetCode(app, verifier);
			const body = new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: BASE44_REDIRECT_URI,
				client_id: BASE44_CLIENT_ID,
				code_verifier: verifier
			});

			const response = await app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
			});

			expect(response.statusCode).toBe(400);
			expect(response.json()).toMatchObject({ error: "invalid_client" });
			await app.close();
		});

		it("rejects a confidential client with an empty configured secret", async () => {
			const { app } = await buildOidcTestApp();
			const verifier = "token-auth-empty-configured-secret-123";
			const code = await authorizeAndGetCode(app, verifier);
			const record = await inMemoryOIDCClientRepository.findByClientId(BASE44_CLIENT_ID);
			if (!record) throw new Error("OIDC test client was not seeded");
			await inMemoryOIDCClientRepository.upsert({ ...record, clientSecret: "" });

			const body = new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: BASE44_REDIRECT_URI,
				client_id: BASE44_CLIENT_ID,
				client_secret: BASE44_CLIENT_SECRET,
				code_verifier: verifier
			});
			const response = await app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
			});

			expect(response.statusCode).toBe(400);
			expect(response.json()).toMatchObject({ error: "invalid_client" });
			await app.close();
		});

		it("authenticates an explicitly public client without a secret and enforces PKCE S256", async () => {
			const { app } = await buildOidcTestApp();
			const record = await inMemoryOIDCClientRepository.findByClientId(BASE44_CLIENT_ID);
			if (!record) throw new Error("OIDC test client was not seeded");
			await inMemoryOIDCClientRepository.upsert({
				...record,
				clientSecret: "",
				tokenEndpointAuthMethod: "none",
				requirePkce: false
			});

			const missingChallenge = await app.inject({
				method: "GET",
				url: `/authorize?${new URLSearchParams({
					response_type: "code",
					client_id: BASE44_CLIENT_ID,
					redirect_uri: BASE44_REDIRECT_URI,
					scope: "openid profile email",
					state: "public-client-state",
					nonce: "public-client-nonce"
				})}`
			});
			expect(missingChallenge.statusCode).toBe(400);
			expect(missingChallenge.json()).toMatchObject({ error: "invalid_request" });

			const verifier = "token-auth-public-pkce-verifier-123456";
			const code = await authorizeAndGetCode(app, verifier);
			const body = new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: BASE44_REDIRECT_URI,
				client_id: BASE44_CLIENT_ID,
				code_verifier: verifier
			});
			const response = await app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
			});

			expect(response.statusCode).toBe(200);
			expect(response.json()).toMatchObject({ token_type: "Bearer" });
			await app.close();
		});

		it("rejects empty client redirect lists at authorization and token exchange", async () => {
			const { app } = await buildOidcTestApp();
			const verifier = "redirect-empty-list-verifier-123456";
			const invalidRedirect = await app.inject({
				method: "GET",
				url: `/authorize?${new URLSearchParams({
					response_type: "code",
					client_id: BASE44_CLIENT_ID,
					redirect_uri: "https://attacker.example/callback",
					scope: "openid profile email",
					state: "invalid-redirect-state",
					nonce: "invalid-redirect-nonce",
					code_challenge: pkceChallengeFromVerifier(verifier),
					code_challenge_method: "S256"
				})}`
			});
			expect(invalidRedirect.statusCode).toBe(400);

			const record = await inMemoryOIDCClientRepository.findByClientId(BASE44_CLIENT_ID);
			if (!record) throw new Error("OIDC test client was not seeded");
			await inMemoryOIDCClientRepository.upsert({ ...record, redirectUris: [] });
			const emptyListAuthorization = await app.inject({
				method: "GET",
				url: `/authorize?${new URLSearchParams({
					response_type: "code",
					client_id: BASE44_CLIENT_ID,
					redirect_uri: BASE44_REDIRECT_URI,
					scope: "openid profile email",
					state: "empty-redirect-state",
					nonce: "empty-redirect-nonce",
					code_challenge: pkceChallengeFromVerifier(verifier),
					code_challenge_method: "S256"
				})}`
			});
			expect(emptyListAuthorization.statusCode).toBe(400);

			await inMemoryOIDCClientRepository.upsert(record);
			const code = await authorizeAndGetCode(app, verifier);
			await inMemoryOIDCClientRepository.upsert({ ...record, redirectUris: [] });

			const body = new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: BASE44_REDIRECT_URI,
				client_id: BASE44_CLIENT_ID,
				client_secret: BASE44_CLIENT_SECRET,
				code_verifier: verifier
			});
			const response = await app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: body.toString()
			});

			expect(response.statusCode).toBe(400);
			expect(response.json()).toMatchObject({ error: "invalid_grant" });
			await app.close();
		});
});
