import { describe, expect, it } from "vitest";

import { buildOidcTestApp } from "./oidcTestHarness.js";

describe("OIDCJWKSTest", () => {
		it("returns RS256 public JWKS keys", async () => {
				const { app } = await buildOidcTestApp();

				const response = await app.inject({
						method: "GET",
						url: "/jwks"
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as { keys: Array<Record<string, unknown>> };
				expect(Array.isArray(payload.keys)).toBe(true);
				expect(payload.keys.length).toBeGreaterThan(0);

				const firstKey = payload.keys[0];
				expect(firstKey.kty).toBe("RSA");
				expect(firstKey.alg).toBe("RS256");
				expect(firstKey.use).toBe("sig");
				expect(typeof firstKey.kid).toBe("string");
				expect(typeof firstKey.n).toBe("string");
				expect(typeof firstKey.e).toBe("string");
				expect(firstKey.d).toBeUndefined();

				await app.close();
		});

		it("generates a local signing key when no JWT signing config is configured in development", async () => {
				const previousNodeEnv = process.env.NODE_ENV;
				const previousJwtPrivateKey = process.env.JWT_PRIVATE_KEY;
				const previousOidcJwksJson = process.env.OIDC_JWKS_JSON;
				delete process.env.JWT_PRIVATE_KEY;
				delete process.env.OIDC_JWKS_JSON;
				process.env.NODE_ENV = "development";

				try {
					const { oidcService } = await import("../src/oidc/OIDCService.js");
					const app = (await import("fastify")).default();
					await oidcService.registerEndpoints(app);

					const response = await app.inject({
						method: "GET",
						url: "/jwks"
					});

					expect(response.statusCode).toBe(200);
					const payload = response.json() as { keys: Array<Record<string, unknown>> };
					expect(Array.isArray(payload.keys)).toBe(true);
					expect(payload.keys.length).toBeGreaterThan(0);
					await app.close();
				} finally {
					if (previousJwtPrivateKey === undefined) {
						delete process.env.JWT_PRIVATE_KEY;
					} else {
						process.env.JWT_PRIVATE_KEY = previousJwtPrivateKey;
					}
					if (previousOidcJwksJson === undefined) {
						delete process.env.OIDC_JWKS_JSON;
					} else {
						process.env.OIDC_JWKS_JSON = previousOidcJwksJson;
					}
					if (previousNodeEnv === undefined) {
						delete process.env.NODE_ENV;
					} else {
						process.env.NODE_ENV = previousNodeEnv;
					}
				}
		});
});
