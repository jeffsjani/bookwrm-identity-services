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
});
