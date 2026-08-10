import { afterEach, describe, expect, it, vi } from "vitest";

import { buildOidcTestApp } from "./oidcTestHarness.js";

describe("OIDCDiscovery", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("serves discovery metadata with Bookwrm issuer", async () => {
				const { app } = await buildOidcTestApp();

				const response = await app.inject({
						method: "GET",
						url: "/.well-known/openid-configuration"
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload.issuer).toBe("https://identity.bookwrm.com");
				expect(payload.authorization_endpoint).toBe("https://identity.bookwrm.com/authorize");
				expect(payload.token_endpoint).toBe("https://identity.bookwrm.com/token");
				expect(payload.userinfo_endpoint).toBe("https://identity.bookwrm.com/userinfo");
				expect(payload.jwks_uri).toBe("https://identity.bookwrm.com/jwks");

				await app.close();
		});
});
