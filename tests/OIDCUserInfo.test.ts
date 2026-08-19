import { describe, expect, it } from "vitest";

import { authorizeAndGetCode, buildOidcTestApp, exchangeAuthorizationCode } from "./oidcTestHarness.js";

describe("OIDCUserInfo", () => {
		// Release Patch 5A: OIDC login resolves identity exclusively via IdentityRegistry, never the legacy
		// Bookwrm IdentityContext API, so `sub` is an IdentityRegistry-issued subject rather than the raw PrivateID user id.
		it("returns an IdentityRegistry-issued sub for a valid access token", async () => {
				const { app } = await buildOidcTestApp();
				const verifier = "userinfo-verifier-123456789";
				const code = await authorizeAndGetCode(app, verifier);
				const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
				const tokens = tokenResponse.json() as Record<string, unknown>;

				const userInfoResponse = await app.inject({
						method: "GET",
						url: "/userinfo",
						headers: {
								authorization: `Bearer ${String(tokens.access_token)}`
						}
				});

				expect(userInfoResponse.statusCode).toBe(200);
				const payload = userInfoResponse.json() as Record<string, unknown>;
				expect(typeof payload.sub).toBe("string");
				expect(payload.sub).not.toBe("dev-user-1");
				expect(payload.email).toBeUndefined();
				expect(payload.email_verified).toBeUndefined();
				expect(payload.name).toBeUndefined();

				await app.close();
		});
});
