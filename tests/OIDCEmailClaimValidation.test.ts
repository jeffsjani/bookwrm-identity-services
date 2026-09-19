import { describe, expect, it } from "vitest";

import { authorizeAndGetCode, buildOidcTestApp, exchangeAuthorizationCode } from "./oidcTestHarness.js";

// Release C5.0: OIDC claims only -- sub/email/email_verified must be present on both the ID Token and
// the /userinfo response for an authenticated IdentitySubject. Email is an interoperability claim only;
// it is never used for identity resolution and sub remains authoritative.
describe("Release C5.0: OIDC email claim", () => {
		it("includes subPresent, emailPresent, and emailVerifiedPresent on the ID Token", async () => {
				const { app } = await buildOidcTestApp();
				const verifier = "email-claim-verifier-123456789";
				const code = await authorizeAndGetCode(app, verifier);
				const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
				const tokens = tokenResponse.json() as Record<string, unknown>;
				const idTokenPayload = JSON.parse(Buffer.from(String(tokens.id_token).split(".")[1], "base64url").toString("utf8")) as Record<string, unknown>;

				const subPresent = typeof idTokenPayload.sub === "string" && idTokenPayload.sub.length > 0;
				const emailPresent = typeof idTokenPayload.email === "string" && idTokenPayload.email.length > 0;
				const emailVerifiedPresent = typeof idTokenPayload.email_verified === "boolean";

				expect(subPresent).toBe(true);
				expect(emailPresent).toBe(true);
				expect(emailVerifiedPresent).toBe(true);

				await app.close();
		});

		it("includes subPresent, emailPresent, and emailVerifiedPresent on the /userinfo response", async () => {
				const { app } = await buildOidcTestApp();
				const verifier = "email-claim-verifier-userinfo-123456789";
				const code = await authorizeAndGetCode(app, verifier);
				const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
				const tokens = tokenResponse.json() as Record<string, unknown>;

				const userInfoResponse = await app.inject({
						method: "GET",
						url: "/userinfo",
						headers: { authorization: `Bearer ${String(tokens.access_token)}` }
				});
				expect(userInfoResponse.statusCode).toBe(200);
				const payload = userInfoResponse.json() as Record<string, unknown>;

				const subPresent = typeof payload.sub === "string" && payload.sub.length > 0;
				const emailPresent = typeof payload.email === "string" && payload.email.length > 0;
				const emailVerifiedPresent = typeof payload.email_verified === "boolean";

				expect(subPresent).toBe(true);
				expect(emailPresent).toBe(true);
				expect(emailVerifiedPresent).toBe(true);

				await app.close();
		});
});
