import { afterEach, describe, expect, it, vi } from "vitest";

import { authorizeAndGetCode, buildOidcTestApp, exchangeAuthorizationCode } from "./oidcTestHarness.js";

function mockIdentityContextFetch(): void {
		const responsePayload = {
				success: true,
				requestId: "identity-2",
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
		};

		vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: vi.fn().mockResolvedValue(responsePayload)
				} as unknown as Response)
		);
}

describe("OIDCUserInfo", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("returns sub, email, email_verified, and name for valid access token", async () => {
				mockIdentityContextFetch();
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
				expect(payload).toEqual({
					sub: "dev-user-1",
					email: "dev.user@bookwrm.local",
					email_verified: true,
					name: "Dev User"
				});

				await app.close();
		});
});
