import { afterEach, describe, expect, it, vi } from "vitest";

import { authorizeAndGetCode, buildOidcTestApp, exchangeAuthorizationCode } from "./oidcTestHarness.js";

function mockIdentityContextFetch(): void {
		const responsePayload = {
				success: true,
				requestId: "identity-1",
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

describe("OIDCToken", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("exchanges authorization code and returns id/access/refresh tokens", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "oidc-token-verifier-123456789";
				const code = await authorizeAndGetCode(app, verifier);

				const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
				expect(tokenResponse.statusCode).toBe(200);
				const payload = tokenResponse.json() as Record<string, unknown>;
				expect(payload.token_type).toBe("Bearer");
				expect(typeof payload.id_token).toBe("string");
				expect(typeof payload.access_token).toBe("string");
				expect(typeof payload.refresh_token).toBe("string");

				await app.close();
		});

		it("validates Base44 integration chain after authenticated session", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "base44-integration-verifier-123";
				const code = await authorizeAndGetCode(app, verifier);
				await exchangeAuthorizationCode(app, code, verifier);

				const diagnosticsResponse = await app.inject({
						method: "GET",
						url: "/diagnostics/oidc/base44"
				});
				expect(diagnosticsResponse.statusCode).toBe(200);

				const diagnostics = diagnosticsResponse.json() as Record<string, unknown>;
				expect(diagnostics.issuer).toBe("https://identity.bookwrm.com");
				expect(diagnostics.clientConfigured).toBe(true);
				expect(diagnostics.base44ToOidc).toBe(true);
				expect(diagnostics.oidcToBookwrmIdentityServices).toBe(true);
				expect(diagnostics.authenticatedSession).toBe(true);

				await app.close();
		});
});
