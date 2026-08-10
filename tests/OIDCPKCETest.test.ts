import { afterEach, describe, expect, it, vi } from "vitest";

import {
		authorizeAndGetCode,
		buildOidcTestApp,
		exchangeAuthorizationCode,
		pkceChallengeFromVerifier
} from "./oidcTestHarness.js";

describe("OIDCPKCETest", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("rejects plain PKCE method", async () => {
				const { app } = await buildOidcTestApp();
				const response = await app.inject({
						method: "GET",
						url: "/authorize?response_type=code&client_id=base44-web&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20profile&state=pkce&nonce=pkce-nonce&code_challenge_method=plain&code_challenge=abc123"
				});

				expect(response.statusCode).toBe(400);
				expect(response.body).toContain("PKCE plain is not supported");
				await app.close();
		});

		it("automatically validates S256 verifier at token exchange", async () => {
				const fetchMock = vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: vi.fn().mockResolvedValue({
								success: true,
								requestId: "identity-3",
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
				} as unknown as Response);
				vi.stubGlobal("fetch", fetchMock);

				const { app } = await buildOidcTestApp();
				const validVerifier = "pkce-valid-verifier-123456";
				const code = await authorizeAndGetCode(app, validVerifier, {
						codeChallenge: pkceChallengeFromVerifier(validVerifier),
						codeChallengeMethod: "S256"
				});

				const invalidVerifierResponse = await exchangeAuthorizationCode(app, code, "different-verifier");
				expect(invalidVerifierResponse.statusCode).toBe(400);
				expect(invalidVerifierResponse.body).toContain("PKCE validation failed");

				await app.close();
		});
});
