import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { inMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { authorizeAndGetCode, buildOidcTestApp, exchangeAuthorizationCode, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

const clientId = "base44-web";
const redirectUri = "https://example.com/callback";

function mockIdentityContextFetch(): void {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
		ok: true,
		status: 200,
		json: vi.fn().mockResolvedValue({
			success: true,
			requestId: "synthetic-client-suspension",
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
	} as unknown as Response));
}

afterEach(() => {
	delete process.env.HAPI_REFRESH_GRANT_ENABLED;
	configuration.reload();
	vi.unstubAllGlobals();
});

describe("OIDC client suspension", () => {
	it("takes effect immediately for authorization, code exchange, refresh, and previously issued access tokens", async () => {
		mockIdentityContextFetch();
		process.env.HAPI_REFRESH_GRANT_ENABLED = "true";
		configuration.reload();
		const { app } = await buildOidcTestApp();
		const originalClient = await inMemoryOIDCClientRepository.findByClientId(clientId);
		if (!originalClient) throw new Error("OIDC test client was not seeded");
		const unrelatedClientId = `active-${randomUUID()}`;

		try {
			await inMemoryOIDCClientRepository.upsert({ ...originalClient, status: "active" });
			const verifier = "suspension-issued-token-verifier-123";
			const pendingVerifier = "suspension-pending-code-verifier-123";
			const code = await authorizeAndGetCode(app, verifier);
			const tokensResponse = await exchangeAuthorizationCode(app, code, verifier);
			expect(tokensResponse.statusCode).toBe(200);
			const tokens = tokensResponse.json() as { access_token: string; refresh_token: string };
			expect(tokens.refresh_token).toBeTruthy();

			const pendingCode = await authorizeAndGetCode(app, pendingVerifier);
			const activeUserInfo = await app.inject({
				method: "GET",
				url: "/userinfo",
				headers: { authorization: `Bearer ${tokens.access_token}` }
			});
			expect(activeUserInfo.statusCode).toBe(200);

			const unrelatedClient = await inMemoryOIDCClientRepository.upsert({
				...originalClient,
				id: randomUUID(),
				clientId: unrelatedClientId,
				clientSecret: "synthetic-unrelated-secret",
				status: "active"
			});

			await inMemoryOIDCClientRepository.upsert({ ...originalClient, status: "suspended" });

			const query = new URLSearchParams({
				response_type: "code",
				client_id: clientId,
				redirect_uri: redirectUri,
				scope: "openid profile email",
				state: "suspended-client-state",
				nonce: "suspended-client-nonce",
				code_challenge_method: "S256",
				code_challenge: pkceChallengeFromVerifier("suspended-client-new-flow-verifier")
			});
			const authorization = await app.inject({ method: "GET", url: `/authorize?${query}` });
			expect(authorization.statusCode).toBe(400);
			expect(authorization.json()).toMatchObject({ error: "invalid_client" });

			const codeExchange = await exchangeAuthorizationCode(app, pendingCode, pendingVerifier);
			expect(codeExchange.statusCode).toBe(400);
			expect(codeExchange.json()).toMatchObject({ error: "invalid_client" });

			const refresh = await app.inject({
				method: "POST",
				url: "/token",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: tokens.refresh_token,
					client_id: clientId,
					client_secret: originalClient.clientSecret
				}).toString()
			});
			expect(refresh.statusCode).toBe(400);
			expect(refresh.json()).toMatchObject({ error: "invalid_client" });

			const userInfo = await app.inject({
				method: "GET",
				url: "/userinfo",
				headers: { authorization: `Bearer ${tokens.access_token}` }
			});
			expect(userInfo.statusCode).toBe(401);
			expect(userInfo.json()).toMatchObject({ error: "invalid_token" });

			const unrelatedVerifier = "unrelated-active-client-verifier-123";
			const unrelatedCode = await authorizeAndGetCode(app, unrelatedVerifier, {
				clientId: unrelatedClient.clientId,
				redirectUri
			});
			const unrelatedToken = await exchangeAuthorizationCode(app, unrelatedCode, unrelatedVerifier, {
				clientId: unrelatedClient.clientId,
				clientSecret: unrelatedClient.clientSecret,
				redirectUri
			});
			expect(unrelatedToken.statusCode).toBe(200);
			const unrelatedAccessToken = unrelatedToken.json().access_token as string;
			const unrelatedUserInfo = await app.inject({
				method: "GET",
				url: "/userinfo",
				headers: { authorization: `Bearer ${unrelatedAccessToken}` }
			});
			expect(unrelatedUserInfo.statusCode).toBe(200);
		} finally {
			await inMemoryOIDCClientRepository.upsert({ ...originalClient, status: originalClient.status });
			await app.close();
		}
	});
});
