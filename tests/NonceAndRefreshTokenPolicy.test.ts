// HAPI ID V2-B Phase 4: nonce fail-fast enforcement and the interim refresh-token policy.
// Nonce has always been mandatory at token exchange (codes without one could never be exchanged);
// V2-B surfaces that existing requirement at /authorize. Refresh tokens are only issued when the
// client registration explicitly includes the refresh_token grant -- no refresh grant exists yet.
import { afterEach, describe, expect, it, vi } from "vitest";

import { inMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import {
		authorizeAndGetCode,
		buildOidcTestApp,
		exchangeAuthorizationCode,
		pkceChallengeFromVerifier
} from "./oidcTestHarness.js";

function mockIdentityContextFetch(): void {
		vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: vi.fn().mockResolvedValue({
								success: true,
								requestId: "nonce-refresh-policy",
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

describe("V2-B Phase 4: nonce enforcement", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("rejects an authorization request without a nonce up front at /authorize", async () => {
				const { app } = await buildOidcTestApp();
				const verifier = "nonce-fail-fast-verifier-123456";

				const response = await app.inject({
						method: "GET",
						url: `/authorize?${new URLSearchParams({
								response_type: "code",
								client_id: "base44-web",
								redirect_uri: "https://example.com/callback",
								scope: "openid profile email",
								state: "nonce-test-state",
								code_challenge: pkceChallengeFromVerifier(verifier),
								code_challenge_method: "S256"
						})}`
				});

				expect(response.statusCode).toBe(400);
				expect(response.json()).toMatchObject({ error: "invalid_request" });
				expect(response.body).toContain("nonce is required");
				await app.close();
		});

		it("reflects the client's nonce in the issued ID Token", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "nonce-reflection-verifier-123456";
				const nonce = "client-chosen-nonce-value";
				const code = await authorizeAndGetCode(app, verifier, { nonce });

				const response = await exchangeAuthorizationCode(app, code, verifier);
				expect(response.statusCode).toBe(200);
				const idToken = response.json().id_token as string;
				const claims = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString());
				expect(claims.nonce).toBe(nonce);
				await app.close();
		});
});

describe("V2-B Phase 4: interim refresh-token policy", () => {
		afterEach(() => {
				vi.unstubAllGlobals();
		});

		it("keeps issuing a refresh token for the legacy client whose registration includes refresh_token", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const verifier = "refresh-legacy-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const response = await exchangeAuthorizationCode(app, code, verifier);
				expect(response.statusCode).toBe(200);
				expect(typeof response.json().refresh_token).toBe("string");
				await app.close();
		});

		it("does not issue a refresh token to a client registered without the refresh_token grant", async () => {
				mockIdentityContextFetch();
				const { app } = await buildOidcTestApp();
				const record = await inMemoryOIDCClientRepository.findByClientId("base44-web");
				if (!record) throw new Error("OIDC test client was not seeded");
				await inMemoryOIDCClientRepository.upsert({ ...record, grantTypes: ["authorization_code"] });

				const verifier = "refresh-restricted-verifier-123456";
				const code = await authorizeAndGetCode(app, verifier);

				const response = await exchangeAuthorizationCode(app, code, verifier);
				expect(response.statusCode).toBe(200);
				const payload = response.json();
				expect(payload.refresh_token).toBeUndefined();
				expect(typeof payload.access_token).toBe("string");
				expect(typeof payload.id_token).toBe("string");
				await app.close();
		});
});
