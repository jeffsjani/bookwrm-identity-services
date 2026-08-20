import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { buildOidcTestApp, exchangeAuthorizationCode, pkceChallengeFromVerifier } from "./oidcTestHarness.js";
import { getPrivateIDAuthenticatedUser, resolvePrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import type { PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";

const WEBHOOK_SECRET = "privateid-webhook-secret";
const VERIFIER = "live-claim-verifier-123456789";
const CODE_CHALLENGE = pkceChallengeFromVerifier(VERIFIER);

const STUB_PENDING_CONTEXT: PendingAuthorizationContext = {
		clientId: "base44-web",
		redirectUri: "https://example.com/callback",
		scope: "openid profile email",
		nonce: "live-claim-nonce",
		codeChallenge: CODE_CHALLENGE
};

async function createOidcSession(app: Awaited<ReturnType<typeof buildOidcTestApp>>["app"], privateIdUserId: string) {
		const correlationId = randomUUID();
		storeCorrelation(correlationId, STUB_PENDING_CONTEXT);
		const provider = new PrivateIDAuthenticationProvider();
		const { sessionId } = await provider.beginAsyncAuthentication(correlationId);
		const record = resolvePrivateIDSessionRecord(sessionId);
		if (!record) {
				throw new Error("Expected PrivateID session to be recorded after beginAsyncAuthentication");
		}

		const webhookResponse = await app.inject({
				method: "POST",
				url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": WEBHOOK_SECRET },
				payload: {
						status: "SUCCESS",
						sessionId,
						transactionId: record.session.transactionId,
						privateIdUserId,
						metadata: { correlationId }
				}
		});
		if (webhookResponse.statusCode !== 200) {
				throw new Error(`Webhook failed: ${webhookResponse.statusCode} ${webhookResponse.body}`);
		}

		const callbackResponse = await app.inject({
				method: "GET",
				url: `/privateid/callback?reason=success&sessionId=${encodeURIComponent(sessionId)}&transactionId=${encodeURIComponent(record.session.transactionId)}`
		});
		if (callbackResponse.statusCode !== 302 || !callbackResponse.headers.location) {
				throw new Error(`Callback failed: ${callbackResponse.statusCode} ${callbackResponse.body}`);
		}

		const code = new URL(callbackResponse.headers.location as string).searchParams.get("code");
		if (!code) {
				throw new Error("Callback redirect missing code parameter");
		}

		const authenticatedUser = getPrivateIDAuthenticatedUser(sessionId);
		if (!authenticatedUser) {
				throw new Error("Expected authenticated user to be recorded after webhook processing");
		}

		return { code, oidcSubject: authenticatedUser.sub };
}

function decodeIdTokenPayload(idToken: string): Record<string, unknown> {
		const [, payloadB64] = idToken.split(".");
		return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
}

describe("Release Patch 6.1: live claim resolution at token issuance", () => {
		it("Case 1: /token reflects an Identity Registry update made after the authorization code was issued", async () => {
				const { app } = await buildOidcTestApp();
				const { code, oidcSubject } = await createOidcSession(app, `patch6-case1-${randomUUID()}`);

				await identityRegistry.applyClaimUpdate(oidcSubject, {
						email: "case1-updated@bookwrm.local",
						emailVerified: true,
						displayName: "Case One"
				});

				const tokenResponse = await exchangeAuthorizationCode(app, code, VERIFIER);
				expect(tokenResponse.statusCode).toBe(200);
				const tokens = tokenResponse.json() as Record<string, unknown>;
				const idTokenPayload = decodeIdTokenPayload(String(tokens.id_token));

				expect(idTokenPayload.email).toBe("case1-updated@bookwrm.local");
				expect(idTokenPayload.email_verified).toBe(true);
				expect(idTokenPayload.name).toBe("Case One");

				await app.close();
		});

		it("Case 2: /userinfo reflects an Identity Registry update made after the authorization code was issued", async () => {
				const { app } = await buildOidcTestApp();
				const { code, oidcSubject } = await createOidcSession(app, `patch6-case2-${randomUUID()}`);

				await identityRegistry.applyClaimUpdate(oidcSubject, {
						email: "case2-updated@bookwrm.local",
						emailVerified: true,
						displayName: "Case Two"
				});

				const tokenResponse = await exchangeAuthorizationCode(app, code, VERIFIER);
				const tokens = tokenResponse.json() as Record<string, unknown>;

				const userInfoResponse = await app.inject({
						method: "GET",
						url: "/userinfo",
						headers: { authorization: `Bearer ${String(tokens.access_token)}` }
				});
				expect(userInfoResponse.statusCode).toBe(200);
				const payload = userInfoResponse.json() as Record<string, unknown>;

				expect(payload.email).toBe("case2-updated@bookwrm.local");
				expect(payload.email_verified).toBe(true);
				expect(payload.name).toBe("Case Two");

				await app.close();
		});

		it("Case 3: returning user with no registry changes sees no regression in ID Token / UserInfo claims", async () => {
				const { app } = await buildOidcTestApp();
				const privateIdUserId = `patch6-case3-${randomUUID()}`;

				const first = await createOidcSession(app, privateIdUserId);
				await identityRegistry.applyClaimUpdate(first.oidcSubject, {
						email: "case3-stable@bookwrm.local",
						emailVerified: true,
						displayName: "Case Three"
				});
				await exchangeAuthorizationCode(app, first.code, VERIFIER);

				// Simulate a returning login: same PrivateID user, new PrivateID session, no registry changes in between.
				const second = await createOidcSession(app, privateIdUserId);
				expect(second.oidcSubject).toBe(first.oidcSubject);

				const tokenResponse = await exchangeAuthorizationCode(app, second.code, VERIFIER);
				expect(tokenResponse.statusCode).toBe(200);
				const tokens = tokenResponse.json() as Record<string, unknown>;
				const idTokenPayload = decodeIdTokenPayload(String(tokens.id_token));

				expect(idTokenPayload.sub).toBe(first.oidcSubject);
				expect(idTokenPayload.email).toBe("case3-stable@bookwrm.local");
				expect(idTokenPayload.email_verified).toBe(true);
				expect(idTokenPayload.name).toBe("Case Three");

				const userInfoResponse = await app.inject({
						method: "GET",
						url: "/userinfo",
						headers: { authorization: `Bearer ${String(tokens.access_token)}` }
				});
				const userInfoPayload = userInfoResponse.json() as Record<string, unknown>;
				expect(userInfoPayload.email).toBe("case3-stable@bookwrm.local");
				expect(userInfoPayload.email_verified).toBe(true);
				expect(userInfoPayload.name).toBe("Case Three");

				await app.close();
		});
});
