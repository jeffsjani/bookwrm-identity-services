import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";
import { getPrivateIDAuthenticatedUser, resolvePrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";
import type { PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";

const WEBHOOK_SECRET = "privateid-webhook-secret";

const STUB_PENDING_CONTEXT: PendingAuthorizationContext = {
		clientId: "base44-web",
		redirectUri: "https://example.com/callback",
		scope: "openid profile email",
		nonce: "test-nonce",
		codeChallenge: "test-challenge"
};

// Mirrors OIDCService.authorize(): stores the correlation, then launches the PrivateID session through the
// provider so the session is recorded as OIDC-origin and linked in the CorrelationStore, exactly as production does.
async function createOidcSession(correlationId: string): Promise<{ sessionId: string; transactionId: string }> {
		storeCorrelation(correlationId, STUB_PENDING_CONTEXT);
		const provider = new PrivateIDAuthenticationProvider();
		const { sessionId } = await provider.beginAsyncAuthentication(correlationId);
		const record = resolvePrivateIDSessionRecord(sessionId);
		if (!record) {
				throw new Error("Expected PrivateID session to be recorded after beginAsyncAuthentication");
		}

		return { sessionId, transactionId: record.session.transactionId };
}

async function sendSuccessWebhook(
		app: Awaited<ReturnType<typeof buildOidcTestApp>>["app"],
		sessionId: string,
		transactionId: string,
		privateIdUserId: string,
		correlationId: string
) {
		return app.inject({
				method: "POST",
				url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": WEBHOOK_SECRET },
				payload: {
						status: "SUCCESS",
						sessionId,
						transactionId,
						privateIdUserId,
						metadata: { correlationId }
				}
		});
}

describe("OIDC login identity resolution (RC1 Phase 3)", () => {
		it("creates a new IdentitySubject-backed sub for a first-time PrivateID login", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const privateIdUserId = `phase3-new-user-${randomUUID()}`;

				const response = await sendSuccessWebhook(app, session.sessionId, session.transactionId, privateIdUserId, correlationId);
				expect(response.statusCode).toBe(200);

				const authenticatedUser = getPrivateIDAuthenticatedUser(session.sessionId);
				expect(authenticatedUser).toBeDefined();
				expect(authenticatedUser?.sub).not.toBe(privateIdUserId);
				expect(authenticatedUser?.sub).not.toBe(session.transactionId);
				expect(authenticatedUser?.email).toBeUndefined();

				await app.close();
		});

		it("resolves the same sub for a returning PrivateID login from a different browser/session", async () => {
				const { app } = await buildOidcTestApp();
				const privateIdUserId = `phase3-returning-user-${randomUUID()}`;

				const firstCorrelationId = randomUUID();
				const firstSession = await createOidcSession(firstCorrelationId);
				await sendSuccessWebhook(app, firstSession.sessionId, firstSession.transactionId, privateIdUserId, firstCorrelationId);
				const firstUser = getPrivateIDAuthenticatedUser(firstSession.sessionId);

				// Different PrivateID session/transaction entirely -- simulates a new browser.
				const secondCorrelationId = randomUUID();
				const secondSession = await createOidcSession(secondCorrelationId);
				await sendSuccessWebhook(app, secondSession.sessionId, secondSession.transactionId, privateIdUserId, secondCorrelationId);
				const secondUser = getPrivateIDAuthenticatedUser(secondSession.sessionId);

				expect(secondUser?.sub).toBe(firstUser?.sub);
				expect(secondUser?.email).toBe(firstUser?.email);

				await app.close();
		});

		it("keeps IdentitySubject.email stable even if a later login carries a different candidate email", async () => {
				const { app } = await buildOidcTestApp();
				const privateIdUserId = `phase3-stable-email-${randomUUID()}`;

				const firstCorrelationId = randomUUID();
				const firstSession = await createOidcSession(firstCorrelationId);
				await sendSuccessWebhook(app, firstSession.sessionId, firstSession.transactionId, privateIdUserId, firstCorrelationId);
				const firstUser = getPrivateIDAuthenticatedUser(firstSession.sessionId);

				const secondCorrelationId = randomUUID();
				const secondSession = await createOidcSession(secondCorrelationId);
				const response = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: { "x-storythink-webhook-secret": WEBHOOK_SECRET },
						payload: {
								status: "SUCCESS",
								sessionId: secondSession.sessionId,
								transactionId: secondSession.transactionId,
								privateIdUserId,
								email: "different-candidate-email@example.com",
								emailVerified: true,
								metadata: { correlationId: secondCorrelationId }
						}
				});
				expect(response.statusCode).toBe(200);
				const secondUser = getPrivateIDAuthenticatedUser(secondSession.sessionId);

				expect(secondUser?.email).toBe(firstUser?.email);
				expect(secondUser?.sub).toBe(firstUser?.sub);

				await app.close();
		});
});
