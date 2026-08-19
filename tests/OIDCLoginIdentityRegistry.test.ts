import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDClient } from "../src/privateid/PrivateIDClient.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";
import { getPrivateIDAuthenticatedUser } from "../src/privateid/PrivateIDSessionStore.js";

const WEBHOOK_SECRET = "privateid-webhook-secret";

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
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();
				const privateIdUserId = `phase3-new-user-${randomUUID()}`;

				const response = await sendSuccessWebhook(app, session.sessionId, session.transactionId, privateIdUserId, randomUUID());
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
				const client = new PrivateIDClient();
				const privateIdUserId = `phase3-returning-user-${randomUUID()}`;

				const firstSession = await client.createAuthenticationSession();
				await sendSuccessWebhook(app, firstSession.sessionId, firstSession.transactionId, privateIdUserId, randomUUID());
				const firstUser = getPrivateIDAuthenticatedUser(firstSession.sessionId);

				// Different PrivateID session/transaction entirely -- simulates a new browser.
				const secondSession = await client.createAuthenticationSession();
				await sendSuccessWebhook(app, secondSession.sessionId, secondSession.transactionId, privateIdUserId, randomUUID());
				const secondUser = getPrivateIDAuthenticatedUser(secondSession.sessionId);

				expect(secondUser?.sub).toBe(firstUser?.sub);
				expect(secondUser?.email).toBe(firstUser?.email);

				await app.close();
		});

		it("keeps IdentitySubject.email stable even if a later login carries a different candidate email", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const privateIdUserId = `phase3-stable-email-${randomUUID()}`;

				const firstSession = await client.createAuthenticationSession();
				await sendSuccessWebhook(app, firstSession.sessionId, firstSession.transactionId, privateIdUserId, randomUUID());
				const firstUser = getPrivateIDAuthenticatedUser(firstSession.sessionId);

				const secondSession = await client.createAuthenticationSession();
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
								metadata: { correlationId: randomUUID() }
						}
				});
				expect(response.statusCode).toBe(200);
				const secondUser = getPrivateIDAuthenticatedUser(secondSession.sessionId);

				expect(secondUser?.email).toBe(firstUser?.email);
				expect(secondUser?.sub).toBe(firstUser?.sub);

				await app.close();
		});
});
