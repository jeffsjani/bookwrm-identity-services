import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
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
		providerSubject: string,
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
						puid: providerSubject,
						contactInformation: {
								email: "user@example.com",
								firstName: "Verified",
								lastName: "User",
								phone: "[TEST-ONLY]"
						},
						metadata: { correlationId }
				}
		});
}

async function createKnownFaceUser(providerSubject: string) {
	const subject = await identityRegistry.resolveOrCreate({
		provider: "PrivateID", providerSubject: `seed-${randomUUID()}`,
		email: "canonical@example.test", emailVerified: true, displayName: "Canonical User"
	});
	await inMemoryUserAuthenticatorRepository.create({
		id: randomUUID(), userId: subject.id, provider: "privateid", providerSubject,
		authenticatorType: "face", status: "active"
	});
	return subject;
}

describe("OIDC face login identity resolution", () => {
		it("uses a pre-existing IdentitySubject-backed sub for a known face", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const providerSubject = `puid-${randomUUID()}`;
				const subject = await createKnownFaceUser(providerSubject);

				const response = await sendSuccessWebhook(app, session.sessionId, session.transactionId, providerSubject, correlationId);
				expect(response.statusCode).toBe(200);

				const authenticatedUser = getPrivateIDAuthenticatedUser(session.sessionId);
				expect(authenticatedUser).toBeDefined();
				expect(authenticatedUser?.id).toBe(subject.id);
				expect(authenticatedUser?.sub).toBe(subject.oidcSubject);
				expect(authenticatedUser?.email).toBe("canonical@example.test");
				expect(authenticatedUser?.emailVerified).toBe(true);
				expect(authenticatedUser?.name).toBe("Canonical User");

				expect(subject?.email).toBe("canonical@example.test");
				expect(subject?.emailVerified).toBe(true);

				const claimsResponse = await app.inject({
						method: "POST",
						url: "/diagnostics/claims",
						headers: { authorization: "Bearer test-key" },
						payload: { subject: subject?.oidcSubject }
				});
				expect(claimsResponse.statusCode).toBe(200);
				const claims = claimsResponse.json() as Record<string, any>;
				expect(claims.identityRegistry.email).toBe("canonical@example.test");
				expect(claims.idTokenClaims.email).toBe("canonical@example.test");
				expect(claims.userInfoClaims.email).toBe("canonical@example.test");

				await app.close();
		});

		it("resolves the same sub for a returning face login from a different browser/session", async () => {
				const { app } = await buildOidcTestApp();
				const providerSubject = `puid-${randomUUID()}`;
				await createKnownFaceUser(providerSubject);

				const firstCorrelationId = randomUUID();
				const firstSession = await createOidcSession(firstCorrelationId);
				await sendSuccessWebhook(app, firstSession.sessionId, firstSession.transactionId, providerSubject, firstCorrelationId);
				const firstUser = getPrivateIDAuthenticatedUser(firstSession.sessionId);

				// Different PrivateID session/transaction entirely -- simulates a new browser.
				const secondCorrelationId = randomUUID();
				const secondSession = await createOidcSession(secondCorrelationId);
				await sendSuccessWebhook(app, secondSession.sessionId, secondSession.transactionId, providerSubject, secondCorrelationId);
				const secondUser = getPrivateIDAuthenticatedUser(secondSession.sessionId);

				expect(secondUser?.sub).toBe(firstUser?.sub);
				expect(secondUser?.email).toBe(firstUser?.email);

				await app.close();
		});

		it("loads email from the canonical user even if a login webhook carries a different email", async () => {
				const { app } = await buildOidcTestApp();
				const providerSubject = `puid-${randomUUID()}`;
				await createKnownFaceUser(providerSubject);

				const firstCorrelationId = randomUUID();
				const firstSession = await createOidcSession(firstCorrelationId);
				await sendSuccessWebhook(app, firstSession.sessionId, firstSession.transactionId, providerSubject, firstCorrelationId);
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
								puid: providerSubject,
								contactInformation: { email: "different-candidate-email@example.com" },
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
