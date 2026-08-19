import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";
import { resolvePrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";
import type { PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";

const WEBHOOK_SECRET = "privateid-webhook-secret";

const STUB_PENDING_CONTEXT: PendingAuthorizationContext = {
		clientId: "base44-web",
		redirectUri: "https://example.com/callback",
		scope: "openid profile email",
		nonce: "test-nonce",
		codeChallenge: "test-challenge"
};

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

function postSuccessWebhook(
		app: Awaited<ReturnType<typeof buildOidcTestApp>>["app"],
		payload: Record<string, unknown>
) {
		return app.inject({
				method: "POST",
				url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": WEBHOOK_SECRET },
				payload
		});
}

describe("Release Patch 6 - puid provider subject mapping", () => {
		it("maps the production SUCCESS webhook's puid field into IdentitySubject.primaryProviderSubject", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const puid = `puid-${randomUUID()}`;

				// Production SUCCESS webhook shape: sessionId, status, puid, guid, identityInformation, contactInformation.
				const response = await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						puid,
						guid: randomUUID(),
						identityInformation: {},
						contactInformation: {}
				});

				expect(response.statusCode).toBe(200);

				const subject = await identityRegistry.findByProvider("PrivateID", puid);
				expect(subject).toBeDefined();
				expect(subject?.primaryProviderSubject).toBe(puid);

				await app.close();
		});

		it("never resolves a null/empty primary_provider_subject when puid is absent", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);

				const response = await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						guid: randomUUID()
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload.completed).toBe(true);

				const subject = await identityRegistry.findByProvider("PrivateID", session.transactionId);
				expect(subject).toBeDefined();
				expect(subject?.primaryProviderSubject).toBeTruthy();

				await app.close();
		});

		it("does not use guid as the provider subject even when both puid and guid are present", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const puid = `puid-${randomUUID()}`;
				const guid = `guid-${randomUUID()}`;

				await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						puid,
						guid
				});

				const byGuid = await identityRegistry.findByProvider("PrivateID", guid);
				const byPuid = await identityRegistry.findByProvider("PrivateID", puid);

				expect(byGuid).toBeUndefined();
				expect(byPuid).toBeDefined();
				expect(byPuid?.primaryProviderSubject).toBe(puid);

				await app.close();
		});
});
