import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
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
		it("maps the production SUCCESS webhook's puid field into the known authenticator", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const puid = `puid-${randomUUID()}`;
				const subject = await identityRegistry.resolveOrCreate({ provider: "PrivateID", providerSubject: `seed-${randomUUID()}`, status: undefined, email: "known@example.test", emailVerified: true, displayName: "Known User" });
				await inMemoryUserAuthenticatorRepository.create({ id: randomUUID(), userId: subject.id, provider: "privateid", providerSubject: puid, authenticatorType: "face", status: "active" });

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

				const authenticatedUser = resolvePrivateIDSessionRecord(session.sessionId)?.authenticatedUser;
				expect(authenticatedUser?.id).toBe(subject.id);

				await app.close();
		});

		it("denies a face login when puid is absent", async () => {
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
				expect(payload.status).toBe("FAILURE");

				await app.close();
		});

		it("does not use guid as the provider subject even when both puid and guid are present", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const puid = `puid-${randomUUID()}`;
				const guid = `guid-${randomUUID()}`;
				const subject = await identityRegistry.resolveOrCreate({ provider: "PrivateID", providerSubject: `seed-${randomUUID()}`, email: "known@example.test", emailVerified: true, displayName: "Known User" });
				await inMemoryUserAuthenticatorRepository.create({ id: randomUUID(), userId: subject.id, provider: "privateid", providerSubject: puid, authenticatorType: "face", status: "active" });

				await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						puid,
						guid
				});

				const authenticatedUser = resolvePrivateIDSessionRecord(session.sessionId)?.authenticatedUser;
				expect(authenticatedUser?.id).toBe(subject.id);

				await app.close();
		});
});
