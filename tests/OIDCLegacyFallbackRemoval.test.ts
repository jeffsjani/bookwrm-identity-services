import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { PrivateIDClient } from "../src/privateid/PrivateIDClient.js";
import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { identityService } from "../src/identity/IdentityService.js";
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

describe("Release Patch 5A - remove legacy OIDC fallback", () => {
		it("Case 1: SUCCESS webhook with a correlationId resolves via IdentityRegistry and authorization continues", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const privateIdUserId = `case1-user-${randomUUID()}`;
				const resolveIdentitySpy = vi.spyOn(identityService, "resolveIdentity");

				const response = await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						privateIdUserId
				});

				expect(response.statusCode).toBe(200);
				expect(resolveIdentitySpy).not.toHaveBeenCalled();

				const authenticatedUser = getPrivateIDAuthenticatedUser(session.sessionId);
				expect(authenticatedUser).toBeDefined();
				expect(authenticatedUser?.sub).not.toBe(privateIdUserId);

				resolveIdentitySpy.mockRestore();
				await app.close();
		});

		it("Case 2: SUCCESS webhook for an OIDC session without a resolvable correlationId fails as Authentication Incomplete", async () => {
				const { app } = await buildOidcTestApp();
				const correlationId = randomUUID();
				const session = await createOidcSession(correlationId);
				const privateIdUserId = `case2-user-${randomUUID()}`;
				const resolveIdentitySpy = vi.spyOn(identityService, "resolveIdentity");

				// Simulate the correlation already being consumed/lost (e.g. a duplicate webhook delivery) before this SUCCESS arrives.
				await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						privateIdUserId
				});
				resolveIdentitySpy.mockClear();

				const response = await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						privateIdUserId
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload).toMatchObject({ status: "FAILURE", message: "Authentication Incomplete" });
				expect(resolveIdentitySpy).not.toHaveBeenCalled();

				resolveIdentitySpy.mockRestore();
				await app.close();
		});

		it("Case 3: genuine legacy Bookwrm-native flow still resolves identity via identityService.resolveIdentity", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();
				const privateIdUserId = `case3-legacy-user-${randomUUID()}`;
				const resolveIdentitySpy = vi.spyOn(identityService, "resolveIdentity");

				const response = await postSuccessWebhook(app, {
						status: "SUCCESS",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						privateIdUserId
				});

				expect(response.statusCode).toBe(200);
				expect(resolveIdentitySpy).toHaveBeenCalledWith(privateIdUserId);

				const authenticatedUser = getPrivateIDAuthenticatedUser(session.sessionId);
				expect(authenticatedUser?.sub).toBe(privateIdUserId);

				resolveIdentitySpy.mockRestore();
				await app.close();
		});
});
