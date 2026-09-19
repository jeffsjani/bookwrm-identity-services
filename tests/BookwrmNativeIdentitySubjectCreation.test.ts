import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { PrivateIDClient } from "../src/privateid/PrivateIDClient.js";
import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import { PrivateIDEnrollmentService } from "../src/identity/PrivateIDEnrollmentService.js";
import type { PrivateIDEnrollmentTransaction } from "../src/models/PrivateIDEnrollmentTransaction.js";
import { resolvePrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";
import type { PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";

const WEBHOOK_SECRET = "privateid-webhook-secret";

const STUB_PENDING_CONTEXT: PendingAuthorizationContext = {
	clientId: "base44-web",
	redirectUri: "https://example.com/callback",
	scope: "openid profile email",
	nonce: "test-nonce",
	codeChallenge: "test-challenge"
};

// In-memory stand-in for the (Postgres-only) PrivateIDEnrollmentTransactionRepository, so this test
// can run against the in-memory IdentityRegistry/UserAuthenticatorRepository driver.
function createInMemoryEnrollmentTransactions() {
	const transactionsById = new Map<string, PrivateIDEnrollmentTransaction>();
	return {
		async create(input: Omit<PrivateIDEnrollmentTransaction, "createdAt" | "completedAt">) {
			const transaction: PrivateIDEnrollmentTransaction = { ...input, createdAt: new Date().toISOString() };
			transactionsById.set(transaction.id, transaction);
			return transaction;
		},
		async findByProviderTransactionId(providerTransactionId: string) {
			return [...transactionsById.values()].find((transaction) => transaction.providerTransactionId === providerTransactionId);
		},
		async updateStatus(id: string, status: PrivateIDEnrollmentTransaction["status"], completedAt?: Date) {
			const transaction = transactionsById.get(id);
			if (!transaction) return undefined;
			const updated = { ...transaction, status, completedAt: completedAt?.toISOString() };
			transactionsById.set(id, updated);
			return updated;
		}
	};
}

describe("Release C4.2: Bookwrm-native IdentitySubject creation", () => {
	it("enrollment mints an IdentitySubject for a Bookwrm-native user, and /privateid/callback resolves PUID -> UserAuthenticator -> IdentitySubject -> ACTIVE -> OIDC -> 302", async () => {
		const { app } = await buildOidcTestApp();
		const bookwrmUserId = randomUUID();
		const puid = `puid-${randomUUID()}`;

		const enrollmentService = new PrivateIDEnrollmentService(
			createInMemoryEnrollmentTransactions(),
			inMemoryUserAuthenticatorRepository,
			(providerTransactionId) => new PrivateIDClient().createEnrollmentSession(providerTransactionId),
			identityRegistry
		);

		// Enrollment: Bookwrm User -> IdentitySubject -> UserAuthenticator (no prior IdentitySubject exists yet).
		const started = await enrollmentService.startEnrollment({ userId: bookwrmUserId });
		const completed = await enrollmentService.completeEnrollment(started.transaction.providerTransactionId, puid);
		expect(completed?.status).toBe("completed");

		const mintedIdentitySubject = await identityRegistry.findByProvider("PrivateID", puid);
		expect(mintedIdentitySubject).toBeDefined();
		expect(mintedIdentitySubject?.status).toBe("ACTIVE");

		// Re-enrollment (e.g. re-linking the same PUID) must reuse the same IdentitySubject via the
		// existing resolveOrCreate service, never mint a second one.
		const reusedIdentitySubject = await identityRegistry.resolveOrCreate({ provider: "PrivateID", providerSubject: puid });
		expect(reusedIdentitySubject.id).toBe(mintedIdentitySubject?.id);

		// Login: PrivateID SUCCESS webhook with the enrolled PUID, then GET /privateid/callback.
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
				sessionId: record.session.sessionId,
				transactionId: record.session.transactionId,
				puid
			}
		});
		expect(webhookResponse.statusCode).toBe(200);

		const callbackResponse = await app.inject({
			method: "GET",
			url: `/privateid/callback?reason=success&sessionId=${encodeURIComponent(record.session.sessionId)}&transactionId=${encodeURIComponent(record.session.transactionId)}`
		});

		expect(callbackResponse.statusCode).toBe(302);
		const location = callbackResponse.headers.location;
		expect(location).toBeDefined();
		const redirectUrl = new URL(location as string);
		expect(redirectUrl.searchParams.get("code")).toBeTruthy();

		await app.close();
	});
});
