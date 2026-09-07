import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { AuthenticatorLoginResolver } from "../src/identity/AuthenticatorLoginResolver.js";
import { InMemoryAuthenticatorLoginTransactionRepository } from "../src/identity/InMemoryAuthenticatorLoginTransactionRepository.js";
import { InMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import { PrivateIDEnrollmentService } from "../src/identity/PrivateIDEnrollmentService.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";

describe("face enrollment login continuity", () => {
	it("retains the canonical user, OIDC subject, and email across enrollment then face login", async () => {
		const authenticators = new InMemoryUserAuthenticatorRepository();
		const user: IdentitySubject = {
			id: randomUUID(), oidcSubject: randomUUID(), primaryProvider: "PrivateID", primaryProviderSubject: "legacy",
			email: "before-enrollment@example.test", emailVerified: true, displayName: "Existing User", status: "ACTIVE",
			createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
		};
		let transaction: any;
		const transactions = {
			async create(input: any) { transaction = { ...input, createdAt: new Date().toISOString() }; return transaction; },
			async findByProviderTransactionId(id: string) { return transaction?.providerTransactionId === id ? transaction : undefined; },
			async updateStatus(id: string, status: any, completedAt?: Date) { transaction = { ...transaction, id, status, completedAt: completedAt?.toISOString() }; return transaction; }
		};
		const enrollment = new PrivateIDEnrollmentService(transactions, authenticators, async (providerTransactionId) => ({
			sessionId: randomUUID(), transactionId: providerTransactionId, status: "created", launchUrl: "https://privateid.example.test/enroll", expires: Date.now() + 60_000, created: Date.now()
		}));

		const started = await enrollment.startEnrollment({ userId: user.id });
		await enrollment.completeEnrollment(started.transaction.providerTransactionId, "puid-continuity");
		const login = new AuthenticatorLoginResolver(authenticators, { async findById(id) { return id === user.id ? user : undefined; } }, new InMemoryAuthenticatorLoginTransactionRepository());
		const resolved = await login.resolveLogin("privateid", randomUUID(), "puid-continuity");

		expect(resolved.id).toBe(user.id);
		expect(resolved.oidcSubject).toBe(user.oidcSubject);
		expect(resolved.email).toBe(user.email);
		expect((await authenticators.findByProviderSubject("privateid", "puid-continuity"))?.status).toBe("active");
	});
});