import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PrivateIDEnrollmentService } from "../src/identity/PrivateIDEnrollmentService.js";
import type { PrivateIDEnrollmentTransaction } from "../src/models/PrivateIDEnrollmentTransaction.js";
import type { PrivateIDSession } from "../src/privateid/PrivateIDSession.js";

describe("PrivateIDEnrollmentService", () => {
	it("links the stored authenticated user to the webhook PUID without identity creation inputs", async () => {
		const createdAuthenticators: unknown[] = [];
		const statusUpdates: Array<{ id: string; status: string }> = [];
		let transaction: PrivateIDEnrollmentTransaction | undefined;
		const userId = randomUUID();
		const providerTransactionId = randomUUID();
		const session: PrivateIDSession = {
			sessionId: randomUUID(),
			transactionId: providerTransactionId,
			status: "created",
			launchUrl: "https://privateid.example.test/enroll",
			expires: Date.now() + 60_000,
			created: Date.now()
		};
		const transactions = {
			async create(input: Omit<PrivateIDEnrollmentTransaction, "createdAt" | "completedAt">) {
				transaction = { ...input, createdAt: new Date().toISOString() };
				return transaction;
			},
			async findByProviderTransactionId(transactionId: string) {
				return transaction?.providerTransactionId === transactionId ? transaction : undefined;
			},
			async updateStatus(id: string, status: PrivateIDEnrollmentTransaction["status"], completedAt?: Date) {
				statusUpdates.push({ id, status });
				if (!transaction || transaction.id !== id) {
					return undefined;
				}
				transaction = { ...transaction, status, completedAt: completedAt?.toISOString() };
				return transaction;
			}
		};
		const authenticators = {
			async create(input: unknown) {
				createdAuthenticators.push(input);
				return input;
			}
		};
		const service = new PrivateIDEnrollmentService(transactions, authenticators, async (transactionId) => ({
			...session,
			transactionId
		}));

		const started = await service.startEnrollment({ userId });
		const completed = await service.completeEnrollment(started.transaction.providerTransactionId, "puid-enrolled-user");

		expect(started.transaction).toMatchObject({ userId, purpose: "face_enrollment", status: "pending" });
		expect(createdAuthenticators).toEqual([expect.objectContaining({
			userId,
			provider: "privateid",
			providerSubject: "puid-enrolled-user",
			authenticatorType: "face",
			status: "active"
		})]);
		expect(createdAuthenticators[0]).not.toHaveProperty("email");
		expect(createdAuthenticators[0]).not.toHaveProperty("oidcSubject");
		expect(completed?.status).toBe("completed");
		expect(statusUpdates).toEqual([{ id: started.transaction.id, status: "completed" }]);
	});
});