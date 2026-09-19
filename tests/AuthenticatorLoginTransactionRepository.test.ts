import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { AuthenticatorLoginTransactionRepository } from "../src/identity/AuthenticatorLoginTransactionRepository.js";
import { InMemoryAuthenticatorLoginTransactionRepository } from "../src/identity/InMemoryAuthenticatorLoginTransactionRepository.js";
import type { PostgresClient } from "../src/identity/infrastructure/PostgresInfrastructure.js";

describe("Release C4.6: AuthenticatorLoginTransaction idempotency", () => {
	it("Postgres: reuses the existing row on a duplicate provider_transaction_id instead of throwing", async () => {
		const providerTransactionId = randomUUID();
		const existingId = randomUUID();
		const now = new Date("2026-09-19T00:00:00.000Z");
		const queries: Array<{ text: string; values?: unknown[] }> = [];
		const client: PostgresClient = {
			async query(text, values) {
				queries.push({ text, values });
				// Simulate the ON CONFLICT DO UPDATE always returning the existing row for this providerTransactionId.
				return {
					rows: [{
						id: existingId,
						provider: "privateid",
						provider_transaction_id: providerTransactionId,
						provider_subject: null,
						resolved_user_id: null,
						status: "pending",
						created_at: now,
						completed_at: null
					}]
				};
			}
		};
		const repository = new AuthenticatorLoginTransactionRepository(client);

		const first = await repository.create({ id: randomUUID(), provider: "privateid", providerTransactionId, status: "pending" });
		const second = await repository.create({ id: randomUUID(), provider: "privateid", providerTransactionId, status: "pending" });

		expect(queries[0].text).toContain("ON CONFLICT (provider_transaction_id) DO UPDATE");
		expect(first.id).toBe(existingId);
		expect(second.id).toBe(existingId);
		expect(second).toEqual(first);
	});

	it("in-memory: reuses the existing row on a duplicate providerTransactionId instead of creating a second one", async () => {
		const repository = new InMemoryAuthenticatorLoginTransactionRepository();
		const providerTransactionId = randomUUID();

		const first = await repository.create({ id: randomUUID(), provider: "privateid", providerTransactionId, status: "pending" });
		const second = await repository.create({ id: randomUUID(), provider: "privateid", providerTransactionId, status: "pending" });

		expect(second.id).toBe(first.id);
		expect(second).toEqual(first);

		// Completing under the reused id must not throw and must be visible to a subsequent create() call.
		const completed = await repository.complete(first.id, "completed", "puid-123", randomUUID());
		expect(completed?.status).toBe("completed");

		const third = await repository.create({ id: randomUUID(), provider: "privateid", providerTransactionId, status: "pending" });
		expect(third.id).toBe(first.id);
		expect(third.status).toBe("completed");
	});
});
