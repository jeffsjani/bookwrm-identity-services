import { describe, expect, it } from "vitest";
import { PrivateIdWebhookDiagnosticsRepository } from "../src/identity/infrastructure/PrivateIdWebhookDiagnosticsRepository.js";
import type { PostgresClient } from "../src/identity/infrastructure/PostgresInfrastructure.js";

describe("PrivateID webhook diagnostics persistence", () => {
	it("stores the SUCCESS envelope and raw webhook JSON", async () => {
		const queries: Array<{ text: string; values?: unknown[] }> = [];
		const client: PostgresClient = {
			async query(text, values) {
				queries.push({ text, values });
				return { rows: [] };
			}
		};
		const repository = new PrivateIdWebhookDiagnosticsRepository(client);
		const receivedAt = new Date("2026-09-07T12:00:00.000Z");
		const rawWebhook = {
			status: "SUCCESS",
			sessionId: "session-1",
			contactInformation: { email: "user@example.com" }
		};

		await repository.capture(receivedAt, "session-1", "transaction-1", rawWebhook);

		expect(queries).toHaveLength(1);
		expect(queries[0].values).toEqual([
			receivedAt,
			"session-1",
			"transaction-1",
			"SUCCESS",
			JSON.stringify(rawWebhook)
		]);
		expect(queries[0].text).toContain("raw_webhook_json");
	});

	it("retrieves only records received within seven days", async () => {
		const queries: Array<{ text: string; values?: unknown[] }> = [];
		const client: PostgresClient = {
			async query(text, values) {
				queries.push({ text, values });
				return { rows: [{ raw_webhook_json: { status: "SUCCESS" } }] };
			}
		};
		const repository = new PrivateIdWebhookDiagnosticsRepository(client);

		const result = await repository.findActiveBySessionId("session-1");

		expect(result).toEqual({ raw_webhook_json: { status: "SUCCESS" } });
		expect(queries[0].text).toContain("received_at >= NOW() - INTERVAL '7 days'");
		expect(queries[0].values).toEqual(["session-1"]);
	});
});
