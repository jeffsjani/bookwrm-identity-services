import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { UserAuthenticatorRepository } from "../src/identity/UserAuthenticatorRepository.js";
import type { PostgresClient } from "../src/identity/infrastructure/PostgresInfrastructure.js";

describe("UserAuthenticatorRepository", () => {
	it("queries provider subjects and records a normalized privateid face authenticator", async () => {
		const queries: Array<{ text: string; values?: unknown[] }> = [];
		const now = new Date("2026-09-07T00:00:00.000Z");
		const authenticatorId = randomUUID();
		const userId = randomUUID();
		const client: PostgresClient = {
			async query(text, values) {
				queries.push({ text, values });
				return {
					rows: text.startsWith("INSERT")
						? [{
							id: authenticatorId,
							user_id: userId,
							provider: "privateid",
							provider_subject: "puid-123",
							authenticator_type: "face",
							status: "active",
							linked_at: now,
							verified_at: null,
							last_used_at: null,
							revoked_at: null,
							created_at: now,
							updated_at: now
						}] : []
				};
			}
		};
		const repository = new UserAuthenticatorRepository(client);

		await repository.findByProviderSubject("privateid", "puid-123");
		await repository.findByUser("6a1f25b6f6771ce75374f8ad");
		const created = await repository.create({
			id: authenticatorId,
			userId,
			provider: "privateid",
			providerSubject: "puid-123",
			authenticatorType: "face",
			status: "active"
		});

		expect(queries[0]).toMatchObject({
			text: expect.stringContaining("provider = $1 AND provider_subject = $2"),
			values: ["privateid", "puid-123"]
		});
		expect(queries[1]).toMatchObject({
			text: expect.stringContaining("user_id::text = $1"),
			values: ["6a1f25b6f6771ce75374f8ad"]
		});
		expect(queries[2].text).toContain("INSERT INTO user_authenticators");
		expect(created).toMatchObject({
			id: authenticatorId,
			userId,
			provider: "privateid",
			providerSubject: "puid-123",
			authenticatorType: "face",
			status: "active"
		});
	});
});