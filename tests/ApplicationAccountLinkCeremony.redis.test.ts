import IORedisModule from "ioredis";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
		ApplicationAccountLinkTransactionStore,
		APPLICATION_ACCOUNT_LINK_TTL_MS
} from "../src/identity/ApplicationAccountLinkCeremony.js";
import type { RedisClient } from "../src/oidc/infrastructure/RedisInfrastructure.js";

const redisUrl = process.env.HAPI_APPLICATION_LINK_TEST_REDIS_URL;
const IORedis = IORedisModule as unknown as { new(url: string): RedisClient };

describe.skipIf(!redisUrl)("Application-account-link transactions (Redis integration)", () => {
		const redis = new IORedis(redisUrl!);
		let now = Date.now();
		const store = new ApplicationAccountLinkTransactionStore(redis, () => now);
		const input = {
				identitySubjectId: "hapi-subject",
				sessionId: "hapi-session",
				applicationId: "bookwrm-app",
				clientId: "bookwrm-web",
				authenticationMethod: "HAPI_EMAIL" as const,
				consent: true
		};

		beforeAll(async () => {
				expect(await redis.ping()).toBe("PONG");
		});

		afterAll(async () => {
				await redis.quit();
		});

		it("consumes transactions once and prevents proof-id replay across transactions", async () => {
				const first = await store.create(input);
				const proofId = randomUUID();
				expect(await store.reserveProof(first.id, first.applicationId, proofId)).toEqual(first);
				expect(await store.reserveProof(first.id, first.applicationId, proofId)).toEqual(first);
				const consumed = await store.consume(first.id, first.applicationId, proofId);
				expect(consumed).toEqual(first);
				expect(await store.reserveProof(first.id, first.applicationId, proofId)).toBeNull();
				expect(await store.consume(first.id, first.applicationId, proofId)).toBeNull();

				const replay = await store.create(input);
				expect(await store.reserveProof(replay.id, replay.applicationId, proofId)).toBeNull();
				const newProofId = randomUUID();
				expect(await store.reserveProof(replay.id, replay.applicationId, newProofId)).toEqual(replay);
				expect(await store.consume(replay.id, replay.applicationId, newProofId)).toEqual(replay);
		});

		it("allows only one concurrent completion and expires a transaction at its TTL", async () => {
				const transaction = await store.create(input);
				const proofIds = [randomUUID(), randomUUID()];
				const results = await Promise.all([
						store.reserveProof(transaction.id, transaction.applicationId, proofIds[0]),
						store.reserveProof(transaction.id, transaction.applicationId, proofIds[1])
				]);
				expect(results.filter(Boolean)).toHaveLength(1);
				const winningProofId = proofIds[results.findIndex(result => result !== null)];
				expect(await store.consume(transaction.id, transaction.applicationId, winningProofId)).toEqual(transaction);

				const expiring = await store.create(input);
				now += APPLICATION_ACCOUNT_LINK_TTL_MS + 1;
				expect(await store.findById(expiring.id)).toBeNull();
				expect(await store.reserveProof(expiring.id, expiring.applicationId, randomUUID())).toBeNull();
				expect(await store.consume(expiring.id, expiring.applicationId, randomUUID())).toBeNull();
		});
});
