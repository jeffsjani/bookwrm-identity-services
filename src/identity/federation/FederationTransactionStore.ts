import { createHash, randomBytes, randomUUID } from "node:crypto";

import type { ExternalIdentityProvider } from "../../models/ExternalIdentity.js";
import { getRedisClient, oidcRedisKey, type RedisClient } from "../../oidc/infrastructure/RedisInfrastructure.js";

// Provider round-trips must finish quickly; a transaction is never extended.
export const FEDERATION_TRANSACTION_TTL_MS = 300_000;
const STATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type FederationTransactionPurpose = "login" | "link";

// A single upstream authorization round-trip. state and nonce are cryptographically random,
// generated server-side ONLY, and bound to exactly one browser context: a Universal Login
// interaction (login) or an authenticated subject + session (link). The browser never chooses or
// influences either value.
export type FederationTransaction = {
		version: 1;
		id: string;
		purpose: FederationTransactionPurpose;
		provider: ExternalIdentityProvider;
		state: string;
		nonce: string;
		createdAt: number;
		expiresAt: number;
		// login purpose: the Universal Login interaction handle this transaction belongs to.
		interactionHandle?: string;
		// link purpose: the authenticated HAPI subject and session that initiated linking.
		identitySubjectId?: string;
		sessionId?: string;
};

export type NewFederationTransaction = {
		purpose: FederationTransactionPurpose;
		provider: ExternalIdentityProvider;
		interactionHandle?: string;
		identitySubjectId?: string;
		sessionId?: string;
};

const digest = (value: string) => createHash("sha256").update(value).digest("base64url");

// HAPI ID V2-D: short-lived, single-use, server-side federation transactions. Storage keys are
// SHA-256 digests of the transaction id and state -- neither raw value is ever used as a key, and
// the record is retrievable by exactly the artifact each flow legitimately holds (state for
// provider callbacks, transaction id for the authenticated linking API).
export class FederationTransactionStore {
		constructor(private readonly redis: RedisClient = getRedisClient(),
				private readonly ttlMs = FEDERATION_TRANSACTION_TTL_MS,
				private readonly clock: () => number = () => Date.now()) {}

		async create(input: NewFederationTransaction): Promise<FederationTransaction> {
				const createdAt = this.clock();
				const transaction: FederationTransaction = {
						version: 1,
						id: randomUUID(),
						purpose: input.purpose,
						provider: input.provider,
						state: randomBytes(32).toString("base64url"),
						nonce: randomBytes(32).toString("base64url"),
						createdAt,
						expiresAt: createdAt + this.ttlMs,
						...(input.interactionHandle !== undefined ? { interactionHandle: input.interactionHandle } : {}),
						...(input.identitySubjectId !== undefined ? { identitySubjectId: input.identitySubjectId } : {}),
						...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {})
				};
				const payload = JSON.stringify(transaction);
				await this.redis.set(this.idKey(transaction.id), payload, "PX", this.ttlMs, "NX");
				await this.redis.set(this.stateKey(transaction.state), transaction.id, "PX", this.ttlMs, "NX");
				return transaction;
		}

		// Atomic single-use consumption by the provider-callback state parameter. Exactly one caller
		// can win a given transaction; replays and unknown states resolve to null.
		async consumeByState(state: string | undefined): Promise<FederationTransaction | null> {
				if (!state || !STATE_PATTERN.test(state)) return null;
				const id = await this.redis.get(this.stateKey(state));
				if (!id) return null;
				return this.consumeById(id);
		}

		// Atomic single-use consumption by transaction id (authenticated linking API completion).
		async consumeById(id: string | undefined): Promise<FederationTransaction | null> {
				if (!id) return null;
				const raw = await this.redis.get(this.idKey(id));
				if (!raw) return null;
				let transaction: FederationTransaction;
				try {
						transaction = JSON.parse(raw) as FederationTransaction;
				} catch {
						return null;
				}
				const remaining = transaction.expiresAt - this.clock();
				if (transaction.version !== 1 || remaining <= 0) {
						await this.redis.del(this.idKey(id));
						await this.redis.del(this.stateKey(transaction.state));
						return null;
				}
				const won = await this.redis.set(this.consumedKey(id), "1", "PX", remaining, "NX");
				if (won !== "OK") return null;
				await this.redis.del(this.idKey(id));
				await this.redis.del(this.stateKey(transaction.state));
				return transaction;
		}

		private idKey(id: string): string {
				return oidcRedisKey(`federation_txn:${digest(id)}`);
		}

		private stateKey(state: string): string {
				return oidcRedisKey(`federation_txn_state:${digest(state)}`);
		}

		private consumedKey(id: string): string {
				return oidcRedisKey(`federation_txn_consumed:${digest(id)}`);
		}
}
