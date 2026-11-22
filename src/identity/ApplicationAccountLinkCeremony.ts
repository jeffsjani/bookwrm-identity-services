import { createHash, randomBytes, randomUUID } from "node:crypto";

import type { HapiSessionAuthenticationMethod } from "../models/HapiSession.js";
import { getRedisClient, oidcRedisKey, type RedisClient } from "../oidc/infrastructure/RedisInfrastructure.js";
import {
		ApplicationAccountLinkConflict,
		type ApplicationAccountLinks
} from "./ApplicationAccountLinks.js";

export const APPLICATION_ACCOUNT_LINK_TTL_MS = 300_000;
export const APPLICATION_OWNERSHIP_PROOF_MAX_AGE_MS = 120_000;
export const APPLICATION_OWNERSHIP_PROOF_AUDIENCE = "urn:hapi:application-account-link:complete";

export type ApplicationAccountLinkTransaction = {
		version: 1;
		id: string;
		identitySubjectId: string;
		sessionId: string;
		applicationId: string;
		clientId: string;
		nonce: string;
		consentGiven: true;
		createdAt: number;
		expiresAt: number;
};

export type VerifiedApplicationOwnershipProof = {
		applicationId: string;
		clientId: string;
		externalAccountId: string;
		audience: string;
		transactionId: string;
		nonce: string;
		proofId: string;
		issuedAt: number;
		expiresAt: number;
};

export interface ApplicationOwnershipProofVerifier {
		// Implementations must verify the proof signature with a key trusted specifically for
		// applicationId/clientId before returning claims. The browser never supplies trusted claims.
		verify(
				proof: string,
				expected: { applicationId: string; clientId: string }
		): Promise<VerifiedApplicationOwnershipProof>;
}

export class ApplicationOwnershipProofRejected extends Error {
		constructor() {
				super("Application ownership proof was rejected");
				this.name = "ApplicationOwnershipProofRejected";
		}
}

export type ApplicationAccountLinkErrorCode =
		| "INVALID_TRANSACTION"
		| "PROOF_REJECTED"
		| "APPLICATION_UNAUTHORIZED"
		| "LINK_CONFLICT";

export class ApplicationAccountLinkError extends Error {
		constructor(readonly code: ApplicationAccountLinkErrorCode) {
				super(code);
				this.name = "ApplicationAccountLinkError";
		}
}

export type AuthenticatedLinkInitiator = {
		identitySubjectId: string;
		sessionId: string;
		authenticationMethod: HapiSessionAuthenticationMethod;
};

export type StartApplicationAccountLinkInput = AuthenticatedLinkInitiator & {
		applicationId: string;
		clientId: string;
		consent: boolean;
};

const digest = (value: string) => createHash("sha256").update(value).digest("base64url");
const RESERVE_PROOF_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local ttl = math.min(tonumber(ARGV[2]), redis.call('PTTL', KEYS[1]))
if ttl <= 0 then return 0 end
local reserved = redis.call('GET', KEYS[3])
if reserved and reserved ~= ARGV[3] then return 0 end
local proofOwner = redis.call('GET', KEYS[4])
if proofOwner and proofOwner ~= ARGV[4] then return 0 end
redis.call('SET', KEYS[3], ARGV[3], 'PX', ttl)
redis.call('SET', KEYS[4], ARGV[4], 'PX', ttl)
return 1`;
const CONSUME_TRANSACTION_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('GET', KEYS[3]) ~= ARGV[3] or redis.call('GET', KEYS[4]) ~= ARGV[4] then return 0 end
local ttl = math.min(tonumber(ARGV[2]), redis.call('PTTL', KEYS[1]))
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[2], '1', 'PX', ttl)
redis.call('DEL', KEYS[1], KEYS[3])
return 1`;

export class ApplicationAccountLinkTransactionStore {
		constructor(
				private readonly redis: RedisClient = getRedisClient(),
				private readonly clock: () => number = () => Date.now()
		) {}

		async create(input: StartApplicationAccountLinkInput): Promise<ApplicationAccountLinkTransaction> {
				const createdAt = this.clock();
				const transaction: ApplicationAccountLinkTransaction = {
						version: 1,
						id: randomUUID(),
						identitySubjectId: input.identitySubjectId,
						sessionId: input.sessionId,
						applicationId: input.applicationId,
						clientId: input.clientId,
						nonce: randomBytes(32).toString("base64url"),
						consentGiven: true,
						createdAt,
						expiresAt: createdAt + APPLICATION_ACCOUNT_LINK_TTL_MS
				};
				const stored = await this.redis.set(this.transactionKey(transaction.id), JSON.stringify(transaction),
						"PX", APPLICATION_ACCOUNT_LINK_TTL_MS, "NX");
				if (stored !== "OK") throw new Error("Could not create an application account-link transaction");
				return transaction;
		}

		async findById(id: string): Promise<ApplicationAccountLinkTransaction | null> {
				if (!id) return null;
				const consumed = await this.redis.get(this.consumedKey(id));
				if (consumed) return null;
				const raw = await this.redis.get(this.transactionKey(id));
				if (!raw) return null;
				const transaction = this.parse(raw);
				if (!transaction || transaction.id !== id || transaction.expiresAt <= this.clock()) {
						await this.redis.del(this.transactionKey(id));
						return null;
				}
				return transaction;
		}

		async reserveProof(id: string, applicationId: string, proofId: string): Promise<ApplicationAccountLinkTransaction | null> {
				const transaction = await this.findById(id);
				if (!transaction || transaction.applicationId !== applicationId || !proofId) return null;
				const remaining = transaction.expiresAt - this.clock();
				if (remaining <= 0) return null;

				const reserved = await this.redis.eval(RESERVE_PROOF_SCRIPT, 4,
						this.transactionKey(id), this.consumedKey(id), this.reservationKey(id),
						this.proofKey(applicationId, proofId), JSON.stringify(transaction), remaining, digest(proofId), id);
				return reserved === 1 ? transaction : null;
		}

		async consume(id: string, applicationId: string, proofId: string): Promise<ApplicationAccountLinkTransaction | null> {
				const transaction = await this.findById(id);
				if (!transaction || transaction.applicationId !== applicationId || !proofId) return null;
				const remaining = transaction.expiresAt - this.clock();
				if (remaining <= 0) return null;

				const consumed = await this.redis.eval(CONSUME_TRANSACTION_SCRIPT, 4,
						this.transactionKey(id), this.consumedKey(id), this.reservationKey(id),
						this.proofKey(applicationId, proofId), JSON.stringify(transaction), remaining, digest(proofId), id);
				return consumed === 1 ? transaction : null;
		}

		private parse(raw: string): ApplicationAccountLinkTransaction | null {
				let value: unknown;
				try {
						value = JSON.parse(raw);
				} catch {
						return null;
				}
				if (!value || typeof value !== "object") return null;
				const item = value as Partial<ApplicationAccountLinkTransaction>;
				if (item.version !== 1 || typeof item.id !== "string" ||
						typeof item.identitySubjectId !== "string" || typeof item.sessionId !== "string" ||
						typeof item.applicationId !== "string" || typeof item.clientId !== "string" ||
						typeof item.nonce !== "string" || item.consentGiven !== true ||
						typeof item.createdAt !== "number" || typeof item.expiresAt !== "number") return null;
				return item as ApplicationAccountLinkTransaction;
		}

		private transactionKey(id: string): string {
				return oidcRedisKey(`application_account_link:${digest(id)}`);
		}

		private consumedKey(id: string): string {
				return oidcRedisKey(`application_account_link_consumed:${digest(id)}`);
		}

		private reservationKey(id: string): string {
				return oidcRedisKey(`application_account_link_reservation:${digest(id)}`);
		}

		private proofKey(applicationId: string, proofId: string): string {
				return oidcRedisKey(`application_account_link_proof:${digest(applicationId)}:${digest(proofId)}`);
		}
}

export class ApplicationAccountLinkCeremony {
		constructor(
				private readonly links: ApplicationAccountLinks,
				private readonly transactions: ApplicationAccountLinkTransactionStore,
				private readonly verifier: ApplicationOwnershipProofVerifier,
				private readonly clock: () => number = () => Date.now()
		) {}

		async start(input: StartApplicationAccountLinkInput): Promise<ApplicationAccountLinkTransaction> {
				if (!input.consent || !input.applicationId.trim() || !input.clientId.trim()) {
						throw new ApplicationAccountLinkError("APPLICATION_UNAUTHORIZED");
				}
				if (!await this.links.isAuthorized(input.identitySubjectId, input.applicationId, input.clientId)) {
						throw new ApplicationAccountLinkError("APPLICATION_UNAUTHORIZED");
				}
				return this.transactions.create(input);
		}

		async complete(input: AuthenticatedLinkInitiator & {
				transactionId: string;
				ownershipProof: string;
		}): Promise<{ link: Awaited<ReturnType<ApplicationAccountLinks["reconcile"]>>["link"]; created: boolean }> {
				const transaction = await this.transactions.findById(input.transactionId);
				if (!transaction || transaction.identitySubjectId !== input.identitySubjectId ||
						transaction.sessionId !== input.sessionId || !transaction.consentGiven) {
						throw new ApplicationAccountLinkError("INVALID_TRANSACTION");
				}

				let proof: VerifiedApplicationOwnershipProof;
				try {
						proof = await this.verifier.verify(input.ownershipProof, {
								applicationId: transaction.applicationId,
								clientId: transaction.clientId
						});
				} catch (error) {
						if (error instanceof ApplicationOwnershipProofRejected) {
								throw new ApplicationAccountLinkError("PROOF_REJECTED");
						}
						throw error;
				}

				if (!this.proofMatches(transaction, proof)) {
						throw new ApplicationAccountLinkError("PROOF_REJECTED");
				}
				if (!await this.transactions.reserveProof(transaction.id, transaction.applicationId, proof.proofId)) {
						throw new ApplicationAccountLinkError("INVALID_TRANSACTION");
				}

				try {
						const result = await this.links.reconcile({
								identitySubjectId: transaction.identitySubjectId,
								applicationId: transaction.applicationId,
								externalAccountId: proof.externalAccountId,
								evidence: {
										authority: "APPLICATION_OWNERSHIP_PROOF",
										clientId: transaction.clientId,
										requestId: transaction.id,
										authenticationMethod: input.authenticationMethod
								}
						});
						const consumed = await this.transactions.consume(transaction.id, transaction.applicationId, proof.proofId);
						if (!consumed) throw new ApplicationAccountLinkError("INVALID_TRANSACTION");
						return { link: result.link, created: result.created };
				} catch (error) {
						if (error instanceof ApplicationAccountLinkConflict) {
								const consumed = await this.transactions.consume(transaction.id, transaction.applicationId, proof.proofId);
								if (!consumed) throw new ApplicationAccountLinkError("INVALID_TRANSACTION");
								throw new ApplicationAccountLinkError("LINK_CONFLICT");
						}
						throw error;
				}
		}

		private proofMatches(
				transaction: ApplicationAccountLinkTransaction,
				proof: VerifiedApplicationOwnershipProof
		): boolean {
				const now = this.clock();
				return proof.applicationId === transaction.applicationId &&
						proof.clientId === transaction.clientId &&
						proof.audience === APPLICATION_OWNERSHIP_PROOF_AUDIENCE &&
						proof.transactionId === transaction.id &&
						proof.nonce === transaction.nonce &&
						typeof proof.externalAccountId === "string" &&
						proof.externalAccountId.trim().length > 0 &&
						proof.externalAccountId.length <= 256 &&
						typeof proof.proofId === "string" &&
						proof.proofId.trim().length > 0 &&
						proof.proofId.length <= 256 &&
						Number.isSafeInteger(proof.issuedAt) &&
						Number.isSafeInteger(proof.expiresAt) &&
						proof.issuedAt >= transaction.createdAt - 30_000 &&
						proof.issuedAt <= now + 30_000 &&
						proof.expiresAt > proof.issuedAt &&
						proof.expiresAt > now &&
						proof.expiresAt <= transaction.expiresAt &&
						proof.expiresAt - proof.issuedAt <= APPLICATION_OWNERSHIP_PROOF_MAX_AGE_MS;
		}
}
