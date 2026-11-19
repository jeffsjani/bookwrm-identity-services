import type pg from "pg";

import type {
		RefreshTokenFamily,
		RefreshTokenGeneration
} from "../../models/RefreshTokenFamily.js";
import type {
		CreateRefreshTokenFamilyCommand,
		RefreshTokenFamilyRepository,
		RotateRefreshTokenCommand,
		RotateRefreshTokenOutcome
} from "./RefreshTokenFamilyRepository.js";
import {
		getPostgresPool,
		withPostgresTransaction,
		type PostgresClient
} from "../../identity/infrastructure/PostgresInfrastructure.js";

const UNIQUE_VIOLATION = "23505";

type FamilyRow = {
		id: string;
		identity_subject_id: string;
		client_id: string;
		scope: string;
		session_id: string | null;
		device_reference: string | null;
		authentication_method: string | null;
		authenticated_at: string | Date | null;
		status: string;
		absolute_expires_at: string | Date;
		revoked_at: string | Date | null;
		revocation_reason: string | null;
		created_at: string | Date;
		updated_at: string | Date;
};

type GenerationRow = {
		id: string;
		family_id: string;
		token_hash: string;
		generation: number;
		status: string;
		expires_at: string | Date;
		rotated_at: string | Date | null;
		replaced_by: string | null;
		created_at: string | Date;
		updated_at: string | Date;
};

function toIso(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toFamily(row: FamilyRow): RefreshTokenFamily {
		return {
				id: row.id,
				identitySubjectId: row.identity_subject_id,
				clientId: row.client_id,
				scope: row.scope,
				...(row.session_id !== null ? { sessionId: row.session_id } : {}),
				...(row.device_reference !== null ? { deviceReference: row.device_reference } : {}),
				...(row.authentication_method !== null ? { authenticationMethod: row.authentication_method } : {}),
				...(row.authenticated_at !== null ? { authenticatedAt: toIso(row.authenticated_at) } : {}),
				status: row.status as RefreshTokenFamily["status"],
				absoluteExpiresAt: toIso(row.absolute_expires_at),
				...(row.revoked_at !== null ? { revokedAt: toIso(row.revoked_at) } : {}),
				...(row.revocation_reason !== null ? { revocationReason: row.revocation_reason } : {}),
				createdAt: toIso(row.created_at),
				updatedAt: toIso(row.updated_at)
		};
}

function toGeneration(row: GenerationRow): RefreshTokenGeneration {
		return {
				id: row.id,
				familyId: row.family_id,
				tokenHash: row.token_hash,
				generation: row.generation,
				status: row.status as RefreshTokenGeneration["status"],
				expiresAt: toIso(row.expires_at),
				...(row.rotated_at !== null ? { rotatedAt: toIso(row.rotated_at) } : {}),
				...(row.replaced_by !== null ? { replacedBy: row.replaced_by } : {}),
				createdAt: toIso(row.created_at),
				updatedAt: toIso(row.updated_at)
		};
}

function isUniqueViolation(error: unknown): boolean {
		return Boolean(error) && typeof error === "object" && (error as { code?: string }).code === UNIQUE_VIOLATION;
}

// System-of-record implementation. Concurrency model: rotation takes FOR UPDATE on both the
// presented generation row and its family row, serializing all rotations per family; the partial
// unique index (one active generation per family) is the database-enforced backstop -- a racing
// successor insert fails closed with a unique violation and the losing transaction rolls back.
export class PostgresRefreshTokenFamilyRepository implements RefreshTokenFamilyRepository {
		constructor(private readonly pool?: pg.Pool) {}

		private get reader(): PostgresClient {
				return (this.pool as PostgresClient | undefined) ?? getPostgresPool();
		}

		private withTransaction<T>(fn: (client: PostgresClient) => Promise<T>): Promise<T> {
				return withPostgresTransaction(fn, this.pool);
		}

		async createFamily(command: CreateRefreshTokenFamilyCommand) {
				return this.withTransaction(async (client) => {
						const family = await client.query<FamilyRow>(
								`INSERT INTO refresh_token_families
										(id, identity_subject_id, client_id, scope, session_id, device_reference,
										 authentication_method, authenticated_at, status, absolute_expires_at,
										 created_at, updated_at)
								 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, $10)
								 RETURNING *`,
								[command.familyId, command.identitySubjectId, command.clientId, command.scope,
										command.sessionId ?? null, command.deviceReference ?? null,
										command.authenticationMethod ?? null, command.authenticatedAt ?? null,
										command.absoluteExpiresAt, command.now]
						);
						const generation = await client.query<GenerationRow>(
								`INSERT INTO refresh_tokens
										(id, family_id, token_hash, generation, status, expires_at, created_at, updated_at)
								 VALUES ($1, $2, $3, 1, 'active', $4, $5, $5)
								 RETURNING *`,
								[command.generationId, command.familyId, command.tokenHash,
										command.generationExpiresAt, command.now]
						);
						return { family: toFamily(family.rows[0]), generation: toGeneration(generation.rows[0]) };
				});
		}

		async rotate(command: RotateRefreshTokenCommand): Promise<RotateRefreshTokenOutcome> {
				try {
						return await this.withTransaction(async (client) => {
								// Lock the generation and its family: all rotations within a family serialize here.
								const presented = await client.query<GenerationRow & { family_status: string }>(
										`SELECT t.*, f.status AS family_status
										 FROM refresh_tokens t
										 JOIN refresh_token_families f ON f.id = t.family_id
										 WHERE t.token_hash = $1
										 FOR UPDATE OF t, f`,
										[command.presentedTokenHash]
								);
								const row = presented.rows[0];
								if (!row) {
										return { status: "not_found" };
								}
								const familyResult = await client.query<FamilyRow>(
										`SELECT * FROM refresh_token_families WHERE id = $1`,
										[row.family_id]
								);
								const family = familyResult.rows[0];
								if (family.status === "revoked") {
										return { status: "family_revoked" };
								}
								const nowMs = Date.parse(command.now);
								if (family.status === "expired" || Date.parse(toIso(family.absolute_expires_at)) <= nowMs) {
										await client.query(
												`UPDATE refresh_token_families SET status = 'expired', updated_at = $2
												 WHERE id = $1 AND status = 'active'`,
												[family.id, command.now]
										);
										return { status: "family_expired" };
								}
								if (family.client_id !== command.clientId) {
										// Fail closed without consuming the token or mutating the family.
										return { status: "client_mismatch" };
								}
								if (row.status === "rotated" || row.status === "revoked") {
										// Replay of a consumed generation: revoke the ENTIRE family in this transaction
										// (OAuth 2.1 family-revocation response to refresh-token reuse).
										await this.revokeFamilyTx(client, family.id, "reuse_detected", command.now);
										return { status: "reuse_detected", familyId: family.id };
								}
								if (row.status === "expired" || Date.parse(toIso(row.expires_at)) <= nowMs) {
										await client.query(
												`UPDATE refresh_tokens SET status = 'expired', updated_at = $2
												 WHERE id = $1 AND status = 'active'`,
												[row.id, command.now]
										);
										return { status: "generation_expired" };
								}

								// One-time consumption + successor mint, atomically. The consumed row is marked
								// rotated first (freeing the one-active-per-family slot), the successor is inserted,
								// then the lineage pointer is backfilled (it must reference an existing row).
								await client.query(
										`UPDATE refresh_tokens
										 SET status = 'rotated', rotated_at = $2, updated_at = $2
										 WHERE id = $1`,
										[row.id, command.now]
								);
								const successor = await client.query<GenerationRow>(
										`INSERT INTO refresh_tokens
												(id, family_id, token_hash, generation, status, expires_at, created_at, updated_at)
										 VALUES ($1, $2, $3, $4, 'active',
												 LEAST($5::timestamptz, (SELECT absolute_expires_at FROM refresh_token_families WHERE id = $2)),
												 $6, $6)
										 RETURNING *`,
										[command.newGenerationId, family.id, command.newTokenHash, row.generation + 1,
												new Date(nowMs + command.slidingTtlMs).toISOString(), command.now]
								);
								await client.query(
										`UPDATE refresh_tokens SET replaced_by = $2 WHERE id = $1`,
										[row.id, command.newGenerationId]
								);
								await client.query(
										`UPDATE refresh_token_families SET updated_at = $2 WHERE id = $1`,
										[family.id, command.now]
								);
								return {
										status: "rotated",
										family: toFamily({ ...family, updated_at: command.now }),
										generation: toGeneration(successor.rows[0])
								};
						});
				} catch (error) {
						if (isUniqueViolation(error)) {
								// Lost the active-generation race; the transaction rolled back and changed nothing.
								return { status: "concurrent_rotation" };
						}
						throw error;
				}
		}

		async revokeFamily(familyId: string, reason: string, at: string): Promise<boolean> {
				return this.withTransaction(async (client) => {
						const updated = await client.query<{ id: string }>(
								`UPDATE refresh_token_families
								 SET status = 'revoked', revoked_at = $3, revocation_reason = $2, updated_at = $3
								 WHERE id = $1 AND status = 'active'
								 RETURNING id`,
								[familyId, reason, at]
						);
						if (updated.rows.length === 0) {
								return false;
						}
						await client.query(
								`UPDATE refresh_tokens SET status = 'revoked', updated_at = $2
								 WHERE family_id = $1 AND status = 'active'`,
								[familyId, at]
						);
						return true;
				});
		}

		async revokeFamilyByTokenHash(tokenHash: string, reason: string, at: string): Promise<boolean> {
				const generation = await this.reader.query<{ family_id: string }>(
						`SELECT family_id FROM refresh_tokens WHERE token_hash = $1`,
						[tokenHash]
				);
				if (!generation.rows[0]) {
						return false;
				}
				return this.revokeFamily(generation.rows[0].family_id, reason, at);
		}

		async revokeAllForSubject(identitySubjectId: string, reason: string, at: string): Promise<number> {
				return this.revokeWhere(
						`identity_subject_id = $1`,
						[identitySubjectId], reason, at);
		}

		async revokeBySession(sessionId: string, reason: string, at: string): Promise<number> {
				return this.revokeWhere(`session_id = $1`, [sessionId], reason, at);
		}

		async revokeByDevice(
				identitySubjectId: string,
				deviceReference: string,
				reason: string,
				at: string
		): Promise<number> {
				return this.revokeWhere(
						`identity_subject_id = $1 AND device_reference = $2`,
						[identitySubjectId, deviceReference], reason, at);
		}

		async findFamily(familyId: string): Promise<RefreshTokenFamily | undefined> {
				const result = await this.reader.query<FamilyRow>(
						`SELECT * FROM refresh_token_families WHERE id = $1`,
						[familyId]
				);
				return result.rows[0] ? toFamily(result.rows[0]) : undefined;
		}

		async listFamiliesBySubject(identitySubjectId: string): Promise<RefreshTokenFamily[]> {
				const result = await this.reader.query<FamilyRow>(
						`SELECT * FROM refresh_token_families WHERE identity_subject_id = $1 ORDER BY created_at, id`,
						[identitySubjectId]
				);
				return result.rows.map(toFamily);
		}

		async listGenerations(familyId: string): Promise<RefreshTokenGeneration[]> {
				const result = await this.reader.query<GenerationRow>(
						`SELECT * FROM refresh_tokens WHERE family_id = $1 ORDER BY generation`,
						[familyId]
				);
				return result.rows.map(toGeneration);
		}

		private async revokeWhere(
				condition: string,
				params: unknown[],
				reason: string,
				at: string
		): Promise<number> {
				return this.withTransaction(async (client) => {
						const reasonParam = params.length + 1;
						const atParam = params.length + 2;
						const updated = await client.query<{ id: string }>(
								`UPDATE refresh_token_families
								 SET status = 'revoked', revoked_at = $${atParam}, revocation_reason = $${reasonParam}, updated_at = $${atParam}
								 WHERE ${condition} AND status = 'active'
								 RETURNING id`,
								[...params, reason, at]
						);
						for (const row of updated.rows) {
								await client.query(
										`UPDATE refresh_tokens SET status = 'revoked', updated_at = $2
										 WHERE family_id = $1 AND status = 'active'`,
										[row.id, at]
								);
						}
						return updated.rows.length;
				});
		}

		private async revokeFamilyTx(client: PostgresClient, familyId: string, reason: string, at: string): Promise<void> {
				await client.query(
						`UPDATE refresh_token_families
						 SET status = 'revoked', revoked_at = $3, revocation_reason = $2, updated_at = $3
						 WHERE id = $1 AND status <> 'revoked'`,
						[familyId, reason, at]
				);
				await client.query(
						`UPDATE refresh_tokens SET status = 'revoked', updated_at = $2
						 WHERE family_id = $1 AND status = 'active'`,
						[familyId, at]
				);
		}
}
