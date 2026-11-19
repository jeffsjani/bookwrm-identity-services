import type pg from "pg";

import type { HapiSession } from "../../models/HapiSession.js";
import type {
		CreateHapiSessionCommand,
		HapiSessionRepository,
		RevokeSessionResult
} from "./HapiSessionRepository.js";
import {
		getPostgresPool,
		withPostgresTransaction,
		type PostgresClient
} from "../infrastructure/PostgresInfrastructure.js";

type SessionRow = {
		id: string;
		identity_subject_id: string;
		token_hash: string;
		csrf_token_hash: string;
		client_id: string | null;
		authentication_method: string;
		authenticated_at: string | Date;
		device_label: string | null;
		user_agent_fingerprint: string | null;
		status: string;
		idle_expires_at: string | Date;
		absolute_expires_at: string | Date;
		last_seen_at: string | Date;
		revoked_at: string | Date | null;
		revocation_reason: string | null;
		created_at: string | Date;
		updated_at: string | Date;
};

function toIso(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toSession(row: SessionRow): HapiSession {
		return {
				id: row.id,
				identitySubjectId: row.identity_subject_id,
				tokenHash: row.token_hash,
				csrfTokenHash: row.csrf_token_hash,
				...(row.client_id !== null ? { clientId: row.client_id } : {}),
				authenticationMethod: row.authentication_method as HapiSession["authenticationMethod"],
				authenticatedAt: toIso(row.authenticated_at),
				...(row.device_label !== null ? { deviceLabel: row.device_label } : {}),
				...(row.user_agent_fingerprint !== null ? { userAgentFingerprint: row.user_agent_fingerprint } : {}),
				status: row.status as HapiSession["status"],
				idleExpiresAt: toIso(row.idle_expires_at),
				absoluteExpiresAt: toIso(row.absolute_expires_at),
				lastSeenAt: toIso(row.last_seen_at),
				...(row.revoked_at !== null ? { revokedAt: toIso(row.revoked_at) } : {}),
				...(row.revocation_reason !== null ? { revocationReason: row.revocation_reason } : {}),
				createdAt: toIso(row.created_at),
				updatedAt: toIso(row.updated_at)
		};
}

// System-of-record implementation. Session mutations are guarded by the row's current status in
// the WHERE clause, so revocation and expiry are terminal even under concurrent requests.
export class PostgresHapiSessionRepository implements HapiSessionRepository {
		constructor(private readonly pool?: pg.Pool) {}

		private get reader(): PostgresClient {
				return (this.pool as PostgresClient | undefined) ?? getPostgresPool();
		}

		async create(command: CreateHapiSessionCommand): Promise<HapiSession> {
				const result = await this.reader.query<SessionRow>(
						`INSERT INTO hapi_sessions
								(id, identity_subject_id, token_hash, csrf_token_hash, client_id,
								 authentication_method, authenticated_at, device_label, user_agent_fingerprint,
								 status, idle_expires_at, absolute_expires_at, last_seen_at, created_at, updated_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11, $12, $12, $12)
						 RETURNING *`,
						[command.id, command.identitySubjectId, command.tokenHash, command.csrfTokenHash,
								command.clientId ?? null, command.authenticationMethod, command.authenticatedAt,
								command.deviceLabel ?? null, command.userAgentFingerprint ?? null,
								command.idleExpiresAt, command.absoluteExpiresAt, command.lastSeenAt]
				);
				return toSession(result.rows[0]);
		}

		async findByTokenHash(tokenHash: string): Promise<HapiSession | undefined> {
				const result = await this.reader.query<SessionRow>(
						`SELECT * FROM hapi_sessions WHERE token_hash = $1`,
						[tokenHash]
				);
				return result.rows[0] ? toSession(result.rows[0]) : undefined;
		}

		async findById(id: string): Promise<HapiSession | undefined> {
				const result = await this.reader.query<SessionRow>(
						`SELECT * FROM hapi_sessions WHERE id = $1`,
						[id]
				);
				return result.rows[0] ? toSession(result.rows[0]) : undefined;
		}

		async touch(id: string, lastSeenAt: string, idleExpiresAt: string): Promise<HapiSession | undefined> {
				// LEAST() enforces the absolute ceiling inside the database, not in application code.
				const result = await this.reader.query<SessionRow>(
						`UPDATE hapi_sessions
						 SET last_seen_at = $2,
								 idle_expires_at = LEAST($3::timestamptz, absolute_expires_at),
								 updated_at = $2
						 WHERE id = $1 AND status = 'active'
						 RETURNING *`,
						[id, lastSeenAt, idleExpiresAt]
				);
				return result.rows[0] ? toSession(result.rows[0]) : undefined;
		}

		async markExpired(id: string, at: string): Promise<void> {
				await this.reader.query(
						`UPDATE hapi_sessions
						 SET status = 'expired', updated_at = $2
						 WHERE id = $1 AND status = 'active'`,
						[id, at]
				);
		}

		async revoke(id: string, reason: string, at: string): Promise<HapiSession | undefined> {
				const result = await this.reader.query<SessionRow>(
						`UPDATE hapi_sessions
						 SET status = 'revoked', revoked_at = $3, revocation_reason = $2, updated_at = $3
						 WHERE id = $1 AND status = 'active'
						 RETURNING *`,
						[id, reason, at]
				);
				return result.rows[0] ? toSession(result.rows[0]) : undefined;
		}

		async revokeForSubject(
				identitySubjectId: string,
				sessionId: string,
				reason: string,
				at: string
		): Promise<RevokeSessionResult> {
				return withPostgresTransaction(async (client) => {
						const existing = await client.query<SessionRow>(
								`SELECT * FROM hapi_sessions WHERE id = $1 FOR UPDATE`,
								[sessionId]
						);
						const row = existing.rows[0];
						if (!row) {
								return { status: "rejected", reason: "not_found" };
						}
						if (row.identity_subject_id !== identitySubjectId) {
								// Never reveal whether the session exists for another subject.
								return { status: "rejected", reason: "wrong_subject" };
						}
						if (row.status !== "active") {
								return { status: "rejected", reason: "not_active" };
						}
						const revoked = await client.query<SessionRow>(
								`UPDATE hapi_sessions
								 SET status = 'revoked', revoked_at = $3, revocation_reason = $2, updated_at = $3
								 WHERE id = $1
								 RETURNING *`,
								[sessionId, reason, at]
						);
						return { status: "revoked", session: toSession(revoked.rows[0]) };
				}, this.pool);
		}

		async revokeAllForSubject(identitySubjectId: string, reason: string, at: string): Promise<number> {
				const result = await this.reader.query<{ id: string }>(
						`UPDATE hapi_sessions
						 SET status = 'revoked', revoked_at = $3, revocation_reason = $2, updated_at = $3
						 WHERE identity_subject_id = $1 AND status = 'active'
						 RETURNING id`,
						[identitySubjectId, reason, at]
				);
				return result.rows.length;
		}

		async listBySubject(identitySubjectId: string): Promise<HapiSession[]> {
				const result = await this.reader.query<SessionRow>(
						`SELECT * FROM hapi_sessions WHERE identity_subject_id = $1 ORDER BY created_at, id`,
						[identitySubjectId]
				);
				return result.rows.map(toSession);
		}
}
