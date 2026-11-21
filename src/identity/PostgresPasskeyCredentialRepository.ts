import { randomBytes } from "node:crypto";
import type pg from "pg";
import type { AuthenticatorTransportFuture, WebAuthnCredential } from "@simplewebauthn/server";
import { getPostgresPool, withPostgresTransaction, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

export class PasskeyAuthenticationRejected extends Error {}

type AuthenticationCredential = {
		id: string; publicKey: Uint8Array<ArrayBuffer>; counter: number;
		backupEligible: boolean; userHandle: string;
};

export class PostgresPasskeyCredentialRepository {
		constructor(private readonly pool?: pg.Pool) {}

		private get reader(): PostgresClient {
				return this.pool ?? getPostgresPool();
		}

		async userHandle(subjectId: string): Promise<Buffer> {
				const result = await this.reader.query<{ user_handle: Buffer }>(
						`INSERT INTO passkey_user_handles (identity_subject_id, user_handle)
						 SELECT id, $2 FROM identity_subjects WHERE id = $1 AND status = 'ACTIVE'
						 ON CONFLICT (identity_subject_id) DO UPDATE SET identity_subject_id = EXCLUDED.identity_subject_id
						 RETURNING user_handle`,
						[subjectId, randomBytes(32)]
				);
				if (!result.rows[0]) throw new Error("Passkey subject is not active");
				return result.rows[0].user_handle;
		}

		async activeCredentials(subjectId: string): Promise<{ id: string; transports: AuthenticatorTransportFuture[] }[]> {
				const result = await this.reader.query<{ credential_id: string; transports: AuthenticatorTransportFuture[] }>(
						`SELECT credential_id, transports FROM passkey_credentials
						 WHERE identity_subject_id = $1 AND revoked_at IS NULL`, [subjectId]);
				return result.rows.map(row => ({ id: row.credential_id, transports: row.transports }));
		}

		async nameInUse(subjectId: string, displayName: string): Promise<boolean> {
				const result = await this.reader.query(
						`SELECT 1 FROM passkey_credentials WHERE identity_subject_id = $1 AND revoked_at IS NULL
						 AND lower(display_name) = lower($2)`, [subjectId, displayName]);
				return result.rows.length > 0;
		}

		async list(subjectId: string, oidcSubject: string, expiresAt: number, authorizingCredentialId?: string):
				Promise<{ id: string; displayName: string | null; createdAt: Date; lastUsedAt: Date | null }[]> {
				return withPostgresTransaction(async client => {
						const subject = await client.query(
								`SELECT id FROM identity_subjects WHERE id = $1 AND oidc_subject = $2 AND status = 'ACTIVE'
								 AND clock_timestamp() < to_timestamp($3::double precision / 1000) FOR UPDATE`,
								[subjectId, oidcSubject, expiresAt]);
						if (!subject.rows[0]) throw new PasskeyAuthenticationRejected();
						if (authorizingCredentialId) {
								const active = await client.query(
										`SELECT 1 FROM passkey_credentials WHERE credential_id = $1 AND identity_subject_id = $2 AND revoked_at IS NULL`,
										[authorizingCredentialId, subjectId]);
								if (!active.rows[0]) throw new PasskeyAuthenticationRejected();
						}
						const live = await client.query<{ live: boolean }>(
								`SELECT clock_timestamp() < to_timestamp($1::double precision / 1000) AS live`, [expiresAt]);
						if (!live.rows[0].live) throw new PasskeyAuthenticationRejected();
						const result = await client.query<{ credential_id: string; display_name: string | null; created_at: Date; last_used_at: Date | null }>(
								`SELECT credential_id, display_name, created_at, last_used_at FROM passkey_credentials
								 WHERE identity_subject_id = $1 AND revoked_at IS NULL ORDER BY created_at, credential_id`, [subjectId]);
						return result.rows.map(row => ({ id: row.credential_id, displayName: row.display_name, createdAt: row.created_at, lastUsedAt: row.last_used_at }));
				}, this.pool);
		}

		async rename(subjectId: string, oidcSubject: string, credentialId: string, displayName: string,
				expiresAt: number, authorizingCredentialId?: string): Promise<boolean> {
				return withPostgresTransaction(async client => {
						const subject = await client.query(
								`SELECT id FROM identity_subjects WHERE id = $1 AND oidc_subject = $2 AND status = 'ACTIVE' FOR UPDATE`,
								[subjectId, oidcSubject]);
						if (!subject.rows[0]) return false;
						if (authorizingCredentialId) {
								const active = await client.query(
										`SELECT 1 FROM passkey_credentials WHERE credential_id = $1 AND identity_subject_id = $2 AND revoked_at IS NULL`,
										[authorizingCredentialId, subjectId]);
								if (!active.rows[0]) throw new PasskeyAuthenticationRejected();
						}
						const result = await client.query(
								`UPDATE passkey_credentials SET display_name = $3
								 WHERE identity_subject_id = $1 AND credential_id = $2 AND revoked_at IS NULL
								 AND clock_timestamp() < to_timestamp($4::double precision / 1000)
								 AND (display_name IS NOT NULL OR credential_id = $5 OR
								      (SELECT count(*) FROM passkey_credentials WHERE identity_subject_id = $1 AND revoked_at IS NULL) = 1)
								 RETURNING credential_id`, [subjectId, credentialId, displayName, expiresAt, authorizingCredentialId ?? null]);
						return result.rows.length === 1;
				}, this.pool);
		}

		async revoke(subjectId: string, oidcSubject: string, credentialId: string, expiresAt: number,
				authorizingCredentialId?: string, expectedName?: string): Promise<boolean> {
				return withPostgresTransaction(async client => {
						const subject = await client.query<{ id: string }>(
								`SELECT id FROM identity_subjects WHERE id = $1 AND oidc_subject = $2 AND status = 'ACTIVE' FOR UPDATE`,
								[subjectId, oidcSubject]);
						if (!subject.rows[0]) return false;
						if (authorizingCredentialId) {
								const active = await client.query(
										`SELECT 1 FROM passkey_credentials WHERE credential_id = $1 AND identity_subject_id = $2 AND revoked_at IS NULL`,
										[authorizingCredentialId, subjectId]);
								if (!active.rows[0]) throw new PasskeyAuthenticationRejected();
						}
						const result = await client.query<{ credential_id: string }>(
								`UPDATE passkey_credentials SET revoked_at = clock_timestamp()
								 WHERE identity_subject_id = $1 AND credential_id = $2 AND revoked_at IS NULL
								 AND clock_timestamp() < to_timestamp($3::double precision / 1000)
								 AND ($4::text IS NULL OR display_name = $4)
								 RETURNING credential_id`, [subjectId, credentialId, expiresAt, expectedName ?? null]);
						return result.rows.length === 1;
				}, this.pool);
		}

		async isActive(credentialId: string, subjectId: string, oidcSubject: string): Promise<boolean> {
				const result = await this.reader.query<{ credential_id: string }>(
						`SELECT c.credential_id FROM passkey_credentials c
						 JOIN identity_subjects s ON s.id = c.identity_subject_id
						 WHERE c.credential_id = $1 AND c.identity_subject_id = $2
						 AND s.oidc_subject = $3 AND s.status = 'ACTIVE' AND c.revoked_at IS NULL`,
						[credentialId, subjectId, oidcSubject]);
				return result.rows.length === 1;
		}

		async authenticate(credentialId: string, userHandle: string, expiresAt: number,
				verify: (credential: AuthenticationCredential) => Promise<{ counter: number; backupEligible: boolean; backupState: boolean }>)
				: Promise<{ subjectId: string; oidcSubject: string }> {
				return withPostgresTransaction(async client => {
						const result = await client.query<{
								credential_id: string; identity_subject_id: string; oidc_subject: string;
								user_handle: Buffer; public_key: Buffer; signature_counter: string; backup_eligible: boolean;
						}>(`SELECT c.credential_id, c.identity_subject_id, c.user_handle, c.public_key,
									c.signature_counter, c.backup_eligible, s.oidc_subject
							 FROM passkey_credentials c JOIN identity_subjects s ON s.id = c.identity_subject_id
							 WHERE c.credential_id = $1 AND c.revoked_at IS NULL AND s.status = 'ACTIVE'
							 FOR UPDATE OF c, s`, [credentialId]);
						const row = result.rows[0];
						if (!row || row.user_handle.toString("base64url") !== userHandle) throw new PasskeyAuthenticationRejected();
						const verified = await verify({ id: row.credential_id, publicKey: Uint8Array.from(row.public_key),
								counter: Number(row.signature_counter), backupEligible: row.backup_eligible, userHandle });
						if (verified.backupEligible !== row.backup_eligible) throw new PasskeyAuthenticationRejected();
						const updated = await client.query<{ credential_id: string }>(`UPDATE passkey_credentials
								SET signature_counter = GREATEST(signature_counter, $2), backup_state = $3, last_used_at = clock_timestamp()
								WHERE credential_id = $1 AND clock_timestamp() < to_timestamp($4::double precision / 1000)
								RETURNING credential_id`, [credentialId, verified.counter, verified.backupState, expiresAt]);
						if (!updated.rows[0]) throw new PasskeyAuthenticationRejected();
						return { subjectId: row.identity_subject_id, oidcSubject: row.oidc_subject };
				}, this.pool);
		}

		async insert(input: {
				subjectId: string; oidcSubject: string; userHandle: Buffer; authorityRef: string;
				expiresAt: number; additionalEnrollmentExpiresAt?: number; authorizingCredentialId?: string; credential: WebAuthnCredential;
				backupEligible: boolean; backupState: boolean; displayName?: string;
		}): Promise<void> {
				await withPostgresTransaction(async client => {
						const subject = await client.query<{ id: string }>(
								`SELECT id FROM identity_subjects WHERE id = $1 AND oidc_subject = $2 AND status = 'ACTIVE' FOR UPDATE`,
								[input.subjectId, input.oidcSubject]);
						if (!subject.rows[0]) throw new Error("Passkey subject is not active");
						if (input.authorizingCredentialId) {
								const active = await client.query(
										`SELECT 1 FROM passkey_credentials WHERE credential_id = $1 AND identity_subject_id = $2 AND revoked_at IS NULL`,
										[input.authorizingCredentialId, input.subjectId]);
								if (!active.rows[0]) throw new PasskeyAuthenticationRejected();
						}
						const existing = await client.query<{ requires_fresh_authentication: boolean }>(
								`SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE identity_subject_id = $1 AND revoked_at IS NULL)
								 AND clock_timestamp() >= to_timestamp($2::double precision / 1000) AS requires_fresh_authentication`,
								[input.subjectId, input.additionalEnrollmentExpiresAt ?? 0]);
						if (existing.rows[0].requires_fresh_authentication) throw new Error("Fresh authentication required to add another passkey");
						const inserted = await client.query<{ credential_id: string }>(
								`INSERT INTO passkey_credentials
										(credential_id, identity_subject_id, user_handle, public_key, signature_counter,
										 transports, backup_eligible, backup_state, enrollment_authority_ref, display_name)
								 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $11
								 WHERE clock_timestamp() < to_timestamp($10::double precision / 1000)
								 RETURNING credential_id`,
								[input.credential.id, input.subjectId, input.userHandle, Buffer.from(input.credential.publicKey),
										input.credential.counter, input.credential.transports ?? [], input.backupEligible,
										input.backupState, input.authorityRef, input.expiresAt, input.displayName ?? null]
						);
						if (!inserted.rows[0]) throw new Error("Passkey enrollment authority expired");
				}, this.pool);
		}
}
