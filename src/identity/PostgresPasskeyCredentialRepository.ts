import { randomBytes } from "node:crypto";
import type pg from "pg";
import type { AuthenticatorTransportFuture, WebAuthnCredential } from "@simplewebauthn/server";
import { getPostgresPool, withPostgresTransaction, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

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

		async insert(input: {
				subjectId: string; oidcSubject: string; userHandle: Buffer; authorityRef: string;
				expiresAt: number; credential: WebAuthnCredential; backupEligible: boolean; backupState: boolean;
		}): Promise<void> {
				await withPostgresTransaction(async client => {
						const subject = await client.query<{ id: string }>(
								`SELECT id FROM identity_subjects WHERE id = $1 AND oidc_subject = $2 AND status = 'ACTIVE' FOR UPDATE`,
								[input.subjectId, input.oidcSubject]);
						if (!subject.rows[0]) throw new Error("Passkey subject is not active");
						const inserted = await client.query<{ credential_id: string }>(
								`INSERT INTO passkey_credentials
										(credential_id, identity_subject_id, user_handle, public_key, signature_counter,
										 transports, backup_eligible, backup_state, enrollment_authority_ref)
								 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
								 WHERE clock_timestamp() < to_timestamp($10::double precision / 1000)
								 RETURNING credential_id`,
								[input.credential.id, input.subjectId, input.userHandle, Buffer.from(input.credential.publicKey),
										input.credential.counter, input.credential.transports ?? [], input.backupEligible,
										input.backupState, input.authorityRef, input.expiresAt]
						);
						if (!inserted.rows[0]) throw new Error("Passkey enrollment authority expired");
				}, this.pool);
		}
}
