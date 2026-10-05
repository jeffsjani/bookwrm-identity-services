import type { IdentityClaimName } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";
import type { ClaimSourceMap, ClaimTimestampMap, IdentityClaimSourceStore } from "./IdentityClaimSourceStore.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

type ProvenanceRow = {
		claim_name: string;
		source: string;
		updated_at: string | Date;
};

function toIsoString(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

// System-of-record implementation (Task 1/2). Accepts an explicit client override so H3's
// registration transaction can bind this store to the SAME open pg.PoolClient as the rest of its
// unit of work (Task 4) -- never a second, independent connection/transaction.
export class PostgresIdentityClaimSourceStore implements IdentityClaimSourceStore {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		async getClaimSources(identitySubjectId: string): Promise<ClaimSourceMap> {
				const result = await this.client.query<ProvenanceRow>(
						"SELECT claim_name, source, updated_at FROM identity_claim_provenance WHERE identity_subject_id = $1",
						[identitySubjectId]
				);
				const sources: ClaimSourceMap = {};
				for (const row of result.rows) {
						sources[row.claim_name as IdentityClaimName] = row.source as IdentityClaimSource;
				}
				return sources;
		}

		async getClaimUpdatedAt(identitySubjectId: string): Promise<ClaimTimestampMap> {
				const result = await this.client.query<ProvenanceRow>(
						"SELECT claim_name, source, updated_at FROM identity_claim_provenance WHERE identity_subject_id = $1",
						[identitySubjectId]
				);
				const timestamps: ClaimTimestampMap = {};
				for (const row of result.rows) {
						timestamps[row.claim_name as IdentityClaimName] = toIsoString(row.updated_at);
				}
				return timestamps;
		}

		// Upsert semantics (Task 11): the latest authorized write always wins and updatedAt always
		// reflects it; concurrent writers are serialized by Postgres itself, never process-local
		// locking/race protection.
		async recordClaimSource(identitySubjectId: string, claim: IdentityClaimName, source: IdentityClaimSource, timestamp: string): Promise<void> {
				await this.client.query(
						`INSERT INTO identity_claim_provenance (identity_subject_id, claim_name, source, updated_at)
						 VALUES ($1, $2, $3, $4)
						 ON CONFLICT (identity_subject_id, claim_name) DO UPDATE SET source = $3, updated_at = $4`,
						[identitySubjectId, claim, source, new Date(timestamp)]
				);
		}
}
