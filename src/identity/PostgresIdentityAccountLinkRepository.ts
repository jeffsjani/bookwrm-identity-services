import type { IdentityAccountLink, IdentityAccountLinkSource, IdentityAccountLinkStatus } from "../models/IdentityAccountLink.js";
import type { CreateIdentityAccountLinkInput, IdentityAccountLinkRepository } from "./IdentityAccountLinkRepository.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

type IdentityAccountLinkRow = {
		id: string;
		source: string;
		external_user_id: string;
		identity_subject_id: string;
		status: string;
		linked_at: string | Date;
		updated_at: string | Date;
};

const UNIQUE_VIOLATION = "23505";

function toIsoString(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toAccountLink(row: IdentityAccountLinkRow): IdentityAccountLink {
		return {
				id: row.id,
				source: row.source as IdentityAccountLinkSource,
				externalUserId: row.external_user_id,
				identitySubjectId: row.identity_subject_id,
				status: row.status as IdentityAccountLinkStatus,
				linkedAt: toIsoString(row.linked_at),
				updatedAt: toIsoString(row.updated_at)
		};
}

function isUniqueViolation(error: unknown): boolean {
		return Boolean(error) && typeof error === "object" && (error as { code?: string }).code === UNIQUE_VIOLATION;
}

// System-of-record implementation; the (source, external_user_id) unique constraint is the sole
// concurrency guarantee that a Bookwrm account can never silently become linked to a different IdentitySubject.
export class PostgresIdentityAccountLinkRepository implements IdentityAccountLinkRepository {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		async findByExternalUserId(source: IdentityAccountLinkSource, externalUserId: string): Promise<IdentityAccountLink | undefined> {
				const result = await this.client.query<IdentityAccountLinkRow>(
						`SELECT * FROM identity_account_links WHERE source = $1 AND external_user_id = $2`,
						[source, externalUserId]
				);

				return result.rows[0] ? toAccountLink(result.rows[0]) : undefined;
		}

		async create(input: CreateIdentityAccountLinkInput): Promise<IdentityAccountLink> {
				const now = new Date();

				try {
						const result = await this.client.query<IdentityAccountLinkRow>(
								`INSERT INTO identity_account_links
									(id, source, external_user_id, identity_subject_id, status, linked_at, updated_at)
								 VALUES ($1, $2, $3, $4, $5, $6, $6)
								 RETURNING *`,
								[input.id, input.source, input.externalUserId, input.identitySubjectId, input.status, now]
						);

						return toAccountLink(result.rows[0]);
				} catch (error) {
						if (isUniqueViolation(error)) {
								throw new Error(`IdentityAccountLink already exists for ${input.source}:${input.externalUserId}`);
						}

						throw error;
				}
		}
}
