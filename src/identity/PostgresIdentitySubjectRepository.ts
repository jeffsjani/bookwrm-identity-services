import type { IdentityProvider, IdentitySubject } from "../models/IdentitySubject.js";
import type {
		CreateIdentitySubjectInput,
		IdentitySubjectRepository,
		UpdateIdentitySubjectInput
} from "./IdentitySubjectRepository.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

type IdentitySubjectRow = {
		id: string;
		oidc_subject: string;
		primary_provider: string;
		primary_provider_subject: string;
		email: string;
		email_verified: boolean;
		display_name: string;
		status: string;
		created_at: string | Date;
		updated_at: string | Date;
		last_authenticated_at: string | Date | null;
};

function toIsoString(value: string | Date | null): string | undefined {
		if (value === null) {
				return undefined;
		}

		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toIdentitySubject(row: IdentitySubjectRow): IdentitySubject {
		return {
				id: row.id,
				oidcSubject: row.oidc_subject,
				primaryProvider: row.primary_provider as IdentityProvider,
				primaryProviderSubject: row.primary_provider_subject,
				email: row.email,
				emailVerified: row.email_verified,
				displayName: row.display_name,
				status: row.status as IdentitySubject["status"],
				createdAt: toIsoString(row.created_at) as string,
				updatedAt: toIsoString(row.updated_at) as string,
				lastAuthenticatedAt: toIsoString(row.last_authenticated_at)
		};
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Malformed input must read as "not found", never a raw Postgres type error (Task 7 security review).
function isValidUuid(value: string): boolean {
		return UUID_PATTERN.test(value);
}

// System-of-record implementation; database uniqueness constraints are the sole concurrency guarantee (RC1 Task 5).
export class PostgresIdentitySubjectRepository implements IdentitySubjectRepository {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		// Deferred so constructing a repository never opens a DB connection until first used.
		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		async create(input: CreateIdentitySubjectInput): Promise<IdentitySubject> {
				const now = new Date();
				const result = await this.client.query<IdentitySubjectRow>(
						`INSERT INTO identity_subjects
							(id, oidc_subject, primary_provider, primary_provider_subject, email, email_verified, display_name, status, created_at, updated_at, last_authenticated_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9)
						 RETURNING *`,
						[
								input.id,
								input.oidcSubject,
								input.primaryProvider,
								input.primaryProviderSubject,
								input.email,
								input.emailVerified,
								input.displayName,
								input.status,
								now
						]
				);

				return toIdentitySubject(result.rows[0]);
		}

		async findByOidcSubject(oidcSubject: string): Promise<IdentitySubject | undefined> {
				if (!isValidUuid(oidcSubject)) {
						return undefined;
				}

				const result = await this.client.query<IdentitySubjectRow>(
						`SELECT * FROM identity_subjects WHERE oidc_subject = $1`,
						[oidcSubject]
				);

				return result.rows[0] ? toIdentitySubject(result.rows[0]) : undefined;
		}

		async findByProviderSubject(provider: IdentityProvider, providerSubject: string): Promise<IdentitySubject | undefined> {
				const result = await this.client.query<IdentitySubjectRow>(
						`SELECT * FROM identity_subjects WHERE primary_provider = $1 AND primary_provider_subject = $2`,
						[provider, providerSubject]
				);

				return result.rows[0] ? toIdentitySubject(result.rows[0]) : undefined;
		}

		async update(oidcSubject: string, changes: UpdateIdentitySubjectInput): Promise<IdentitySubject | undefined> {
				const fields: string[] = [];
				const values: unknown[] = [];

				if (changes.email !== undefined) {
						values.push(changes.email);
						fields.push(`email = $${values.length}`);
				}
				if (changes.emailVerified !== undefined) {
						values.push(changes.emailVerified);
						fields.push(`email_verified = $${values.length}`);
				}
				if (changes.displayName !== undefined) {
						values.push(changes.displayName);
						fields.push(`display_name = $${values.length}`);
				}
				if (changes.status !== undefined) {
						values.push(changes.status);
						fields.push(`status = $${values.length}`);
				}

				if (fields.length === 0) {
						return this.findByOidcSubject(oidcSubject);
				}

				values.push(new Date());
				fields.push(`updated_at = $${values.length}`);
				values.push(oidcSubject);

				const result = await this.client.query<IdentitySubjectRow>(
						`UPDATE identity_subjects SET ${fields.join(", ")} WHERE oidc_subject = $${values.length} RETURNING *`,
						values
				);

				return result.rows[0] ? toIdentitySubject(result.rows[0]) : undefined;
		}

		async touchLastAuthentication(oidcSubject: string): Promise<IdentitySubject | undefined> {
				const now = new Date();
				const result = await this.client.query<IdentitySubjectRow>(
						`UPDATE identity_subjects
						 SET updated_at = $2, last_authenticated_at = $2
						 WHERE oidc_subject = $1
						 RETURNING *`,
						[oidcSubject, now]
				);

				return result.rows[0] ? toIdentitySubject(result.rows[0]) : undefined;
		}

		async delete(oidcSubject: string): Promise<boolean> {
				const result = await this.client.query(
						`DELETE FROM identity_subjects WHERE oidc_subject = $1 RETURNING id`,
						[oidcSubject]
				);
				return result.rows.length > 0;
		}

		async exists(provider: IdentityProvider, providerSubject: string): Promise<boolean> {
				const result = await this.client.query(
						`SELECT 1 FROM identity_subjects WHERE primary_provider = $1 AND primary_provider_subject = $2`,
						[provider, providerSubject]
				);

				return result.rows.length > 0;
		}

		// The (primary_provider, primary_provider_subject) unique constraint is the collision guarantee here:
		// a duplicate-key error surfaces as a rejected promise, which callers must treat as "already linked".
		async relinkPrimaryProviderSubject(oidcSubject: string, newProviderSubject: string): Promise<IdentitySubject | undefined> {
				if (!isValidUuid(oidcSubject)) {
						return undefined;
				}

				const result = await this.client.query<IdentitySubjectRow>(
						`UPDATE identity_subjects
						 SET primary_provider_subject = $2, updated_at = $3
						 WHERE oidc_subject = $1
						 RETURNING *`,
						[oidcSubject, newProviderSubject, new Date()]
				);

				return result.rows[0] ? toIdentitySubject(result.rows[0]) : undefined;
		}

		async list(): Promise<IdentitySubject[]> {
				const result = await this.client.query<IdentitySubjectRow>(`SELECT * FROM identity_subjects ORDER BY created_at ASC`);
				return result.rows.map(toIdentitySubject);
		}

		async findByEmail(email: string): Promise<IdentitySubject[]> {
				const result = await this.client.query<IdentitySubjectRow>(
						`SELECT * FROM identity_subjects WHERE email = $1 ORDER BY created_at ASC`,
						[email]
				);
				return result.rows.map(toIdentitySubject);
		}

		// Single-statement UPSERT: the unique (primary_provider, primary_provider_subject) constraint
		// makes this atomic under concurrent callers -- exactly one row is ever inserted per provider identity.
		async resolveOrCreate(input: CreateIdentitySubjectInput): Promise<IdentitySubject> {
				const now = new Date();
				const result = await this.client.query<IdentitySubjectRow>(
						`INSERT INTO identity_subjects
							(id, oidc_subject, primary_provider, primary_provider_subject, email, email_verified, display_name, status, created_at, updated_at, last_authenticated_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9)
						 ON CONFLICT (primary_provider, primary_provider_subject)
						 DO UPDATE SET updated_at = $9, last_authenticated_at = $9
						 RETURNING *`,
						[
								input.id,
								input.oidcSubject,
								input.primaryProvider,
								input.primaryProviderSubject,
								input.email,
								input.emailVerified,
								input.displayName,
								input.status,
								now
						]
				);

				return toIdentitySubject(result.rows[0]);
		}
}
