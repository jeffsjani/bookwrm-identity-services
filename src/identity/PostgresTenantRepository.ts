import type { Tenant, TenantStatus } from "../models/Tenant.js";
import type { TenantRepository, UpsertTenantInput } from "./TenantRepository.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

type TenantRow = {
		id: string;
		name: string;
		slug: string;
		status: string;
		created_at: string | Date;
		updated_at: string | Date;
};

function toIsoString(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toTenant(row: TenantRow): Tenant {
		return {
				id: row.id,
				name: row.name,
				slug: row.slug,
				status: row.status as TenantStatus,
				createdAt: toIsoString(row.created_at),
				updatedAt: toIsoString(row.updated_at)
		};
}

export class PostgresTenantRepository implements TenantRepository {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		async findById(id: string): Promise<Tenant | undefined> {
				const result = await this.client.query<TenantRow>(`SELECT * FROM tenants WHERE id = $1`, [id]);
				return result.rows[0] ? toTenant(result.rows[0]) : undefined;
		}

		async findBySlug(slug: string): Promise<Tenant | undefined> {
				const result = await this.client.query<TenantRow>(`SELECT * FROM tenants WHERE slug = $1`, [slug]);
				return result.rows[0] ? toTenant(result.rows[0]) : undefined;
		}

		async list(): Promise<Tenant[]> {
				const result = await this.client.query<TenantRow>(`SELECT * FROM tenants ORDER BY created_at ASC`);
				return result.rows.map(toTenant);
		}

		async upsert(input: UpsertTenantInput): Promise<Tenant> {
				const now = new Date();
				const result = await this.client.query<TenantRow>(
						`INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
						 VALUES ($1, $2, $3, $4, $5, $5)
						 ON CONFLICT (id) DO UPDATE SET name = $2, slug = $3, status = $4, updated_at = $5
						 RETURNING *`,
						[input.id, input.name, input.slug, input.status, now]
				);

				return toTenant(result.rows[0]);
		}
}
