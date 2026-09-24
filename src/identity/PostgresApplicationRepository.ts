import type { Application, ApplicationStatus } from "../models/Application.js";
import type { ApplicationRepository, UpsertApplicationInput } from "./ApplicationRepository.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

type ApplicationRow = {
		id: string;
		tenant_id: string;
		name: string;
		slug: string;
		status: string;
		created_at: string | Date;
		updated_at: string | Date;
};

function toIsoString(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toApplication(row: ApplicationRow): Application {
		return {
				id: row.id,
				tenantId: row.tenant_id,
				name: row.name,
				slug: row.slug,
				status: row.status as ApplicationStatus,
				createdAt: toIsoString(row.created_at),
				updatedAt: toIsoString(row.updated_at)
		};
}

export class PostgresApplicationRepository implements ApplicationRepository {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		async findById(id: string): Promise<Application | undefined> {
				const result = await this.client.query<ApplicationRow>(`SELECT * FROM applications WHERE id = $1`, [id]);
				return result.rows[0] ? toApplication(result.rows[0]) : undefined;
		}

		async findByTenantAndSlug(tenantId: string, slug: string): Promise<Application | undefined> {
				const result = await this.client.query<ApplicationRow>(
						`SELECT * FROM applications WHERE tenant_id = $1 AND slug = $2`,
						[tenantId, slug]
				);
				return result.rows[0] ? toApplication(result.rows[0]) : undefined;
		}

		async listByTenant(tenantId: string): Promise<Application[]> {
				const result = await this.client.query<ApplicationRow>(
						`SELECT * FROM applications WHERE tenant_id = $1 ORDER BY created_at ASC`,
						[tenantId]
				);
				return result.rows.map(toApplication);
		}

		async upsert(input: UpsertApplicationInput): Promise<Application> {
				const now = new Date();
				const result = await this.client.query<ApplicationRow>(
						`INSERT INTO applications (id, tenant_id, name, slug, status, created_at, updated_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $6)
						 ON CONFLICT (id) DO UPDATE SET tenant_id = $2, name = $3, slug = $4, status = $5, updated_at = $6
						 RETURNING *`,
						[input.id, input.tenantId, input.name, input.slug, input.status, now]
				);

				return toApplication(result.rows[0]);
		}
}
