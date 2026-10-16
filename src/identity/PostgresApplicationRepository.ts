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
		application_key: string;
		allowed_authentication_methods: Application["allowedAuthenticationMethods"];
		allowed_identity_providers: string[];
		face_setup_enabled: boolean;
		presentation: Application["presentation"];
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
				applicationKey: row.application_key,
				allowedAuthenticationMethods: row.allowed_authentication_methods,
				allowedIdentityProviders: row.allowed_identity_providers,
				faceSetupEnabled: row.face_setup_enabled,
				presentation: row.presentation,
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
						`INSERT INTO applications (id, tenant_id, name, slug, status, created_at, updated_at,
						 application_key, allowed_authentication_methods, allowed_identity_providers, face_setup_enabled, presentation)
						 VALUES ($1::uuid, $2, $3, $4, $5, $6, $6, COALESCE($7,$1::text),
						 COALESCE($8,ARRAY['HAPI_EMAIL']),COALESCE($9,ARRAY[]::text[]),COALESCE($10,false),COALESCE($11,'{}'::jsonb))
						 ON CONFLICT (id) DO UPDATE SET tenant_id = $2, name = $3, slug = $4, status = $5, updated_at = $6,
						 application_key=COALESCE($7,applications.application_key),
						 allowed_authentication_methods=COALESCE($8,applications.allowed_authentication_methods),
						 allowed_identity_providers=COALESCE($9,applications.allowed_identity_providers),
						 face_setup_enabled=COALESCE($10,applications.face_setup_enabled),
						 presentation=COALESCE($11,applications.presentation)
						 RETURNING *`,
						[input.id, input.tenantId, input.name, input.slug, input.status, now,
						 input.applicationKey ?? null, input.allowedAuthenticationMethods ?? null,
						 input.allowedIdentityProviders ?? null, input.faceSetupEnabled ?? null, input.presentation ?? null]
				);

				return toApplication(result.rows[0]);
		}
}
