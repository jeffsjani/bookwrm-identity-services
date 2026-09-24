import type { OIDCClientRecord, OIDCClientTokenEndpointAuthMethod } from "../models/OIDCClientRecord.js";
import type { OIDCClientRepository, UpsertOIDCClientInput } from "./OIDCClientRepository.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

type OIDCClientRow = {
		id: string;
		application_id: string;
		client_id: string;
		client_secret: string;
		redirect_uris: string[];
		scopes: string[];
		grant_types: string[];
		response_types: string[];
		token_endpoint_auth_method: string;
		require_pkce: boolean;
		created_at: string | Date;
		updated_at: string | Date;
};

function toIsoString(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toOIDCClientRecord(row: OIDCClientRow): OIDCClientRecord {
		return {
				id: row.id,
				applicationId: row.application_id,
				clientId: row.client_id,
				clientSecret: row.client_secret,
				redirectUris: row.redirect_uris,
				scopes: row.scopes,
				grantTypes: row.grant_types,
				responseTypes: row.response_types,
				tokenEndpointAuthMethod: row.token_endpoint_auth_method as OIDCClientTokenEndpointAuthMethod,
				requirePkce: row.require_pkce,
				createdAt: toIsoString(row.created_at),
				updatedAt: toIsoString(row.updated_at)
		};
}

export class PostgresOIDCClientRepository implements OIDCClientRepository {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		async findByClientId(clientId: string): Promise<OIDCClientRecord | undefined> {
				const result = await this.client.query<OIDCClientRow>(
						`SELECT * FROM oidc_clients WHERE client_id = $1`,
						[clientId]
				);
				return result.rows[0] ? toOIDCClientRecord(result.rows[0]) : undefined;
		}

		async listByApplication(applicationId: string): Promise<OIDCClientRecord[]> {
				const result = await this.client.query<OIDCClientRow>(
						`SELECT * FROM oidc_clients WHERE application_id = $1 ORDER BY created_at ASC`,
						[applicationId]
				);
				return result.rows.map(toOIDCClientRecord);
		}

		async list(): Promise<OIDCClientRecord[]> {
				const result = await this.client.query<OIDCClientRow>(`SELECT * FROM oidc_clients ORDER BY created_at ASC`);
				return result.rows.map(toOIDCClientRecord);
		}

		async upsert(input: UpsertOIDCClientInput): Promise<OIDCClientRecord> {
				const now = new Date();
				const result = await this.client.query<OIDCClientRow>(
						`INSERT INTO oidc_clients
							(id, application_id, client_id, client_secret, redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, require_pkce, created_at, updated_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
						 ON CONFLICT (client_id) DO UPDATE SET
							application_id = $2,
							client_secret = $4,
							redirect_uris = $5,
							scopes = $6,
							grant_types = $7,
							response_types = $8,
							token_endpoint_auth_method = $9,
							require_pkce = $10,
							updated_at = $11
						 RETURNING *`,
						[
								input.id,
								input.applicationId,
								input.clientId,
								input.clientSecret,
								input.redirectUris,
								input.scopes,
								input.grantTypes,
								input.responseTypes,
								input.tokenEndpointAuthMethod,
								input.requirePkce,
								now
						]
				);

				return toOIDCClientRecord(result.rows[0]);
		}
}
