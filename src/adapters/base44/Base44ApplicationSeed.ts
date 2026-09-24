import { randomUUID } from "node:crypto";

import { configuration } from "../../config/ConfigurationService.js";
import { BOOKWRM_TENANT_ID, BOOKWRM_APPLICATION_ID } from "../../identity/WellKnownIdentities.js";
import type { TenantRepository } from "../../identity/TenantRepository.js";
import type { ApplicationRepository } from "../../identity/ApplicationRepository.js";
import type { OIDCClientRepository } from "../../identity/OIDCClientRepository.js";
import { inMemoryTenantRepository } from "../../identity/InMemoryTenantRepository.js";
import { inMemoryApplicationRepository } from "../../identity/InMemoryApplicationRepository.js";
import { inMemoryOIDCClientRepository } from "../../identity/InMemoryOIDCClientRepository.js";
import { PostgresTenantRepository } from "../../identity/PostgresTenantRepository.js";
import { PostgresApplicationRepository } from "../../identity/PostgresApplicationRepository.js";
import { PostgresOIDCClientRepository } from "../../identity/PostgresOIDCClientRepository.js";
import { getPostgresPool, type PostgresClient } from "../../identity/infrastructure/PostgresInfrastructure.js";
import { registerBase44OIDCClient } from "./Base44OIDCClientAdapter.js";

export type Base44ApplicationSeedResult = {
		tenantId: string;
		applicationId: string;
		clientSeeded: boolean;
		backfilledIdentitySubjects: number;
};

export type Base44ApplicationSeedDependencies = {
		tenants?: TenantRepository;
		applications?: ApplicationRepository;
		oidcClients?: OIDCClientRepository;
		postgresClient?: PostgresClient;
};

function defaultTenants(): TenantRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? inMemoryTenantRepository
				: new PostgresTenantRepository();
}

function defaultApplications(): ApplicationRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? inMemoryApplicationRepository
				: new PostgresApplicationRepository();
}

function defaultOidcClients(): OIDCClientRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? inMemoryOIDCClientRepository
				: new PostgresOIDCClientRepository();
}

// Backfills pre-H1 identity_subjects rows (application_id IS NULL) onto Bookwrm's Application.
// No-op on the memory driver -- there is no cross-process state to migrate there.
async function backfillIdentitySubjects(applicationId: string, client?: PostgresClient): Promise<number> {
		if (configuration.getIdentityRegistryDriver() !== "postgres") {
				return 0;
		}

		const pool = client ?? getPostgresPool();
		const result = await pool.query<{ id: string }>(
				`UPDATE identity_subjects SET application_id = $1 WHERE application_id IS NULL RETURNING id`,
				[applicationId]
		);

		return result.rows.length;
}

// Bookwrm/Base44-scoped migration: seeds Tenant #1 (Bookwrm) + Application #1 (Bookwrm Base44) + its
// OIDCClient row from the legacy env-driven Base44 config, then backfills any pre-H1 IdentitySubjects
// onto that Application. Idempotent -- safe to run on every process start (mirrors ensureIdentitySchema()).
export async function ensureBookwrmApplicationSeed(
		deps: Base44ApplicationSeedDependencies = {}
): Promise<Base44ApplicationSeedResult> {
		const tenants = deps.tenants ?? defaultTenants();
		const applications = deps.applications ?? defaultApplications();
		const oidcClients = deps.oidcClients ?? defaultOidcClients();

		const tenant = await tenants.upsert({
				id: BOOKWRM_TENANT_ID,
				name: "Bookwrm",
				slug: "bookwrm",
				status: "active"
		});

		const application = await applications.upsert({
				id: BOOKWRM_APPLICATION_ID,
				tenantId: tenant.id,
				name: "Bookwrm Base44",
				slug: "bookwrm-base44",
				status: "active"
		});

		const [legacyClient] = registerBase44OIDCClient();
		let clientSeeded = false;
		if (legacyClient) {
				await oidcClients.upsert({
						id: randomUUID(),
						applicationId: application.id,
						clientId: legacyClient.client_id,
						clientSecret: legacyClient.client_secret,
						redirectUris: legacyClient.redirect_uris,
						scopes: legacyClient.scope.split(" ").filter((scope) => scope.length > 0),
						grantTypes: legacyClient.grant_types,
						responseTypes: legacyClient.response_types,
						tokenEndpointAuthMethod: legacyClient.token_endpoint_auth_method,
						requirePkce: legacyClient.require_pkce
				});
				clientSeeded = true;
		}

		const backfilledIdentitySubjects = await backfillIdentitySubjects(application.id, deps.postgresClient);

		return {
				tenantId: tenant.id,
				applicationId: application.id,
				clientSeeded,
				backfilledIdentitySubjects
		};
}
