import { configuration } from "../config/ConfigurationService.js";
import { resolveConfiguredIssuer } from "../config/IssuerPolicy.js";
import { STAGING_CONSOLE_CALLBACK, STAGING_ISSUER } from "../oidc/StagingTestConsole.js";
import { withPostgresTransaction, type TransactionRunner } from "./infrastructure/PostgresInfrastructure.js";

export const STAGING_WEB_ORIGINAL_CALLBACK = "https://staging-app.hapiinc.com/callback";

export function isStagingWebRedirectSet(uris: string[]): boolean {
	return uris[0] === STAGING_WEB_ORIGINAL_CALLBACK &&
		(uris.length === 1 || (uris.length === 2 && uris[1] === STAGING_CONSOLE_CALLBACK));
}

export async function registerStagingConsoleCallbackAtBoot(deps: {
	env?: NodeJS.ProcessEnv;
	issuer?: string;
	driver?: string;
	runTransaction?: TransactionRunner;
} = {}): Promise<"disabled" | "unchanged" | "registered"> {
	const env = deps.env ?? process.env;
	if (env.STAGING_TEST_CONSOLE_REGISTER_CALLBACK !== "true") return "disabled";
	if ((deps.issuer ?? resolveConfiguredIssuer()) !== STAGING_ISSUER ||
		(deps.driver ?? configuration.getIdentityRegistryDriver()) !== "postgres") {
		throw new Error("Staging callback registration requires the staging issuer and PostgreSQL");
	}
	return (deps.runTransaction ?? withPostgresTransaction)(async client => {
		const foreign = await client.query<{ client_id: string }>(
			"SELECT client_id FROM oidc_clients WHERE client_id <> ALL($1) LIMIT 1", [["staging-web", "staging-native"]]);
		if (foreign.rows.length) throw new Error("Staging callback registration refused: unexpected client");
		const result = await client.query<{
			application_id: string; token_endpoint_auth_method: string; require_pkce: boolean;
			status: string; redirect_uris: string[]; grant_types: string[];
		}>(`SELECT c.application_id, c.token_endpoint_auth_method, c.require_pkce, c.status, c.redirect_uris, c.grant_types
			FROM oidc_clients c JOIN applications a ON a.id = c.application_id
			JOIN tenants t ON t.id = a.tenant_id
			WHERE c.client_id = 'staging-web' AND a.application_key = 'HAPI_STAGING'
			AND a.status = 'active' AND t.slug = 'hapi-staging' AND t.status = 'active' FOR UPDATE OF c`);
		const row = result.rows[0];
		if (!row || row.status !== "active" || row.token_endpoint_auth_method !== "client_secret_basic" ||
			!row.require_pkce || row.grant_types.length !== 1 || row.grant_types[0] !== "authorization_code" ||
			!isStagingWebRedirectSet(row.redirect_uris)) {
			throw new Error("Staging callback registration refused: client configuration does not match");
		}
		const native = await client.query<{ application_id: string; token_endpoint_auth_method: string; status: string }>(
			"SELECT application_id, token_endpoint_auth_method, status FROM oidc_clients WHERE client_id = 'staging-native'");
		if (native.rows.length !== 1 || native.rows[0].application_id !== row.application_id ||
			native.rows[0].token_endpoint_auth_method !== "none" || native.rows[0].status !== "active") {
			throw new Error("Staging callback registration refused: staging-native is not valid");
		}
		if (row.redirect_uris.includes(STAGING_CONSOLE_CALLBACK)) return "unchanged";
		const updated = await client.query<{ client_id: string }>(
			"UPDATE oidc_clients SET redirect_uris = $1, updated_at = now() WHERE client_id = 'staging-web' RETURNING client_id",
			[[...row.redirect_uris, STAGING_CONSOLE_CALLBACK]]);
		if (updated.rows.length !== 1) throw new Error("Staging callback registration failed");
		return "registered";
	});
}
