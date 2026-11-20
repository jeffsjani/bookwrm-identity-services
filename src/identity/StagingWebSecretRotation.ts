import { createHash } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import { resolveConfiguredIssuer } from "../config/IssuerPolicy.js";
import { constantTimeStringEqual } from "../security/ServiceAuthentication.js";
import {
		withPostgresTransaction,
		type PostgresClient,
		type TransactionRunner
} from "./infrastructure/PostgresInfrastructure.js";

// =============================================================================
// HAPI ID V2-E Stage 3 — one-time, flag-gated staging-web client-secret rotation
// =============================================================================
// Boot-time replacement for the retired temporary-Railway-job procedure (see the
// Stage 3 rotation runbook §7). Ports the reviewed fail-closed guards of
// scripts/rotate-staging-web-secret.sql with ONE deliberate change: the
// "BOOKWRM application must be absent" guard is replaced, because the deployed
// staging backend itself seeds the BOOKWRM tenant/application at every boot
// (ensureBookwrmApplicationSeed), so BOOKWRM presence is legitimate in staging
// and proves nothing. The replacement is a POSITIVE staging fingerprint: the
// 'hapi-staging' tenant + 'HAPI_STAGING' application seeded by the certified
// Stage 2 scripts/seed-staging-clients.sql must exist, both staging clients
// must belong to that application, and no OIDC client outside the staging pair
// may exist (a production registry always contains the Bookwrm/Base44 client;
// OIDC_BASE44_* is never set in staging per the Stage 1 isolation matrix).
//
// Secret handling: the value moves environment -> parameterized query ($1), so
// it never appears in statement text, argv, files, or any log/return value.
// Success/failure logs carry only status, length, and an md5-8 fingerprint.
// =============================================================================

export const STAGING_WEB_SECRET_ROTATION_FLAG = "STAGING_WEB_SECRET_ROTATION_ENABLED";
export const STAGING_WEB_CLIENT_SECRET_VARIABLE = "STAGING_WEB_CLIENT_SECRET";

const STAGING_ISSUER = "https://id-staging.hapiinc.com";
const STAGING_CLIENT_IDS = ["staging-web", "staging-native"];
const STAGING_WEB_REDIRECT_URIS = ["https://staging-app.hapiinc.com/callback"];
const STAGING_WEB_GRANT_TYPES = ["authorization_code"];

export type StagingWebSecretRotationResult = "disabled" | "rotated" | "unchanged";

export type StagingWebSecretRotationDependencies = {
		env?: Record<string, string | undefined>;
		issuer?: string;
		driver?: "postgres" | "memory";
		runTransaction?: TransactionRunner;
};

type RotationLogger = {
		info: (details: object, message: string) => void;
};

type OidcClientRow = {
		application_id: string;
		client_id: string;
		client_secret: string;
		token_endpoint_auth_method: string;
		require_pkce: boolean;
		status: string;
		redirect_uris: string[];
		grant_types: string[];
		updated_at: Date | string;
};

// All refusal/abort messages are secret-free by construction.
function refusal(reason: string): Error {
		return new Error(`staging-web secret rotation refused: ${reason}`);
}

function arraysEqual(actual: readonly string[], expected: readonly string[]): boolean {
		return actual.length === expected.length && expected.every((value, index) => actual[index] === value);
}

function timestampMs(value: Date | string): number {
		return new Date(value).getTime();
}

function fingerprintMd5_8(secret: string): string {
		return createHash("md5").update(secret).digest("hex").slice(0, 8);
}

async function selectClient(client: PostgresClient, clientId: string, forUpdate: boolean): Promise<OidcClientRow | undefined> {
		const result = await client.query<OidcClientRow>(
				`SELECT application_id, client_id, client_secret, token_endpoint_auth_method, require_pkce,
						status, redirect_uris, grant_types, updated_at
				 FROM oidc_clients WHERE client_id = $1${forUpdate ? " FOR UPDATE" : ""}`,
				[clientId]
		);
		return result.rows[0];
}

// Runs inside one transaction: every throw rolls the whole mutation back.
async function rotateInTransaction(client: PostgresClient, secret: string): Promise<StagingWebSecretRotationResult> {
		// Leak guard: parameterized values stay out of statement text, but server-side
		// parameter logging would persist them. Refuse while any such channel is open.
		const settings = await client.query<{ name: string; setting: string }>(
				`SELECT name, setting FROM pg_settings
				 WHERE name IN ('log_statement', 'log_min_duration_statement', 'log_parameter_max_length_on_error')`
		);
		for (const { name, setting } of settings.rows) {
				if (name === "log_statement" && (setting === "all" || setting === "mod")) {
						throw refusal(`log_statement=${setting} could write query parameters to server logs`);
				}
				if (name === "log_min_duration_statement" && setting !== "-1") {
						throw refusal(`log_min_duration_statement=${setting} could write query parameters to server logs`);
				}
				if (name === "log_parameter_max_length_on_error" && setting !== "0") {
						throw refusal(`log_parameter_max_length_on_error=${setting} could write query parameters to server logs`);
				}
		}

		// Staging registry fingerprint 1: no OIDC client outside the staging pair.
		const foreign = await client.query<{ client_id: string }>(
				`SELECT client_id FROM oidc_clients WHERE client_id <> ALL($1) LIMIT 1`,
				[STAGING_CLIENT_IDS]
		);
		if (foreign.rows[0]) {
				throw refusal(`non-staging OIDC client "${foreign.rows[0].client_id}" exists — this is not the dedicated staging database`);
		}

		// Staging registry fingerprint 2: the certified Stage 2 tenant/application pair.
		const application = await client.query<{ id: string }>(
				`SELECT a.id FROM applications a
				 JOIN tenants t ON t.id = a.tenant_id
				 WHERE t.slug = 'hapi-staging' AND t.status = 'active'
					 AND a.application_key = 'HAPI_STAGING' AND a.status = 'active'`
		);
		const applicationId = application.rows[0]?.id;
		if (!applicationId) {
				throw refusal("active hapi-staging tenant with HAPI_STAGING application not found — staging identity not established");
		}

		// Target must exist and match the certified Stage 2 staging-web shape, under lock.
		const web = await selectClient(client, "staging-web", true);
		if (!web) {
				throw refusal("client staging-web not found");
		}
		if (
				web.application_id !== applicationId ||
				web.token_endpoint_auth_method !== "client_secret_basic" ||
				!web.require_pkce ||
				web.status !== "active" ||
				!arraysEqual(web.redirect_uris, STAGING_WEB_REDIRECT_URIS) ||
				!arraysEqual(web.grant_types, STAGING_WEB_GRANT_TYPES)
		) {
				throw refusal("staging-web does not match the certified staging configuration — resolve manually (fail closed)");
		}

		const nativeBefore = await selectClient(client, "staging-native", false);
		if (!nativeBefore || nativeBefore.application_id !== applicationId || nativeBefore.token_endpoint_auth_method !== "none") {
				throw refusal("staging-native missing or not the expected public staging client");
		}

		const unchanged = constantTimeStringEqual(web.client_secret, secret);

		// The rotation: plaintext value (the registry's verified storage scheme),
		// parameterized, exactly one row, keyed by the unique client_id.
		const updated = await client.query<{ client_id: string }>(
				`UPDATE oidc_clients SET client_secret = $1, updated_at = now()
				 WHERE client_id = 'staging-web' RETURNING client_id`,
				[secret]
		);
		if (updated.rows.length !== 1) {
				throw refusal(`expected exactly 1 row updated, got ${updated.rows.length} — rolling back`);
		}

		// staging-native must be byte-identical after the update (rollback on drift).
		const nativeAfter = await selectClient(client, "staging-native", false);
		if (
				!nativeAfter ||
				nativeAfter.client_secret !== nativeBefore.client_secret ||
				nativeAfter.token_endpoint_auth_method !== nativeBefore.token_endpoint_auth_method ||
				nativeAfter.status !== nativeBefore.status ||
				timestampMs(nativeAfter.updated_at) !== timestampMs(nativeBefore.updated_at)
		) {
				throw refusal("staging-native changed during rotation — rolling back");
		}

		// Persistence check: the stored value must now equal the provided value.
		const persisted = await selectClient(client, "staging-web", false);
		if (!persisted || !constantTimeStringEqual(persisted.client_secret, secret)) {
				throw refusal("persisted staging-web secret does not match the provided value — rolling back");
		}

		return unchanged ? "unchanged" : "rotated";
}

// No-op unless STAGING_WEB_SECRET_ROTATION_ENABLED=true; once enabled, every
// failure throws (fail clearly — the operator explicitly requested rotation).
// Re-running with the same secret is a verified no-op ("unchanged").
export async function rotateStagingWebSecretAtBoot(
		log: RotationLogger,
		deps: StagingWebSecretRotationDependencies = {}
): Promise<StagingWebSecretRotationResult> {
		const env = deps.env ?? process.env;
		if ((env[STAGING_WEB_SECRET_ROTATION_FLAG] ?? "").trim().toLowerCase() !== "true") {
				return "disabled";
		}

		const driver = deps.driver ?? configuration.getIdentityRegistryDriver();
		if (driver !== "postgres") {
				throw refusal(`identity registry driver is "${driver}", not postgres`);
		}

		const issuer = deps.issuer ?? resolveConfiguredIssuer();
		if (issuer !== STAGING_ISSUER) {
				throw refusal(`configured issuer "${issuer}" is not exactly ${STAGING_ISSUER}`);
		}

		const secret = env[STAGING_WEB_CLIENT_SECRET_VARIABLE] ?? "";
		if (secret.length < 32 || secret.startsWith("__")) {
				throw refusal(`${STAGING_WEB_CLIENT_SECRET_VARIABLE} is missing or not a generated value of at least 32 characters`);
		}

		const runTransaction = deps.runTransaction ?? withPostgresTransaction;
		const result = await runTransaction(async (client) => rotateInTransaction(client, secret));

		log.info(
				{ result, secretLength: secret.length, fingerprintMd5_8: fingerprintMd5_8(secret) },
				`staging-web secret rotation: ${result} (compare fingerprint with: printf %s "$SECRET" | md5sum | cut -c1-8); ` +
						`remove ${STAGING_WEB_SECRET_ROTATION_FLAG} from the service variables now`
		);
		return result;
}
