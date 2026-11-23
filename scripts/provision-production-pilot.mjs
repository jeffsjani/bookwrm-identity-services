#!/usr/bin/env node
import crypto from "node:crypto";
import pg from "pg";

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
	const key = process.argv[i];
	if (key === "--execute") continue;
	if (!key?.startsWith("--")) {
		throw new Error("usage: provision-production-pilot.mjs --application-id UUID --redirect-uri HTTPS_URI [--execute]");
	}
	const value = process.argv[++i];
	if (value === undefined) {
		throw new Error("usage: provision-production-pilot.mjs --application-id UUID --redirect-uri HTTPS_URI [--execute]");
	}
	args.set(key, value);
}

const execute = process.argv.includes("--execute");
const applicationId = args.get("--application-id")?.trim();
const redirectUri = args.get("--redirect-uri")?.trim();
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

if (!applicationId || !uuidPattern.test(applicationId)) throw new Error("--application-id must be an explicitly approved UUID");
if (!redirectUri) throw new Error("--redirect-uri is required");
const callback = new URL(redirectUri);
if (callback.protocol !== "https:" || callback.username || callback.password || callback.hash) {
	throw new Error("--redirect-uri must be an exact HTTPS callback URL without credentials or fragment");
}

const PILOT_TENANT_ID = "c04e7cf0-9e90-49cb-b26f-9ec8e3e7fd18";
const plan = {
	issuer: "https://id.hapiinc.com",
	tenant: { id: PILOT_TENANT_ID, name: "HAPI Pilot", slug: "hapi-pilot", applicationKey: "HAPI_PILOT" },
	applicationId,
	application: { name: "HAPI Pilot Certification", slug: "hapi-pilot-certification", allowedAuthenticationMethods: ["HAPI_EMAIL"], allowedIdentityProviders: [], faceSetupEnabled: false },
	client: { clientId: "hapi-pilot-certification", redirectUri, grantTypes: ["authorization_code"], scopes: ["openid", "email"], authMethod: "client_secret_basic", requirePkce: true }
};

if (!execute) {
	console.log(JSON.stringify({ action: "plan-only", plan }, null, 2));
	console.log("No database changes made. Rerun with --execute only after explicit operator approval.");
	process.exit(0);
}

if (process.env.HAPI_PILOT_PROVISIONING_ACKNOWLEDGED !== "true") {
	throw new Error("Execution refused: set HAPI_PILOT_PROVISIONING_ACKNOWLEDGED=true only for an explicitly approved database target");
}
if (process.env.HAPI_PILOT_PROVISIONING_TARGET !== "https://id.hapiinc.com") {
	throw new Error("Execution refused: HAPI_PILOT_PROVISIONING_TARGET must exactly equal https://id.hapiinc.com");
}
if (process.env.OIDC_ISSUER !== "https://id.hapiinc.com") {
	throw new Error("Execution refused: OIDC_ISSUER must exactly equal https://id.hapiinc.com");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const databaseUrl = new URL(process.env.DATABASE_URL);
const approvedDatabaseHost = process.env.HAPI_PILOT_PROVISIONING_DATABASE_HOST?.trim();
if (!approvedDatabaseHost) throw new Error("Execution refused: HAPI_PILOT_PROVISIONING_DATABASE_HOST is required");
if (approvedDatabaseHost !== databaseUrl.hostname) throw new Error("Execution refused: DATABASE_URL host differs from approved production database host");
if (databaseUrl.searchParams.get("sslmode") !== "require" && databaseUrl.searchParams.get("sslmode") !== "verify-full") {
	throw new Error("Execution refused: DATABASE_URL must use sslmode=require or sslmode=verify-full");
}
if (/^(localhost|127\.0\.0\.1)$/i.test(databaseUrl.hostname) || /(staging|test|dev)/i.test(databaseUrl.hostname)) {
	throw new Error("Execution refused: DATABASE_URL appears to be non-production or a disposable environment");
}

function hashSecret(secret) {
	const salt = crypto.randomBytes(16);
	const derived = crypto.scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
	return `scrypt$16384$8$1$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
try {
	await client.query("BEGIN");
	const existingTenant = await client.query(
		"SELECT id, name, slug, status FROM tenants WHERE slug=$1 OR id=$2", [plan.tenant.slug, plan.tenant.id]);
	if (existingTenant.rows.length > 1) {
		throw new Error("multiple pilot tenant matches; refusing mutation");
	}
	if (existingTenant.rows.length === 0) {
		await client.query(
			`INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
			 VALUES ($1,$2,$3,'active',now(),now())`,
			[plan.tenant.id, plan.tenant.name, plan.tenant.slug]);
	} else {
		const tenant = existingTenant.rows[0];
		if (tenant.id !== plan.tenant.id || tenant.name !== plan.tenant.name || tenant.slug !== plan.tenant.slug || tenant.status !== "active") {
			throw new Error("existing pilot tenant differs; refusing mutation");
		}
	}
	const tenantId = plan.tenant.id;

	const existingApplication = await client.query(
		"SELECT id, tenant_id, name, slug, status, application_key, allowed_authentication_methods, allowed_identity_providers, face_setup_enabled FROM applications WHERE id=$1",
		[applicationId]);
	if (existingApplication.rows.length) {
		const application = existingApplication.rows[0];
		if (application.tenant_id !== tenantId || application.application_key !== plan.tenant.applicationKey ||
			application.name !== plan.application.name || application.slug !== plan.application.slug || application.status !== "active" ||
			JSON.stringify(application.allowed_authentication_methods) !== JSON.stringify(plan.application.allowedAuthenticationMethods) ||
			JSON.stringify(application.allowed_identity_providers) !== JSON.stringify(plan.application.allowedIdentityProviders) ||
			application.face_setup_enabled !== false) {
			throw new Error("existing approved application differs; refusing mutation");
		}
	} else {
		await client.query(
		`INSERT INTO applications
		 (id, tenant_id, name, slug, status, created_at, updated_at, application_key, allowed_authentication_methods, allowed_identity_providers, face_setup_enabled)
		 VALUES ($1,$2,$3,$4,'active',now(),now(),$5,$6,$7,false)`,
		[applicationId, tenantId, plan.application.name, plan.application.slug, plan.tenant.applicationKey,
			plan.application.allowedAuthenticationMethods, plan.application.allowedIdentityProviders]);
	}

	const existingClient = await client.query(
		"SELECT id, application_id, redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, require_pkce, status FROM oidc_clients WHERE client_id=$1",
		[plan.client.clientId]);
	let secret = null;
	if (existingClient.rows.length === 0) {
		secret = crypto.randomBytes(48).toString("base64url");
		await client.query(
			`INSERT INTO oidc_clients
			 (id, application_id, client_id, client_secret, redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, require_pkce, created_at, updated_at, status)
			 VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,true,now(),now(),'active')`,
			[applicationId, plan.client.clientId, hashSecret(secret), [redirectUri], plan.client.scopes,
				plan.client.grantTypes, ["code"], plan.client.authMethod]);
	} else {
		const row = existingClient.rows[0];
		const same = row.application_id === applicationId &&
			JSON.stringify(row.redirect_uris) === JSON.stringify([redirectUri]) &&
			JSON.stringify(row.scopes) === JSON.stringify(plan.client.scopes) &&
			JSON.stringify(row.grant_types) === JSON.stringify(plan.client.grantTypes) &&
			JSON.stringify(row.response_types) === JSON.stringify(["code"]) &&
			row.token_endpoint_auth_method === plan.client.authMethod && row.require_pkce === true && row.status === "active";
		if (!same) throw new Error("existing hapi-pilot-certification client differs; refusing mutation");
	}
	await client.query("COMMIT");
	console.log(JSON.stringify({ action: existingClient.rows.length ? "unchanged" : "created", applicationId, clientId: plan.client.clientId, secretWasGenerated: secret !== null }, null, 2));
	if (secret) {
		console.log("CLIENT_SECRET_BEGIN");
		console.log(secret);
		console.log("CLIENT_SECRET_END");
	}
} catch (error) {
	await client.query("ROLLBACK");
	throw error;
} finally {
	await client.end();
}
