import crypto from "node:crypto";

function hashSecret(secret) {
	const salt = crypto.randomBytes(16);
	const derived = crypto.scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
	return `scrypt$16384$8$1$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

function matchesSecret(stored, supplied) {
	const parts = stored.split("$");
	if (parts.length !== 6 || parts[0] !== "scrypt" || parts[1] !== "16384" || parts[2] !== "8" || parts[3] !== "1") return false;
	const salt = Buffer.from(parts[4], "base64url");
	const expected = Buffer.from(parts[5], "base64url");
	if (salt.length !== 16 || expected.length !== 32 ||
		salt.toString("base64url") !== parts[4] || expected.toString("base64url") !== parts[5]) return false;
	const actual = crypto.scryptSync(supplied, salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
	return crypto.timingSafeEqual(expected, actual);
}

class ProvisioningError extends Error {}

export async function provisionPilot(client, plan, secret, approvedDatabaseName, approvedDatabaseSchema) {
	const { applicationId } = plan;
	const { redirectUri } = plan.client;
	try {
		const target = await client.query("SELECT current_database() AS database_name, current_schema() AS schema_name");
		if (target.rows[0]?.database_name !== approvedDatabaseName || target.rows[0]?.schema_name !== approvedDatabaseSchema) {
			throw new ProvisioningError("connected database or schema differs from approved target; refusing mutation");
		}
		await client.query("BEGIN");
		const existingTenant = await client.query(
			"SELECT id, name, slug, status FROM tenants WHERE slug=$1 OR id=$2", [plan.tenant.slug, plan.tenant.id]);
		if (existingTenant.rows.length > 1) {
			throw new ProvisioningError("multiple pilot tenant matches; refusing mutation");
		}
		if (existingTenant.rows.length === 0) {
			await client.query(
				`INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
				 VALUES ($1,$2,$3,'active',now(),now())`,
				[plan.tenant.id, plan.tenant.name, plan.tenant.slug]);
		} else {
			const tenant = existingTenant.rows[0];
			if (tenant.id !== plan.tenant.id || tenant.name !== plan.tenant.name || tenant.slug !== plan.tenant.slug || tenant.status !== "active") {
				throw new ProvisioningError("existing pilot tenant differs; refusing mutation");
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
				throw new ProvisioningError("existing approved application differs; refusing mutation");
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
			"SELECT id, application_id, client_secret, redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, require_pkce, status FROM oidc_clients WHERE client_id=$1",
			[plan.client.clientId]);
		if (existingClient.rows.length === 0) {
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
				row.token_endpoint_auth_method === plan.client.authMethod && row.require_pkce === true && row.status === "active" &&
				matchesSecret(row.client_secret, secret);
			if (!same) throw new ProvisioningError("existing hapi-pilot-certification client or credential differs; refusing mutation");
		}
		await client.query("COMMIT");
		return { action: existingClient.rows.length ? "unchanged" : "created", applicationId, clientId: plan.client.clientId };
	} catch (error) {
		try {
			await client.query("ROLLBACK");
		} catch {
			console.error("Provisioning rollback failed; transaction outcome requires operator investigation");
		}
		if (error instanceof ProvisioningError) throw error;
		throw new Error("Provisioning failed; transaction was not confirmed. Inspect the target securely before retrying");
	}
}
