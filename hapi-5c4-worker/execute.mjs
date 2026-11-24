import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { scryptSync, timingSafeEqual } from "node:crypto";
import pg from "pg";
import { validateTarget, productionTarget } from "./target.mjs";

const tenantId = "c04e7cf0-9e90-49cb-b26f-9ec8e3e7fd18";
const applicationId = "5716f2cc-519e-40d9-8b51-011e7be409a7";
const clientId = "hapi-pilot-certification";
const callback = "https://certification.hapiinc.com/oidc-certification/callback";

async function collisionCounts(db) {
	const result = await db.query(`SELECT
		(SELECT count(*) FROM public.tenants WHERE id = $1 OR slug = 'hapi-pilot') AS tenants,
		(SELECT count(*) FROM public.applications WHERE id = $2 OR application_key = 'HAPI_PILOT'
			OR (tenant_id = $1 AND slug = 'hapi-pilot-certification')) AS applications,
		(SELECT count(*) FROM public.oidc_clients WHERE client_id = $3) AS clients`, [tenantId, applicationId, clientId]);
	return Object.values(result.rows[0]).map(Number);
}

async function verifyMetadata(db) {
	const result = await db.query(`SELECT c.status = 'suspended' AND c.application_id = $1
		AND c.redirect_uris = ARRAY[$2]::text[] AND c.scopes = ARRAY['openid','email']::text[]
		AND c.grant_types = ARRAY['authorization_code']::text[] AND c.response_types = ARRAY['code']::text[]
		AND c.token_endpoint_auth_method = 'client_secret_basic' AND c.require_pkce = true
		AND a.tenant_id = $3 AND a.application_key = 'HAPI_PILOT' AND a.slug = 'hapi-pilot-certification'
		AND a.name = 'HAPI Pilot Certification' AND a.status = 'active' AND a.allowed_authentication_methods = ARRAY['HAPI_EMAIL']::text[]
		AND a.allowed_identity_providers = ARRAY[]::text[] AND a.face_setup_enabled = false
		AND t.name = 'HAPI Pilot' AND t.slug = 'hapi-pilot' AND t.status = 'active' AS matches
		FROM public.oidc_clients c JOIN public.applications a ON a.id = c.application_id
		JOIN public.tenants t ON t.id = a.tenant_id WHERE c.client_id = $4`,
	[applicationId, callback, tenantId, clientId]);
	if (result.rows.length !== 1 || result.rows[0].matches !== true) throw new Error("metadata");
}

async function verifySecret(db, secret) {
	const result = await db.query("SELECT client_secret FROM public.oidc_clients WHERE client_id = $1", [clientId]);
	const parts = result.rows[0]?.client_secret?.split("$");
	if (!parts || parts.length !== 6 || parts.slice(0, 4).join("$") !== "scrypt$16384$8$1") throw new Error("credential");
	const salt = Buffer.from(parts[4], "base64url");
	const expected = Buffer.from(parts[5], "base64url");
	if (salt.length !== 16 || expected.length !== 32 || salt.toString("base64url") !== parts[4] ||
		expected.toString("base64url") !== parts[5] ||
		!timingSafeEqual(scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }), expected)) {
		throw new Error("credential");
	}
}

function provision(script, env, secret) {
	return new Promise((resolve, reject) => {
		const child = spawn(process.execPath, [script, "--application-id", applicationId,
			"--redirect-uri", callback, "--execute"], { env, stdio: ["pipe", "ignore", "ignore"] });
		let finished = false;
		const timer = setTimeout(() => child.kill("SIGKILL"), 30000);
		child.on("error", () => { if (!finished) { finished = true; clearTimeout(timer); reject(new Error("child")); } });
		child.on("close", code => {
			if (finished) return;
			finished = true;
			clearTimeout(timer);
			if (code === 0) resolve(); else reject(new Error("child"));
		});
		child.stdin.on("error", () => {});
		child.stdin.end(secret);
	});
}

export async function execute(env, script, target = productionTarget, mode = "create") {
	if (!["create", "inspect"].includes(mode)) throw new Error("mode");
	if (env.HAPI_WORKER_EXECUTION_ACK !== "I_HAVE_APPROVED_ONE_PRODUCTION_WRITE" ||
		env.HAPI_WORKER_BACKEND_FLAGS_CONFIRMED !== "true" || !env.RAILWAY_SERVICE_ID ||
		env.RAILWAY_SERVICE_ID !== env.HAPI_WORKER_APPROVED_SERVICE_ID) throw new Error("approval");
	for (const name of ["HAPI_EMAIL_AUTHENTICATION_ENABLED", "HAPI_UNIVERSAL_LOGIN_ENABLED"]) {
		if (env[name] !== undefined && env[name] !== "false") throw new Error("authentication flags");
	}
	const certificate = env.HAPI_WORKER_POSTGRES_CA;
	if (!certificate) throw new Error("certificate");
	const url = validateTarget(env, certificate, target);
	const secret = env.HAPI_WORKER_CLIENT_SECRET;
	if (!secret || !/^[A-Za-z0-9_-]{64}$/.test(secret)) throw new Error("secret");
	let directory;
	let db;
	try {
		directory = mkdtempSync(join(tmpdir(), "hapi-pilot-ca-"));
		const caPath = join(directory, "root-ca.pem");
		writeFileSync(caPath, certificate, { mode: 0o600, flag: "wx" });
		url.searchParams.set("sslmode", "verify-full");
		url.searchParams.set("sslrootcert", caPath);
		db = new pg.Client({ connectionString: url.toString(), connectionTimeoutMillis: 10000 });
		const ssl = db.connectionParameters.ssl;
		if (!ssl || ssl.ca !== certificate || ssl.rejectUnauthorized === false || ssl.checkServerIdentity) throw new Error("TLS options");
		await db.connect();
		if (db.connection.stream.authorized !== true) throw new Error("TLS");
		const identity = await db.query("SELECT current_database() AS database_name, current_schema() AS schema_name");
		if (identity.rows[0]?.database_name !== target.database || identity.rows[0]?.schema_name !== target.schema) throw new Error("database identity");
		if (mode === "inspect") {
			const lock = await db.query("SELECT pg_try_advisory_lock(1212248153, 534) AS acquired");
			if (lock.rows[0]?.acquired !== true) throw new Error("concurrent");
		}
		await db.query("BEGIN READ ONLY");
		const counts = await collisionCounts(db);
		if (mode === "inspect") {
			if (counts.every(count => count === 0)) {
				await db.query("ROLLBACK");
				return "not_created";
			}
			if (counts.some(count => count !== 1)) throw new Error("existing metadata");
			await verifyMetadata(db);
			await verifySecret(db, secret);
			await db.query("ROLLBACK");
			return "matched";
		}
		await db.query("ROLLBACK");
		if (counts.some(count => count !== 0)) throw new Error("existing metadata");
		const childEnv = {
			DATABASE_URL: url.toString(), OIDC_ISSUER: "https://id.hapiinc.com",
			HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com",
			HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true", HAPI_PILOT_ALLOWLIST_CONFIRMED: "true",
			HAPI_PILOT_PROVISIONING_DATABASE_HOST: target.host, HAPI_PILOT_PROVISIONING_DATABASE_PORT: target.port,
			HAPI_PILOT_PROVISIONING_DATABASE_NAME: target.database, HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA: target.schema
		};
		await provision(script, childEnv, secret);
		await db.query("BEGIN READ ONLY");
		await verifyMetadata(db);
		await verifySecret(db, secret);
		await db.query("ROLLBACK");
		return "created";
	} finally {
		if (db) await db.end().catch(() => {});
		if (directory) rmSync(directory, { recursive: true, force: true });
	}
}