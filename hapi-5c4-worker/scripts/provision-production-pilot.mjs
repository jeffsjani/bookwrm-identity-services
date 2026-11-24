#!/usr/bin/env node
import pg from "pg";
import { provisionPilot } from "./pilot-provisioning-transaction.mjs";

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
	client: { clientId: "hapi-pilot-certification", redirectUri, grantTypes: ["authorization_code"], scopes: ["openid", "email"], authMethod: "client_secret_basic", requirePkce: true, status: "suspended" }
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
if (process.env.HAPI_PILOT_ALLOWLIST_CONFIRMED !== "true") {
	throw new Error("Execution refused: confirm the pilot application allowlist will be configured before activation");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
let databaseUrl;
try {
	databaseUrl = new URL(process.env.DATABASE_URL);
} catch {
	throw new Error("Execution refused: DATABASE_URL is invalid");
}
if (!["postgres:", "postgresql:"].includes(databaseUrl.protocol)) throw new Error("Execution refused: DATABASE_URL must use PostgreSQL");
if (databaseUrl.hash || process.env.PGOPTIONS) {
	throw new Error("Execution refused: DATABASE_URL fragments and PGOPTIONS are unsupported");
}
const allowedParameters = new Set(["sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "connect_timeout"]);
for (const key of databaseUrl.searchParams.keys()) {
	if (!allowedParameters.has(key) || databaseUrl.searchParams.getAll(key).length !== 1) {
		throw new Error("Execution refused: DATABASE_URL contains an unsupported or duplicate parameter");
	}
}
const approvedDatabaseHost = process.env.HAPI_PILOT_PROVISIONING_DATABASE_HOST?.trim();
if (!approvedDatabaseHost) throw new Error("Execution refused: HAPI_PILOT_PROVISIONING_DATABASE_HOST is required");
if (approvedDatabaseHost !== databaseUrl.hostname) throw new Error("Execution refused: DATABASE_URL host differs from approved production database host");
const approvedDatabasePort = process.env.HAPI_PILOT_PROVISIONING_DATABASE_PORT?.trim();
if (!approvedDatabasePort || !/^[1-9]\d{0,4}$/.test(approvedDatabasePort) || Number(approvedDatabasePort) > 65535) {
	throw new Error("Execution refused: HAPI_PILOT_PROVISIONING_DATABASE_PORT must be an approved port");
}
if (!databaseUrl.port || approvedDatabasePort !== databaseUrl.port) throw new Error("Execution refused: DATABASE_URL port differs from approved database port");
const approvedDatabaseName = process.env.HAPI_PILOT_PROVISIONING_DATABASE_NAME;
const approvedDatabaseSchema = process.env.HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA;
if (!approvedDatabaseName || !approvedDatabaseSchema) throw new Error("Execution refused: approved database name and schema are required");
let databaseName;
try {
	databaseName = decodeURI(databaseUrl.pathname.slice(1));
} catch {
	throw new Error("Execution refused: DATABASE_URL database name is invalid");
}
if (!databaseName || databaseName !== approvedDatabaseName) throw new Error("Execution refused: DATABASE_URL database name differs from approved database name");
if (databaseUrl.searchParams.get("sslmode") !== "require" && databaseUrl.searchParams.get("sslmode") !== "verify-full") {
	throw new Error("Execution refused: DATABASE_URL must use sslmode=require or sslmode=verify-full");
}
if (/^(localhost|127(?:\.\d{1,3}){3}|\[::1\])$/i.test(databaseUrl.hostname) || /(staging|test|dev)/i.test(databaseUrl.hostname)) {
	throw new Error("Execution refused: DATABASE_URL appears to be non-production or a disposable environment");
}

if (process.stdin.isTTY) throw new Error("Execution refused: supply the approved vault credential via standard input, not a terminal");
let secretInput = "";
for await (const chunk of process.stdin) {
	secretInput += chunk.toString("utf8");
	if (secretInput.length > 65) throw new Error("Execution refused: invalid credential input");
}
const secret = secretInput.replace(/\r?\n$/, "");
if (!/^[A-Za-z0-9_-]{64}$/.test(secret)) {
	throw new Error("Execution refused: credential must be a 48-byte random base64url value supplied via standard input");
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
	await client.connect();
} catch {
	throw new Error("Provisioning database connection failed; inspect the approved target without exposing credentials");
}
try {
	console.log(JSON.stringify(await provisionPilot(client, plan, secret, approvedDatabaseName, approvedDatabaseSchema), null, 2));
} finally {
	try {
		await client.end();
	} catch {
		throw new Error("Provisioning database disconnect failed; inspect the target securely");
	}
}
