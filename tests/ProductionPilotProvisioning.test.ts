import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import { hashOIDCClientSecret, verifyOIDCClientSecret } from "../src/security/OIDCClientSecret.js";

const script = "scripts/provision-production-pilot.mjs";
const applicationId = "123e4567-e89b-42d3-a456-426614174000";
const redirectUri = "https://certification.hapiinc.com/oidc-certification/callback";

describe("production pilot provisioning", () => {
	it("plan mode cannot write and emits the exact pilot shape", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri], {
			cwd: process.cwd(), encoding: "utf8"
		});
		expect(run.status).toBe(0);
		expect(run.stdout).toContain('"action": "plan-only"');
		expect(run.stdout).toContain('"grantTypes"');
		expect(run.stdout).toContain('"authorization_code"');
		expect(run.stdout).toContain('"authMethod": "client_secret_basic"');
		expect(run.stdout).toContain('"requirePkce": true');
		expect(run.stdout).not.toContain("refresh_token");
		expect(run.stdout).not.toContain("never-rendered");
	});

	it("execute mode refuses without explicit production acknowledgement", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", env: { ...process.env, DATABASE_URL: "postgresql://user:pass@localhost/db" }
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("Execution refused");
	});

	it("execute mode refuses a staging or disposable database hostname", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", env: {
				...process.env,
				HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true",
				HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com",
				HAPI_PILOT_ALLOWLIST_CONFIRMED: "true",
				OIDC_ISSUER: "https://id.hapiinc.com",
				HAPI_PILOT_PROVISIONING_DATABASE_HOST: "staging-db.example",
				HAPI_PILOT_PROVISIONING_DATABASE_PORT: "5432",
				HAPI_PILOT_PROVISIONING_DATABASE_NAME: "db",
				HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA: "public",
				DATABASE_URL: "postgresql://user:pass@staging-db.example:5432/db?sslmode=require"
			}
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("disposable environment");
	});

	it.each([
		["issuer", { OIDC_ISSUER: "https://wrong.example" }, "OIDC_ISSUER must exactly equal"],
		["target", { HAPI_PILOT_PROVISIONING_TARGET: "https://wrong.example" }, "HAPI_PILOT_PROVISIONING_TARGET must exactly equal"],
		["database host", { HAPI_PILOT_PROVISIONING_DATABASE_HOST: "different.example.invalid" }, "host differs"],
		["database port", { HAPI_PILOT_PROVISIONING_DATABASE_PORT: "5433" }, "port differs"],
		["database name", { HAPI_PILOT_PROVISIONING_DATABASE_NAME: "different" }, "database name differs"],
		["invalid URL", { DATABASE_URL: "not-a-url-with-synthetic-credential" }, "DATABASE_URL is invalid"],
		["host override", { DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db?sslmode=require&host=other.example" }, "unsupported or duplicate parameter"],
		["duplicate TLS mode", { DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db?sslmode=require&sslmode=disable" }, "unsupported or duplicate parameter"],
		["schema override", { DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db?sslmode=require&options=-c%20search_path%3Dother" }, "unsupported or duplicate parameter"],
		["ambient connection options", { PGOPTIONS: "-c search_path=other" }, "PGOPTIONS are unsupported"],
		["implicit port", { DATABASE_URL: "postgresql://user:pass@database.example.invalid/db?sslmode=require" }, "port differs"],
		["TLS", { DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db" }, "must use sslmode"],
		["allowlist confirmation", { HAPI_PILOT_ALLOWLIST_CONFIRMED: "false" }, "confirm the pilot application allowlist"]
	])("refuses an invalid %s before attempting a database connection", (_name, overrides, message) => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", input: "A".repeat(64),
			env: {
				PATH: process.env.PATH, HOME: process.env.HOME,
				HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true",
				HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com",
				OIDC_ISSUER: "https://id.hapiinc.com",
				HAPI_PILOT_ALLOWLIST_CONFIRMED: "true",
				HAPI_PILOT_PROVISIONING_DATABASE_HOST: "database.example.invalid",
				HAPI_PILOT_PROVISIONING_DATABASE_PORT: "5432",
				HAPI_PILOT_PROVISIONING_DATABASE_NAME: "db",
				HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA: "public",
				DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db?sslmode=verify-full",
				...overrides
			}
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr).toContain(message);
		expect(run.stderr + run.stdout).not.toContain("A".repeat(64));
	});

	it("refuses an invalid application ID before execution", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", "invalid", "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", env: { PATH: process.env.PATH, HOME: process.env.HOME }
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr).toContain("--application-id must be an explicitly approved UUID");
	});

	it("refuses malformed stdin credentials without connecting or printing them", () => {
		const secret = "synthetic-should-never-be-printed";
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", input: secret,
			env: { ...process.env, HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true",
				HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com", OIDC_ISSUER: "https://id.hapiinc.com",
				HAPI_PILOT_ALLOWLIST_CONFIRMED: "true", HAPI_PILOT_PROVISIONING_DATABASE_HOST: "database.example.invalid",
				HAPI_PILOT_PROVISIONING_DATABASE_PORT: "5432", HAPI_PILOT_PROVISIONING_DATABASE_NAME: "db",
				HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA: "public",
				DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db?sslmode=verify-full" }
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("credential must be");
		expect(run.stderr + run.stdout).not.toContain(secret);
	});

	it.each(["create", "unchanged", "conflict", "application-conflict", "client-conflict", "insert-error", "wrong-schema"])("handles a mocked %s transaction without emitting the credential", async mode => {
		const secret = "A".repeat(64);
		const storedSecret = mode === "unchanged" ? await hashOIDCClientSecret(secret) : "";
		const originalArgv = process.argv;
		const query = vi.fn(async (sql: string, _values?: unknown[]) => {
			if (mode === "insert-error" && sql.includes("INSERT INTO oidc_clients")) throw new Error("synthetic insertion error");
			return {
				rows: sql.startsWith("SELECT current_database()")
					? [{ database_name: "db", schema_name: mode === "wrong-schema" ? "other" : "public" }]
					: mode === "conflict" && sql.startsWith("SELECT id, name, slug, status FROM tenants")
						? [{ id: "another-tenant", name: "other", slug: "hapi-pilot", status: "active" }]
						: mode === "unchanged" && sql.startsWith("SELECT id, name, slug, status FROM tenants")
							? [{ id: "c04e7cf0-9e90-49cb-b26f-9ec8e3e7fd18", name: "HAPI Pilot", slug: "hapi-pilot", status: "active" }]
							: mode === "application-conflict" && sql.startsWith("SELECT id, tenant_id, name")
								? [{ tenant_id: "another-tenant" }]
								: mode === "unchanged" && sql.startsWith("SELECT id, tenant_id, name")
									? [{ tenant_id: "c04e7cf0-9e90-49cb-b26f-9ec8e3e7fd18", application_key: "HAPI_PILOT",
										name: "HAPI Pilot Certification", slug: "hapi-pilot-certification", status: "active",
										allowed_authentication_methods: ["HAPI_EMAIL"], allowed_identity_providers: [], face_setup_enabled: false }]
									: mode === "client-conflict" && sql.startsWith("SELECT id, application_id, client_secret")
										? [{ application_id: "another-application", client_secret: "wrong" }]
										: mode === "unchanged" && sql.startsWith("SELECT id, application_id, client_secret")
											? [{ application_id: applicationId, client_secret: storedSecret, redirect_uris: [redirectUri],
												scopes: ["openid", "email"], grant_types: ["authorization_code"], response_types: ["code"],
												token_endpoint_auth_method: "client_secret_basic", require_pkce: true, status: "active" }] : []
			};
		});
		const connect = vi.fn(async () => {});
		const end = vi.fn(async () => {});
		vi.resetModules();
		vi.doMock("pg", () => ({ default: { Client: class { connect = connect; query = query; end = end; } } }));
		vi.spyOn(process.stdin, Symbol.asyncIterator).mockImplementation(async function* () { yield Buffer.from(secret); });
		const log = vi.spyOn(console, "log").mockImplementation(() => {});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		for (const [key, value] of Object.entries({
			HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true", HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com",
			OIDC_ISSUER: "https://id.hapiinc.com", HAPI_PILOT_ALLOWLIST_CONFIRMED: "true",
			HAPI_PILOT_PROVISIONING_DATABASE_HOST: "database.example.invalid",
			HAPI_PILOT_PROVISIONING_DATABASE_PORT: "5432", HAPI_PILOT_PROVISIONING_DATABASE_NAME: "db",
			HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA: "public",
			DATABASE_URL: "postgresql://user:pass@database.example.invalid:5432/db?sslmode=verify-full"
		})) vi.stubEnv(key, value);
		process.argv = [process.execPath, script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"];
		try {
			if (mode === "create") {
				await import("../scripts/provision-production-pilot.mjs");
				const insert = query.mock.calls.find(([sql]) => sql.includes("INSERT INTO oidc_clients"));
				expect(insert).toBeDefined();
				const stored = insert![1]![2] as string;
				expect(stored).not.toContain(secret);
				expect(await verifyOIDCClientSecret(stored, secret)).toBe(true);
				expect(query.mock.calls.some(([sql]) => sql === "COMMIT")).toBe(true);
			} else if (mode === "unchanged") {
				await import("../scripts/provision-production-pilot.mjs");
				expect(query.mock.calls.some(([sql]) => sql.startsWith("INSERT"))).toBe(false);
				expect(query.mock.calls.some(([sql]) => sql === "COMMIT")).toBe(true);
			} else {
				const message = mode === "conflict" ? "existing pilot tenant differs"
					: mode === "application-conflict" ? "existing approved application differs"
					: mode === "client-conflict" ? "client or credential differs"
						: mode === "wrong-schema" ? "connected database or schema differs" : "Provisioning failed";
				await expect(import("../scripts/provision-production-pilot.mjs")).rejects.toThrow(message);
				expect(query.mock.calls.some(([sql]) => sql === "ROLLBACK")).toBe(true);
				expect(query.mock.calls.some(([sql]) => sql === "COMMIT")).toBe(false);
				if (mode === "wrong-schema") expect(query.mock.calls.some(([sql]) => sql === "BEGIN")).toBe(false);
			}
			expect(JSON.stringify([...log.mock.calls, ...error.mock.calls])).not.toContain(secret);
			expect(connect).toHaveBeenCalledOnce();
			expect(end).toHaveBeenCalledOnce();
		} finally {
			process.argv = originalArgv;
			vi.restoreAllMocks();
			vi.unstubAllEnvs();
			vi.doUnmock("pg");
		}
	});
});
