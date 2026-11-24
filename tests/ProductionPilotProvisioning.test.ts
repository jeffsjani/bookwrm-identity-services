import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import { verifyOIDCClientSecret } from "../src/security/OIDCClientSecret.js";

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
				DATABASE_URL: "postgresql://user:pass@staging-db.example/db?sslmode=require"
			}
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("disposable environment");
	});

	it("refuses malformed stdin credentials without connecting or printing them", () => {
		const secret = "synthetic-should-never-be-printed";
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", input: secret,
			env: { ...process.env, HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true",
				HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com", OIDC_ISSUER: "https://id.hapiinc.com",
				HAPI_PILOT_ALLOWLIST_CONFIRMED: "true", HAPI_PILOT_PROVISIONING_DATABASE_HOST: "database.example.invalid",
				DATABASE_URL: "postgresql://user:pass@database.example.invalid/db?sslmode=verify-full" }
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("credential must be");
		expect(run.stderr + run.stdout).not.toContain(secret);
	});

	it.each(["create", "conflict"])("handles a mocked %s transaction without emitting the credential", async mode => {
		const secret = "A".repeat(64);
		const originalArgv = process.argv;
		const query = vi.fn(async (sql: string, _values?: unknown[]) => ({
			rows: mode === "conflict" && sql.startsWith("SELECT id, name, slug, status FROM tenants")
				? [{ id: "another-tenant", name: "other", slug: "hapi-pilot", status: "active" }] : []
		}));
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
			DATABASE_URL: "postgresql://user:pass@database.example.invalid/db?sslmode=verify-full"
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
			} else {
				await expect(import("../scripts/provision-production-pilot.mjs")).rejects.toThrow("existing pilot tenant differs");
				expect(query.mock.calls.some(([sql]) => sql === "ROLLBACK")).toBe(true);
				expect(query.mock.calls.some(([sql]) => sql === "COMMIT")).toBe(false);
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
