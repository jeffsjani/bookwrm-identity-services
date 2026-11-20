import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { registerStagingConsoleCallbackAtBoot, STAGING_WEB_ORIGINAL_CALLBACK } from "../src/identity/StagingConsoleClientRegistration.js";
import { STAGING_CONSOLE_CALLBACK, STAGING_ISSUER } from "../src/oidc/StagingTestConsole.js";
import { withPostgresTransaction, type PostgresClient, type TransactionRunner } from "../src/identity/infrastructure/PostgresInfrastructure.js";

const databaseUrl = process.env.HAPI_STAGING_CONSOLE_TEST_DATABASE_URL;
const schema = "console_" + randomUUID().replaceAll("-", "");

describe.skipIf(!databaseUrl)("staging console callback registration (PostgreSQL)", () => {
	const admin = new pg.Pool({ connectionString: databaseUrl });
	const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}` });
	const run: TransactionRunner = fn => withPostgresTransaction(fn, pool);
	const deps = { issuer: STAGING_ISSUER, driver: "postgres", env: { STAGING_TEST_CONSOLE_REGISTER_CALLBACK: "true" }, runTransaction: run };
	const redirects = async () => (await pool.query<{ redirect_uris: string[] }>(
		"SELECT redirect_uris FROM oidc_clients WHERE client_id = 'staging-web'")).rows[0].redirect_uris;

	beforeAll(async () => {
		const version = await admin.query<{ server_version_num: string }>("SHOW server_version_num");
		expect(Number(version.rows[0].server_version_num)).toBeGreaterThanOrEqual(160000);
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		const seed = readFileSync(new URL("../scripts/seed-staging-clients.sql", import.meta.url), "utf8")
			.replaceAll("__STAGING_WEB_SECRET__", "synthetic-client-secret-01234567890123456789");
		await pool.query(seed);
	});

	beforeEach(async () => {
		await pool.query("DELETE FROM oidc_clients WHERE client_id = 'foreign-client'");
		await pool.query("UPDATE oidc_clients SET redirect_uris = $1 WHERE client_id = 'staging-web'", [[STAGING_WEB_ORIGINAL_CALLBACK]]);
	});

	afterAll(async () => {
		await pool.end();
		await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
		await admin.end();
	});

	it("atomically appends the callback, preserves existing data and is idempotent under concurrency", async () => {
		const nativeBefore = await pool.query("SELECT * FROM oidc_clients WHERE client_id = 'staging-native'");
		const results = await Promise.all([registerStagingConsoleCallbackAtBoot(deps), registerStagingConsoleCallbackAtBoot(deps)]);
		expect(results.sort()).toEqual(["registered", "unchanged"]);
		expect(await redirects()).toEqual([STAGING_WEB_ORIGINAL_CALLBACK, STAGING_CONSOLE_CALLBACK]);
		expect((await pool.query("SELECT * FROM oidc_clients WHERE client_id = 'staging-native'")).rows).toEqual(nativeBefore.rows);
	});

	it("rolls the update back when a later transaction operation fails", async () => {
		const failing: TransactionRunner = fn => withPostgresTransaction(async client => {
			const wrapped: PostgresClient = {
				async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
					const result = await client.query<T>(text, values);
					if (text.startsWith("UPDATE oidc_clients")) throw new Error("synthetic transaction failure");
					return result;
				}
			};
			return fn(wrapped);
		}, pool);
		await expect(registerStagingConsoleCallbackAtBoot({ ...deps, runTransaction: failing })).rejects.toThrow("synthetic transaction failure");
		expect(await redirects()).toEqual([STAGING_WEB_ORIGINAL_CALLBACK]);
	});

	it("refuses an unexpected client without changing the registered callback", async () => {
		await pool.query(`INSERT INTO oidc_clients
			(id, application_id, client_id, client_secret, redirect_uris, scopes, grant_types, response_types,
			 token_endpoint_auth_method, require_pkce, status, created_at, updated_at)
			SELECT gen_random_uuid(), application_id, 'foreign-client', '', ARRAY[]::text[], scopes, grant_types,
			 response_types, 'none', true, 'active', now(), now()
			FROM oidc_clients WHERE client_id = 'staging-web'`);
		await expect(registerStagingConsoleCallbackAtBoot(deps)).rejects.toThrow(/unexpected client/);
		expect(await redirects()).toEqual([STAGING_WEB_ORIGINAL_CALLBACK]);
	});
});
