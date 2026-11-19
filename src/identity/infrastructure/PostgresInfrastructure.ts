import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";

import { configuration } from "../../config/ConfigurationService.js";

const { Pool } = pg;

export interface PostgresClient {
		query<T extends Record<string, unknown> = Record<string, unknown>>(
				text: string,
				values?: unknown[]
		): Promise<{ rows: T[] }>;
}

let pool: pg.Pool | undefined;
let schemaEnsured = false;

// Current Identity Registry schema version (Task 3, Sprint 5.1; bumped by HAPI ID V2-B).
export const CURRENT_SCHEMA_VERSION = "1.1.0";
export const CURRENT_SCHEMA_DESCRIPTION = "Universal identity federation foundation (V2-B)";
const INITIAL_SCHEMA_VERSION = "1.0.0";
const INITIAL_SCHEMA_DESCRIPTION = "Initial Identity Registry";

export type SchemaVersionInfo = {
		schemaVersion: string | null;
		migrationStatus: "current" | "pending" | "unknown";
};

function buildPool(): pg.Pool {
		const connectionString = configuration.require("DATABASE_URL");
		return new Pool({ connectionString });
}

export function getPostgresPool(): PostgresClient {
		if (!pool) {
				pool = buildPool();
		}

		return pool;
}

// Idempotent bootstrap; safe to call on every process start (Task 2/Task 6 "Restart").
export async function ensureIdentitySchema(client: PostgresClient = getPostgresPool()): Promise<void> {
		if (schemaEnsured) {
				return;
		}

		const schemaDirectory = join(dirname(fileURLToPath(import.meta.url)), "..");
		// Ordered, additive-only DDL files; each must remain individually idempotent.
		for (const file of ["schema.sql", "schema-federation.sql"]) {
				const ddl = readFileSync(join(schemaDirectory, file), "utf8");
				await client.query(ddl);
		}

		// Record each version exactly once; never duplicated on subsequent startups.
		for (const [version, description] of [
				[INITIAL_SCHEMA_VERSION, INITIAL_SCHEMA_DESCRIPTION],
				[CURRENT_SCHEMA_VERSION, CURRENT_SCHEMA_DESCRIPTION]
		]) {
				await client.query(
						`INSERT INTO schema_migrations (version, description, applied_at)
						 VALUES ($1, $2, $3)
						 ON CONFLICT (version) DO NOTHING`,
						[version, description, new Date()]
				);
		}

		schemaEnsured = true;
}

// Read-only for health reporting (Task 4); never mutates schema_migrations.
export async function getSchemaVersionInfo(client: PostgresClient = getPostgresPool()): Promise<SchemaVersionInfo> {
		const result = await client.query<{ version: string }>(
				`SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1`
		);

		const latestVersion = result.rows[0]?.version ?? null;
		if (!latestVersion) {
				return { schemaVersion: null, migrationStatus: "unknown" };
		}

		return {
				schemaVersion: latestVersion,
				migrationStatus: latestVersion === CURRENT_SCHEMA_VERSION ? "current" : "pending"
		};
}

// Runs fn inside a single BEGIN/COMMIT transaction on one dedicated connection. Required by
// operations whose invariants cannot be expressed in a single statement (e.g. V2-B account
// linking: lock subject row -> validate -> mutate -> audit, all-or-nothing).
export type TransactionRunner = <T>(fn: (client: PostgresClient) => Promise<T>) => Promise<T>;

export async function withPostgresTransaction<T>(
		fn: (client: PostgresClient) => Promise<T>,
		transactionPool?: pg.Pool
): Promise<T> {
		if (!transactionPool) {
				getPostgresPool();
				transactionPool = pool as pg.Pool;
		}
		const client = await transactionPool.connect();
		try {
				await client.query("BEGIN");
				const result = await fn(client);
				await client.query("COMMIT");
				return result;
		} catch (error) {
				try {
						await client.query("ROLLBACK");
				} catch {
						// The original error is the meaningful one; a failed ROLLBACK means the connection is gone.
				}
				throw error;
		} finally {
				client.release();
		}
}

export async function closePostgresPool(): Promise<void> {
		if (pool) {
				await pool.end();
				pool = undefined;
				schemaEnsured = false;
		}
}
