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

// Current Identity Registry schema version (Task 3, Sprint 5.1).
export const CURRENT_SCHEMA_VERSION = "1.0.0";
const CURRENT_SCHEMA_DESCRIPTION = "Initial Identity Registry";

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

		const schemaPath = join(dirname(fileURLToPath(import.meta.url)), "..", "schema.sql");
		const ddl = readFileSync(schemaPath, "utf8");
		await client.query(ddl);

		// Record the current version exactly once; never duplicated on subsequent startups.
		await client.query(
				`INSERT INTO schema_migrations (version, description, applied_at)
				 VALUES ($1, $2, $3)
				 ON CONFLICT (version) DO NOTHING`,
				[CURRENT_SCHEMA_VERSION, CURRENT_SCHEMA_DESCRIPTION, new Date()]
		);

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

export async function closePostgresPool(): Promise<void> {
		if (pool) {
				await pool.end();
				pool = undefined;
				schemaEnsured = false;
		}
}
