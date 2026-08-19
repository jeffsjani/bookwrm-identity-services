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
		schemaEnsured = true;
}

export async function closePostgresPool(): Promise<void> {
		if (pool) {
				await pool.end();
				pool = undefined;
				schemaEnsured = false;
		}
}
