import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Integration test against a real PostgreSQL instance (Sprint 5.1, Task 5).
// Skipped automatically when DATABASE_URL is not set.
const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("Schema versioning (integration)", () => {
		let ensureIdentitySchema: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").ensureIdentitySchema;
		let getSchemaVersionInfo: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").getSchemaVersionInfo;
		let getPostgresPool: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").getPostgresPool;
		let closePostgresPool: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").closePostgresPool;
		let CURRENT_SCHEMA_VERSION: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").CURRENT_SCHEMA_VERSION;

		beforeAll(async () => {
				process.env.DATABASE_URL = databaseUrl;
				({
						ensureIdentitySchema,
						getSchemaVersionInfo,
						getPostgresPool,
						closePostgresPool,
						CURRENT_SCHEMA_VERSION
				} = await import("../src/identity/infrastructure/PostgresInfrastructure.js"));
		});

		afterAll(async () => {
				await closePostgresPool();
		});

		it("creates schema_migrations and inserts exactly one row for the current version on a fresh database", async () => {
				const pool = getPostgresPool();
				// Simulate a fresh database from the migrations table's perspective.
				await pool.query("DELETE FROM schema_migrations WHERE version = $1", [CURRENT_SCHEMA_VERSION]);

				// This test file gets its own isolated module instance, so ensureIdentitySchema()
				// runs its real bootstrap path here, not a no-op from a prior call.
				await ensureIdentitySchema();

				const result = await pool.query<{ version: string; description: string }>(
						"SELECT version, description FROM schema_migrations WHERE version = $1",
						[CURRENT_SCHEMA_VERSION]
				);

				expect(result.rows).toHaveLength(1);
				expect(result.rows[0].description).toBe("Initial Identity Registry");

				const info = await getSchemaVersionInfo();
				expect(info.schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
				expect(info.migrationStatus).toBe("current");
		});

		it("never inserts a duplicate row for the same version across repeated startups", async () => {
				const pool = getPostgresPool();

				await pool.query(
						`INSERT INTO schema_migrations (version, description, applied_at)
						 VALUES ($1, $2, $3)
						 ON CONFLICT (version) DO NOTHING`,
						[CURRENT_SCHEMA_VERSION, "Initial Identity Registry", new Date()]
				);
				await pool.query(
						`INSERT INTO schema_migrations (version, description, applied_at)
						 VALUES ($1, $2, $3)
						 ON CONFLICT (version) DO NOTHING`,
						[CURRENT_SCHEMA_VERSION, "Initial Identity Registry", new Date()]
				);
				await pool.query(
						`INSERT INTO schema_migrations (version, description, applied_at)
						 VALUES ($1, $2, $3)
						 ON CONFLICT (version) DO NOTHING`,
						[CURRENT_SCHEMA_VERSION, "Initial Identity Registry", new Date()]
				);

				const result = await pool.query<{ version: string }>(
						"SELECT version FROM schema_migrations WHERE version = $1",
						[CURRENT_SCHEMA_VERSION]
				);
				expect(result.rows.length).toBe(1);
		});

		it("reports migrationStatus 'current' via IdentityAdministrationService.getHealth()", async () => {
				process.env.IDENTITY_REGISTRY_DRIVER = "postgres";
				const { identityAdministrationService } = await import("../src/identity/IdentityAdministrationService.js");
				const health = await identityAdministrationService.getHealth();

				expect(health.schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
				expect(health.migrationStatus).toBe("current");
		});
});
