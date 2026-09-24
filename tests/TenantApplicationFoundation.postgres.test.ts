import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Integration test against a real PostgreSQL instance (HAPI ID H1 Multi-Tenant/Application Foundation).
// Skipped automatically when DATABASE_URL is not set.
const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("HAPI ID H1 - schema migration + Bookwrm backfill (integration)", () => {
		let ensureIdentitySchema: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").ensureIdentitySchema;
		let getPostgresPool: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").getPostgresPool;
		let closePostgresPool: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").closePostgresPool;
		let ensureBookwrmApplicationSeed: typeof import("../src/adapters/base44/Base44ApplicationSeed.js").ensureBookwrmApplicationSeed;
		let BOOKWRM_TENANT_ID: typeof import("../src/identity/WellKnownIdentities.js").BOOKWRM_TENANT_ID;
		let BOOKWRM_APPLICATION_ID: typeof import("../src/identity/WellKnownIdentities.js").BOOKWRM_APPLICATION_ID;
		let registerOIDCClients: typeof import("../src/oidc/clients.js").registerOIDCClients;

		beforeAll(async () => {
				process.env.DATABASE_URL = databaseUrl;
				process.env.IDENTITY_REGISTRY_DRIVER = "postgres";
				process.env.OIDC_BASE44_CLIENT_ID = "bookwrm-base44-production";
				process.env.OIDC_BASE44_CLIENT_SECRET = "integration-test-secret";
				process.env.OIDC_BASE44_REDIRECT_URI = "https://existing.example.com/auth/sso/callback";
				delete process.env.OIDC_BASE44_REDIRECT_URIS;

				({ ensureIdentitySchema, getPostgresPool, closePostgresPool } = await import(
						"../src/identity/infrastructure/PostgresInfrastructure.js"
				));
				({ ensureBookwrmApplicationSeed } = await import("../src/adapters/base44/Base44ApplicationSeed.js"));
				({ BOOKWRM_TENANT_ID, BOOKWRM_APPLICATION_ID } = await import("../src/identity/WellKnownIdentities.js"));
				({ registerOIDCClients } = await import("../src/oidc/clients.js"));

				await ensureIdentitySchema();
		});

		afterAll(async () => {
				const pool = getPostgresPool();
				await pool.query("DELETE FROM oidc_clients WHERE application_id = $1", [BOOKWRM_APPLICATION_ID]);
				await pool.query("DELETE FROM applications WHERE id = $1", [BOOKWRM_APPLICATION_ID]);
				await pool.query("DELETE FROM tenants WHERE id = $1", [BOOKWRM_TENANT_ID]);
				await closePostgresPool();
		});

		it("adds the tenants/applications/oidc_clients tables and a nullable identity_subjects.application_id column", async () => {
				const pool = getPostgresPool();

				const tables = await pool.query<{ table_name: string }>(
						`SELECT table_name FROM information_schema.tables
						 WHERE table_schema = 'public' AND table_name IN ('tenants', 'applications', 'oidc_clients')`
				);
				expect(tables.rows.map((row) => row.table_name).sort()).toEqual(["applications", "oidc_clients", "tenants"]);

				const column = await pool.query<{ is_nullable: string }>(
						`SELECT is_nullable FROM information_schema.columns
						 WHERE table_name = 'identity_subjects' AND column_name = 'application_id'`
				);
				expect(column.rows[0]?.is_nullable).toBe("YES");
		});

		it("backfills pre-H1 IdentitySubjects (application_id IS NULL) onto Bookwrm's Application, and seeds Tenant/Application/OIDCClient idempotently", async () => {
				const pool = getPostgresPool();

				// Simulate a row created before H1 shipped: no application_id, since the column didn't exist yet.
				const legacySubjectId = randomUUID();
				const legacyOidcSubject = randomUUID();
				const now = new Date();
				await pool.query(
						`INSERT INTO identity_subjects
							(id, oidc_subject, primary_provider, primary_provider_subject, status, created_at, updated_at)
						 VALUES ($1, $2, 'PrivateID', $3, 'ACTIVE', $4, $4)`,
						[legacySubjectId, legacyOidcSubject, `pre-h1-puid-${legacySubjectId}`, now]
				);

				const beforeBackfill = await pool.query<{ application_id: string | null }>(
						`SELECT application_id FROM identity_subjects WHERE id = $1`,
						[legacySubjectId]
				);
				expect(beforeBackfill.rows[0]?.application_id).toBeNull();

				const firstRun = await ensureBookwrmApplicationSeed();
				expect(firstRun.tenantId).toBe(BOOKWRM_TENANT_ID);
				expect(firstRun.applicationId).toBe(BOOKWRM_APPLICATION_ID);
				expect(firstRun.clientSeeded).toBe(true);
				expect(firstRun.backfilledIdentitySubjects).toBeGreaterThanOrEqual(1);

				const afterBackfill = await pool.query<{ application_id: string | null }>(
						`SELECT application_id FROM identity_subjects WHERE id = $1`,
						[legacySubjectId]
				);
				expect(afterBackfill.rows[0]?.application_id).toBe(BOOKWRM_APPLICATION_ID);

				const [legacyClient] = registerOIDCClients();
				const persistedClient = await pool.query<{ client_secret: string; redirect_uris: string[] }>(
						`SELECT client_secret, redirect_uris FROM oidc_clients WHERE client_id = $1`,
						[legacyClient.client_id]
				);
				expect(persistedClient.rows).toHaveLength(1);
				expect(persistedClient.rows[0].client_secret).toBe(legacyClient.client_secret);
				expect(persistedClient.rows[0].redirect_uris).toEqual(legacyClient.redirect_uris);

				// Idempotency: running the seed again must not duplicate rows or re-backfill the same row.
				const secondRun = await ensureBookwrmApplicationSeed();
				expect(secondRun.backfilledIdentitySubjects).toBe(0);

				const tenantCount = await pool.query(`SELECT id FROM tenants WHERE id = $1`, [BOOKWRM_TENANT_ID]);
				const applicationCount = await pool.query(`SELECT id FROM applications WHERE id = $1`, [BOOKWRM_APPLICATION_ID]);
				const clientCount = await pool.query(`SELECT id FROM oidc_clients WHERE client_id = $1`, [legacyClient.client_id]);
				expect(tenantCount.rows).toHaveLength(1);
				expect(applicationCount.rows).toHaveLength(1);
				expect(clientCount.rows).toHaveLength(1);

				await pool.query("DELETE FROM identity_subjects WHERE id = $1", [legacySubjectId]);
		});

		it("scopes newly created IdentitySubjects to Bookwrm's Application at creation time (no backfill needed)", async () => {
				const { IdentityRegistry } = await import("../src/identity/IdentityRegistry.js");
				const { PostgresIdentitySubjectRepository } = await import("../src/identity/PostgresIdentitySubjectRepository.js");

				const registry = new IdentityRegistry(new PostgresIdentitySubjectRepository());
				const subject = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: `post-h1-puid-${randomUUID()}`
				});

				expect(subject.applicationId).toBe(BOOKWRM_APPLICATION_ID);

				const pool = getPostgresPool();
				await pool.query("DELETE FROM identity_subjects WHERE id = $1", [subject.id]);
		});
});
