import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

// Only point this at a disposable local database.
const databaseUrl = process.env.HAPI_STARTUP_TEST_DATABASE_URL;
const redisUrl = process.env.HAPI_STARTUP_TEST_REDIS_URL;

describe.skipIf(!databaseUrl)("HAPI production startup safety", () => {
		const admin = new pg.Pool({ connectionString: databaseUrl });
		const schemas: string[] = [];
		const children: ChildProcess[] = [];
		const privateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey
				.export({ type: "pkcs8", format: "pem" }).toString();

		beforeAll(() => {
				for (const url of [databaseUrl, redisUrl]) {
						if (url && !["localhost", "127.0.0.1", "[::1]"].includes(new URL(url).hostname)) {
								throw new Error("Startup tests require loopback-only disposable services");
						}
				}
		});

		async function newSchema(): Promise<{ url: string; pool: pg.Pool }> {
				const schema = `startup_${randomUUID().replaceAll("-", "")}`;
				await admin.query(`CREATE SCHEMA ${schema}`);
				schemas.push(schema);
				const url = new URL(databaseUrl!);
				url.searchParams.set("options", `-c search_path=${schema}`);
				return { url: url.toString(), pool: new pg.Pool({ connectionString: url.toString() }) };
		}

		function start(url: string, extraEnv: NodeJS.ProcessEnv = {}) {
				const child = spawn(process.execPath, ["--import", "tsx", "src/server.ts"], {
						env: {
								PATH: process.env.PATH,
								HOME: process.env.HOME,
								NODE_ENV: "production",
								PORT: "0",
								OIDC_ISSUER: "https://id.hapiinc.com",
								OIDC_ALLOWED_ISSUERS: "https://id.hapiinc.com",
								CORS_TRUSTED_ORIGINS: "https://id.hapiinc.com",
								DATABASE_URL: url,
								OIDC_USE_REDIS_MOCK: redisUrl ? "false" : "true",
								...(redisUrl ? { REDIS_URL: redisUrl } : {}),
								JWT_PRIVATE_KEY: privateKey,
								PRIVATEID_CALLBACK_URL: "https://id.hapiinc.com/privateid/webhook",
								PRIVATEID_REDIRECT_URL: "https://id.hapiinc.com/privateid/callback",
								MOCK_AUTH_ENABLED: "false",
								HAPI_PLATFORM_SERVICE_KEY: "synthetic-legacy-key",
								...extraEnv
						},
						stdio: ["ignore", "pipe", "pipe"]
				});
				children.push(child);
				let output = "";
				child.stdout!.on("data", chunk => { output += chunk.toString(); });
				child.stderr!.on("data", chunk => { output += chunk.toString(); });
				const exited = new Promise<number | null>((resolve, reject) => {
						child.once("error", reject);
						child.once("exit", resolve);
				});
				async function waitForListening(): Promise<string> {
						const deadline = Date.now() + 15_000;
						while (Date.now() < deadline) {
								const match = output.match(/Server listening at http:\/\/127\.0\.0\.1:(\d+)/);
								if (match) return `http://127.0.0.1:${match[1]}`;
								if (child.exitCode !== null) throw new Error(`Server exited before listening: ${output}`);
								await new Promise(resolve => setTimeout(resolve, 50));
						}
						throw new Error(`Server did not listen: ${output}`);
				}
				return { child, exited, waitForListening, output: () => output };
		}

		afterEach(async () => {
				await Promise.all(children.splice(0).map(async child => {
						if (child.exitCode === null && child.signalCode === null) {
								const exited = new Promise(resolve => child.once("exit", resolve));
								child.kill("SIGTERM");
								await exited;
						}
				}));
		});

		afterAll(async () => {
				for (const schema of schemas) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
				await admin.end();
		});

		it("initializes a fresh schema before becoming ready and hides both linking APIs", async () => {
				const { url, pool } = await newSchema();
				try {
						const server = start(url);
						const base = await server.waitForListening();
						const ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(200);
						expect(await ready.json()).toMatchObject({ databaseConnected: true, providerReady: true, migrationsReady: true });
						const versions = await pool.query("SELECT version FROM schema_migrations ORDER BY version");
						expect(versions.rows.map(row => row.version)).toEqual(["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]);
						expect((await fetch(`${base}/internal/identity/account-link`, {
								method: "POST",
								headers: { authorization: "Bearer synthetic-legacy-key", "x-bookwrm-user-id": "test", "content-type": "application/json" },
								body: JSON.stringify({ source: "bookwrm", oidcSubject: randomUUID() })
						})).status).toBe(404);
						expect((await fetch(`${base}/account/authentication-methods`)).status).toBe(404);
						expect((await pool.query("SELECT client_id FROM oidc_clients")).rows).toHaveLength(0);
						server.child.kill("SIGTERM");
						expect(await server.exited).toBe(0);
						const restarted = start(url);
						const restartedBase = await restarted.waitForListening();
						const restartedReady = await fetch(`${restartedBase}/health/ready`);
						expect(restartedReady.status).toBe(200);
						expect(await restartedReady.json()).toMatchObject({ migrationsReady: true });
						expect((await pool.query("SELECT version FROM schema_migrations")).rows).toHaveLength(5);
				} finally {
						await pool.end();
				}
		}, 35_000);

		it("fails readiness for each missing migration, missing unversioned schema, or verification error", async () => {
				const { url, pool } = await newSchema();
				try {
						const server = start(url);
						const base = await server.waitForListening();
						for (const version of ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]) {
								const removed = await pool.query("DELETE FROM schema_migrations WHERE version = $1 RETURNING *", [version]);
								const ready = await fetch(`${base}/health/ready`);
								expect(ready.status, version).toBe(503);
								expect(await ready.json()).toMatchObject({ status: "not_ready", databaseConnected: true, migrationsReady: false });
								const row = removed.rows[0];
								await pool.query("INSERT INTO schema_migrations (version, description, applied_at) VALUES ($1, $2, $3)",
										[row.version, row.description, row.applied_at]);
						}
						await pool.query("ALTER TABLE identity_registration_audit RENAME TO hidden_registration_audit");
						let ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(503);
						expect(await ready.json()).toMatchObject({ migrationsReady: false });
						await pool.query("ALTER TABLE hidden_registration_audit RENAME TO identity_registration_audit");
						await pool.query("ALTER TABLE authenticator_enrollment_audit RENAME TO hidden_face_audit");
						ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(503);
						expect(await ready.json()).toMatchObject({ migrationsReady: false });
						await pool.query("ALTER TABLE hidden_face_audit RENAME TO authenticator_enrollment_audit");
						await pool.query("ALTER TABLE schema_migrations RENAME TO hidden_schema_migrations");
						ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(503);
						expect(await ready.json()).toMatchObject({ migrationsReady: false });
						await pool.query("ALTER TABLE hidden_schema_migrations RENAME TO schema_migrations");
						ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(200);
						expect(await ready.json()).toMatchObject({ migrationsReady: true });
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("does not become ready when a migration record is not persisted during bootstrap", async () => {
				const { url, pool } = await newSchema();
				try {
						await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
						await pool.query(`CREATE FUNCTION suppress_migration() RETURNS trigger LANGUAGE plpgsql AS $$
								BEGIN IF NEW.version = '1.1.0' THEN RETURN NULL; END IF; RETURN NEW; END $$`);
						await pool.query("CREATE TRIGGER suppress_migration BEFORE INSERT ON schema_migrations FOR EACH ROW EXECUTE FUNCTION suppress_migration()");
						const server = start(url);
						const base = await server.waitForListening();
						const ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(503);
						expect(await ready.json()).toMatchObject({ migrationsReady: false });
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("checks email schema tables when the email provider is configured", async () => {
				const { url, pool } = await newSchema();
				try {
						const server = start(url, {
								HAPI_EMAIL_PROVIDER: "resend",
								HAPI_EMAIL_AUTHENTICATION_ENABLED: "true",
								HAPI_EMAIL_PILOT_ALLOWLIST: "pilot@example.com",
								HAPI_EMAIL_PILOT_APPLICATION_ID: randomUUID(),
								HAPI_EMAIL_VERIFICATION_SECRET: "synthetic-verification-secret-32-bytes",
								RESEND_API_KEY: "synthetic-key",
								HAPI_EMAIL_FROM: "test@example.invalid"
						});
						const base = await server.waitForListening();
						expect((await fetch(`${base}/health/ready`)).status).toBe(200);
						await pool.query("ALTER TABLE email_authentication_audit RENAME TO hidden_email_audit");
						const ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(503);
						expect(await ready.json()).toMatchObject({ migrationsReady: false });
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("refuses a partially configured production pilot allowlist", async () => {
			const { url, pool } = await newSchema();
			try {
				const server = start(url, {
					HAPI_EMAIL_PROVIDER: "resend",
					HAPI_EMAIL_PILOT_APPLICATION_ID: randomUUID(),
					HAPI_EMAIL_VERIFICATION_SECRET: "synthetic-verification-secret-32-bytes",
					RESEND_API_KEY: "synthetic-key",
					HAPI_EMAIL_FROM: "test@example.invalid"
				});
				expect(await server.exited).not.toBe(0);
				expect(server.output()).toContain("HAPI_EMAIL_PILOT_ALLOWLIST and HAPI_EMAIL_PILOT_APPLICATION_ID must be configured together");
				expect(server.output()).not.toContain("Server listening");
			} finally {
				await pool.end();
			}
		}, 25_000);

		it.each(["https://id-staging.hapiinc.com", "https://identity.bookwrm.com"])(
				"does not change readiness for %s", async issuer => {
				const { url, pool } = await newSchema();
				try {
						const server = start(url, { OIDC_ISSUER: issuer, OIDC_ALLOWED_ISSUERS: issuer });
						const base = await server.waitForListening();
						await pool.query("DELETE FROM schema_migrations WHERE version = '1.0.0'");
						const ready = await fetch(`${base}/health/ready`);
						expect(ready.status).toBe(200);
						expect(await ready.json()).not.toHaveProperty("migrationsReady");
						const link = await fetch(`${base}/internal/identity/account-link`, { method: "POST" });
						expect(link.status).toBe(issuer === "https://id-staging.hapiinc.com" ? 404 : 401);
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("exits before listening when schema initialization fails despite a reachable database", async () => {
				const { url, pool } = await newSchema();
				try {
						await pool.query("CREATE TABLE identity_subjects (id integer)");
						expect((await pool.query("SELECT 1")).rows).toHaveLength(1);
						const server = start(url);
						expect(await server.exited).not.toBe(0);
						expect(server.output()).toContain("Failed to bootstrap Identity Registry schema at startup");
						expect(server.output()).not.toContain("Server listening");
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("exits before listening when the startup seed migration fails", async () => {
				const { url, pool } = await newSchema();
				try {
						await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
						await pool.query(`CREATE FUNCTION reject_seed() RETURNS trigger LANGUAGE plpgsql AS $$
								BEGIN RAISE EXCEPTION 'synthetic seed failure'; END $$`);
						await pool.query("CREATE TRIGGER reject_seed BEFORE INSERT ON tenants FOR EACH ROW EXECUTE FUNCTION reject_seed()");
						const server = start(url);
						expect(await server.exited).not.toBe(0);
						expect(server.output()).toContain("Failed to seed Bookwrm Tenant/Application at startup");
						expect(server.output()).not.toContain("Server listening");
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("exits before listening when a later required schema initializer fails", async () => {
				const { url, pool } = await newSchema();
				try {
						await pool.query("CREATE TABLE hapi_face_enrollment_bindings (id integer)");
						const server = start(url);
						expect(await server.exited).not.toBe(0);
						expect(server.output()).toContain("identity_subject_id");
						expect(server.output()).not.toContain("Server listening");
				} finally {
						await pool.end();
				}
		}, 25_000);

		it("rejects a memory registry on the production issuer", async () => {
				const { url, pool } = await newSchema();
				try {
						const server = start(url, { IDENTITY_REGISTRY_DRIVER: "memory" });
						expect(await server.exited).not.toBe(0);
						expect(server.output()).toContain("HAPI production requires the PostgreSQL identity registry");
						expect(server.output()).not.toContain("Server listening");
				} finally {
						await pool.end();
				}
		}, 25_000);
});
