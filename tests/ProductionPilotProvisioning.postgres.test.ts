import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { verifyOIDCClientSecret } from "../src/security/OIDCClientSecret.js";
import { provisionPilot } from "../scripts/pilot-provisioning-transaction.mjs";

const databaseUrl = process.env.HAPI_PILOT_TEST_DATABASE_URL;
const applicationId = "123e4567-e89b-42d3-a456-426614174000";
const redirectUri = "https://certification.example.invalid/oidc-certification/callback";
const secret = "A".repeat(64);

describe.skipIf(!databaseUrl)("pilot provisioning on disposable PostgreSQL", () => {
	const schema = `pilot_${randomUUID().replaceAll("-", "")}`;
	let admin: pg.Client;
	let client: pg.Client;
	let databaseName: string;
	let plan: {
		tenant: { id: string; name: string; slug: string };
		application: { name: string; slug: string };
	};

	beforeAll(async () => {
		const url = new URL(databaseUrl!);
		databaseName = decodeURIComponent(url.pathname.slice(1));
		if (!["postgres:", "postgresql:"].includes(url.protocol) ||
			!["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
			!databaseName.startsWith("hapi_disposable_") || url.search || url.hash || process.env.PGOPTIONS) {
			throw new Error("Pilot tests require an explicitly named loopback-only disposable database without connection options");
		}
		const run = spawnSync(process.execPath, ["scripts/provision-production-pilot.mjs",
			"--application-id", applicationId, "--redirect-uri", redirectUri], {
			encoding: "utf8", env: { PATH: process.env.PATH, HOME: process.env.HOME }
		});
		expect(run.status).toBe(0);
		plan = JSON.parse(run.stdout.split("\nNo database changes made.")[0]).plan;
		admin = new pg.Client({ connectionString: databaseUrl });
		await admin.connect();
		await admin.query(`CREATE SCHEMA ${schema}`);
		client = new pg.Client({ connectionString: databaseUrl, options: `-c search_path=${schema}` });
		await client.connect();
		await client.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
	});

	afterEach(async () => {
		vi.restoreAllMocks();
		if (client) {
			await client.query("DROP TRIGGER IF EXISTS fail_pilot_insert ON oidc_clients");
			await client.query("DROP FUNCTION IF EXISTS fail_pilot_insert()");
			await client.query("TRUNCATE oidc_clients, applications, tenants CASCADE");
		}
	});

	afterAll(async () => {
		if (client) await client.end();
		if (admin) {
			await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
			await admin.end();
		}
	});

	async function provision(value = secret) {
		return provisionPilot(client, plan, value, databaseName, schema);
	}

	it("creates the exact tenant, application and OAuth client, then repeats without changes", async () => {
		expect((await provision()).action).toBe("created");
		const tenant = (await client.query("SELECT id, name, slug, status FROM tenants")).rows;
		expect(tenant).toEqual([{ id: plan.tenant.id, name: plan.tenant.name, slug: plan.tenant.slug, status: "active" }]);
		const applications = (await client.query("SELECT id, tenant_id, name, slug, status, application_key, allowed_authentication_methods, allowed_identity_providers, face_setup_enabled FROM applications")).rows;
		expect(applications).toEqual([{ id: applicationId, tenant_id: plan.tenant.id, name: plan.application.name,
			slug: plan.application.slug, status: "active", application_key: "HAPI_PILOT",
			allowed_authentication_methods: ["HAPI_EMAIL"], allowed_identity_providers: [], face_setup_enabled: false }]);
		const clients = (await client.query("SELECT * FROM oidc_clients")).rows;
		expect(clients).toHaveLength(1);
		const row = clients[0];
		expect(row).toMatchObject({ application_id: applicationId, client_id: "hapi-pilot-certification",
			redirect_uris: [redirectUri], scopes: ["openid", "email"], grant_types: ["authorization_code"],
			response_types: ["code"], token_endpoint_auth_method: "client_secret_basic", require_pkce: true, status: "active" });
		expect(row.client_secret.startsWith("scrypt$16384$8$1$")).toBe(true);
		expect(row.client_secret.includes(secret)).toBe(false);
		expect(await verifyOIDCClientSecret(row.client_secret, secret)).toBe(true);
		expect(await verifyOIDCClientSecret(row.client_secret, "B".repeat(64))).toBe(false);
		expect((await provision()).action).toBe("unchanged");
		expect((await client.query("SELECT * FROM oidc_clients")).rows).toEqual(clients);
		expect((await client.query("SELECT count(*)::int AS count FROM tenants")).rows[0].count).toBe(1);
		expect((await client.query("SELECT count(*)::int AS count FROM applications")).rows[0].count).toBe(1);
	});

	it("uses a fresh salt when provisioning the same synthetic credential twice", async () => {
		await provision();
		const first = (await client.query("SELECT client_secret FROM oidc_clients")).rows[0].client_secret;
		await client.query("TRUNCATE oidc_clients, applications, tenants CASCADE");
		await provision();
		const second = (await client.query("SELECT client_secret FROM oidc_clients")).rows[0].client_secret;
		expect(first === second).toBe(false);
		expect(await verifyOIDCClientSecret(second, secret)).toBe(true);
	});

	it.each([
		["tenant", "UPDATE tenants SET name='conflict'", "existing pilot tenant differs"],
		["application", "UPDATE applications SET name='conflict'", "existing approved application differs"],
		["client", "UPDATE oidc_clients SET redirect_uris=ARRAY['https://other.example.invalid']", "client or credential differs"]
	])("refuses a conflicting existing %s without modifying rows", async (_name, update, message) => {
		await provision();
		await client.query(update);
		const before = (await client.query("SELECT to_jsonb(t) AS row FROM tenants t UNION ALL SELECT to_jsonb(a) FROM applications a UNION ALL SELECT to_jsonb(c) FROM oidc_clients c")).rows;
		await expect(provision()).rejects.toThrow(message);
		const after = (await client.query("SELECT to_jsonb(t) AS row FROM tenants t UNION ALL SELECT to_jsonb(a) FROM applications a UNION ALL SELECT to_jsonb(c) FROM oidc_clients c")).rows;
		expect(JSON.stringify(after) === JSON.stringify(before)).toBe(true);
	});

	it.each(["application", "client"])("rolls back newly created rows when a pre-existing %s conflicts", async conflict => {
		const otherTenant = randomUUID();
		const otherApplication = conflict === "application" ? applicationId : randomUUID();
		await client.query("INSERT INTO tenants VALUES ($1,'Other','other','active',now(),now())", [otherTenant]);
		await client.query(`INSERT INTO applications
			(id, tenant_id, name, slug, status, created_at, updated_at, application_key)
			VALUES ($1,$2,'Other','other','active',now(),now(),'OTHER')`, [otherApplication, otherTenant]);
		if (conflict === "client") {
			await client.query(`INSERT INTO oidc_clients
				(id, application_id, client_id, client_secret, redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method, created_at, updated_at)
				VALUES (gen_random_uuid(),$1,'hapi-pilot-certification','other',ARRAY['https://other.invalid'],
					ARRAY['openid'],ARRAY['authorization_code'],ARRAY['code'],'client_secret_basic',now(),now())`, [otherApplication]);
		}
		await expect(provision()).rejects.toThrow(conflict === "application"
			? "existing approved application differs" : "client or credential differs");
		expect((await client.query("SELECT id FROM tenants")).rows).toEqual([{ id: otherTenant }]);
		expect((await client.query("SELECT id FROM applications")).rows).toEqual([{ id: otherApplication }]);
		expect((await client.query("SELECT count(*)::int AS count FROM oidc_clients")).rows[0].count)
			.toBe(conflict === "client" ? 1 : 0);
	});

	it("refuses a different credential without disclosing either value", async () => {
		await provision();
		let message = "";
		try {
			await provision("B".repeat(64));
		} catch (error) {
			message = String(error);
		}
		expect(message.includes("client or credential differs")).toBe(true);
		expect(message.includes(secret) || message.includes("B".repeat(64))).toBe(false);
		expect((await client.query("SELECT count(*)::int AS count FROM oidc_clients")).rows[0].count).toBe(1);
	});

	it("rolls back tenant and application on a database failure without exposing the credential", async () => {
		await client.query(`CREATE FUNCTION fail_pilot_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'synthetic insertion failure'; END $$`);
		await client.query("CREATE TRIGGER fail_pilot_insert BEFORE INSERT ON oidc_clients FOR EACH ROW EXECUTE FUNCTION fail_pilot_insert()");
		const log = vi.spyOn(console, "log").mockImplementation(() => {});
		const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
		let message = "";
		try {
			await provision();
		} catch (error) {
			message = String(error);
		}
		expect(message.includes("Provisioning failed")).toBe(true);
		expect((message + JSON.stringify([...log.mock.calls, ...errorLog.mock.calls])).includes(secret)).toBe(false);
		for (const table of ["tenants", "applications", "oidc_clients"]) {
			expect((await client.query(`SELECT count(*)::int AS count FROM ${table}`)).rows[0].count).toBe(0);
		}
	});

	it("refuses an incorrect connected schema before mutation", async () => {
		await expect(provisionPilot(client, plan, secret, databaseName, "wrong_schema")).rejects.toThrow("connected database or schema differs");
		expect((await client.query("SELECT count(*)::int AS count FROM tenants")).rows[0].count).toBe(0);
	});
});
