import assert from "node:assert/strict";
import { X509Certificate, scryptSync, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { lookup } from "node:dns/promises";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { execute } from "./execute.mjs";

const databaseUrl = process.env.HAPI_WORKER_TEST_DATABASE_URL;
const caPath = process.env.HAPI_WORKER_TEST_CA;
const badCaPath = process.env.HAPI_WORKER_TEST_BAD_CA;

test("disposable TLS provisioning, concurrency, secret match and duplicate refusal", {
	skip: !databaseUrl || !caPath || !badCaPath, timeout: 60000
}, async () => {
	const url = new URL(databaseUrl);
	assert.equal(url.hostname, "127.0.0.1.nip.io");
	assert.equal(url.pathname, "/hapi_disposable_pilot");
	assert.equal(url.search, "");
	assert.equal((await lookup(url.hostname, { family: 4 })).address, "127.0.0.1");
	const certificate = readFileSync(caPath, "utf8");
	const badCertificate = readFileSync(badCaPath, "utf8");
	const target = { project: "synthetic-project", environment: "synthetic-environment", host: url.hostname,
		port: url.port, database: url.pathname.slice(1), schema: "public", fingerprint: new X509Certificate(certificate).fingerprint256 };
	const secret = "A".repeat(64);
	const env = { RAILWAY_PROJECT_ID: target.project, RAILWAY_ENVIRONMENT_ID: target.environment,
		RAILWAY_SERVICE_ID: "synthetic-service", HAPI_WORKER_APPROVED_SERVICE_ID: "synthetic-service",
		OIDC_ISSUER: "https://id.hapiinc.com", DATABASE_URL: databaseUrl,
		HAPI_WORKER_POSTGRES_CA: certificate, HAPI_WORKER_CLIENT_SECRET: secret,
		HAPI_WORKER_EXECUTION_ACK: "I_HAVE_APPROVED_ONE_PRODUCTION_WRITE", HAPI_WORKER_BACKEND_FLAGS_CONFIRMED: "true" };
	const script = fileURLToPath(new URL("./locked-provision.mjs", import.meta.url));
	const admin = new pg.Client({ connectionString: databaseUrl, ssl: { ca: certificate, rejectUnauthorized: true } });
	await admin.connect();
	try {
		await admin.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		await admin.query("DROP TRIGGER IF EXISTS slow_pilot ON oidc_clients");
		await admin.query("TRUNCATE oidc_clients, applications, tenants CASCADE");
		await assert.rejects(execute({ ...env, HAPI_WORKER_EXECUTION_ACK: "" }, script, target));
		await assert.rejects(execute({ ...env, HAPI_EMAIL_AUTHENTICATION_ENABLED: "true" }, script, target));
		await assert.rejects(execute({ ...env, HAPI_UNIVERSAL_LOGIN_ENABLED: "true" }, script, target));
		const badTarget = { ...target, fingerprint: new X509Certificate(badCertificate).fingerprint256 };
		await assert.rejects(execute({ ...env, HAPI_WORKER_POSTGRES_CA: badCertificate }, script, badTarget));
		const wrongHost = "127-0-0-1.sslip.io";
		const wrongUrl = new URL(databaseUrl);
		wrongUrl.hostname = wrongHost;
		await assert.rejects(execute({ ...env, DATABASE_URL: wrongUrl.toString() }, script, { ...target, host: wrongHost }),
			error => error.code === "ERR_TLS_CERT_ALTNAME_INVALID");
		assert.equal(Number((await admin.query("SELECT count(*) FROM oidc_clients")).rows[0].count), 0);
		assert.equal(await execute(env, script, target, "inspect"), "not_created");
		await admin.query(`CREATE OR REPLACE FUNCTION slow_pilot_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$`);
		await admin.query("CREATE TRIGGER slow_pilot BEFORE INSERT ON oidc_clients FOR EACH ROW EXECUTE FUNCTION slow_pilot_insert()");
		const results = await Promise.allSettled([execute(env, script, target), execute(env, script, target)]);
		assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
		assert.equal(results.filter(result => result.status === "rejected").length, 1);
		const rows = (await admin.query("SELECT status, client_secret FROM oidc_clients WHERE client_id = 'hapi-pilot-certification'")).rows;
		assert.equal(rows.length, 1);
		assert.equal(rows[0].status, "suspended");
		const parts = rows[0].client_secret.split("$");
		const expected = Buffer.from(parts[5], "base64url");
		assert.ok(timingSafeEqual(scryptSync(secret, Buffer.from(parts[4], "base64url"), 32), expected));
		assert.ok(!timingSafeEqual(scryptSync("B".repeat(64), Buffer.from(parts[4], "base64url"), 32), expected));
		assert.equal(await execute(env, script, target, "inspect"), "matched");
		await assert.rejects(execute({ ...env, HAPI_WORKER_CLIENT_SECRET: "B".repeat(64) }, script, target, "inspect"));
		await assert.rejects(execute(env, script, target));
		assert.equal(Number((await admin.query("SELECT count(*) FROM oidc_clients")).rows[0].count), 1);

		await admin.query("TRUNCATE oidc_clients, applications, tenants CASCADE");
		await admin.query(`CREATE OR REPLACE FUNCTION slow_pilot_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$`);
		const moduleUrl = new URL("./execute.mjs", import.meta.url).href;
		const source = `import { execute } from ${JSON.stringify(moduleUrl)};
			await execute(process.env, ${JSON.stringify(script)}, ${JSON.stringify(target)});`;
		const parent = spawn(process.execPath, ["--input-type=module", "-e", source], { env, stdio: "ignore" });
		const deadline = Date.now() + 10000;
		let locked = false;
		try {
			while (Date.now() < deadline) {
				const locks = await admin.query("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = 1212248153 AND objid = 534 AND granted");
				if (Number(locks.rows[0].count) > 0) { locked = true; break; }
				await new Promise(resolve => setTimeout(resolve, 25));
			}
			assert.ok(locked, "child must acquire the execution lock");
			parent.kill("SIGKILL");
			await once(parent, "close");
			await assert.rejects(execute(env, script, target, "inspect"));
			await assert.rejects(execute(env, script, target));
			while (Date.now() < deadline) {
				const current = await admin.query("SELECT status FROM oidc_clients WHERE client_id = 'hapi-pilot-certification'");
				if (current.rows.length) { assert.equal(current.rows[0].status, "suspended"); break; }
				await new Promise(resolve => setTimeout(resolve, 25));
			}
			assert.equal(Number((await admin.query("SELECT count(*) FROM oidc_clients")).rows[0].count), 1);
			assert.equal(await execute(env, script, target, "inspect"), "matched");
			await assert.rejects(execute(env, script, target));
		} finally {
			if (parent.exitCode === null && parent.signalCode === null) parent.kill("SIGKILL");
		}
	} finally {
		await admin.end();
	}
});