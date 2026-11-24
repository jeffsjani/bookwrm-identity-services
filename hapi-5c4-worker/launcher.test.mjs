import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { productionTarget, validateTarget } from "./target.mjs";

const secret = "SYNTHETIC_" + "x".repeat(64);
const env = { PATH: process.env.PATH, HAPI_WORKER_CLIENT_SECRET: secret,
	HAPI_WORKER_EXECUTION_ACK: "I_HAVE_APPROVED_ONE_PRODUCTION_WRITE", HAPI_WORKER_BACKEND_FLAGS_CONFIRMED: "true" };

test("startup only prints a suspended plan and never prints credentials", { timeout: 5000 }, async () => {
	for (let run = 0; run < 2; run += 1) {
		const child = spawn("sh", ["hapi-5c4-worker/start.sh"], { env });
		let output = "";
		child.stdout.setEncoding("utf8");
		child.stderr.setEncoding("utf8");
		child.stderr.on("data", data => { output += data; });
		try {
			for await (const data of child.stdout) {
				output += data;
				if (output.includes("PLAN_ONLY_PASS")) break;
			}
			assert.match(output, /PLAN_ONLY_PASS/);
			assert.equal(child.exitCode, null);
			assert.ok(!output.includes(secret));
		} finally {
			child.kill("SIGTERM");
			await once(child, "close");
		}
	}
});

test("execution and retry requests are refused without printing credentials", () => {
	for (const argument of ["--execute", "--retry", "--execute-once", "--inspect"]) {
		const result = spawnSync(process.execPath, ["hapi-5c4-worker/launcher.mjs", argument], { env, encoding: "utf8" });
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /WORKER_FAIL/);
		assert.ok(!(result.stdout + result.stderr).includes(secret));
	}
});

test("startup refuses NODE_OPTIONS before invoking Node", () => {
	const result = spawnSync("sh", ["hapi-5c4-worker/start.sh"], {
		env: { ...env, NODE_OPTIONS: "--require=/nonexistent" }, encoding: "utf8"
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /WORKER_FAIL: NODE_OPTIONS/);
	assert.ok(!(result.stdout + result.stderr).includes(secret));
});

test("manual action rejects NODE_OPTIONS before invoking Node", () => {
	const result = spawnSync("sh", ["hapi-5c4-worker/manual.sh", "--execute-once"], {
		env: { ...env, NODE_OPTIONS: "--require=/nonexistent" }, encoding: "utf8"
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /WORKER_FAIL: NODE_OPTIONS/);
	assert.ok(!(result.stdout + result.stderr).includes(secret));
});

test("Railway configuration has no restart or schedule", () => {
	const config = JSON.parse(readFileSync("hapi-5c4-worker/railway.json", "utf8"));
	assert.equal(config.deploy.restartPolicyType, "NEVER");
	assert.equal(config.deploy.cronSchedule, undefined);
});

test("target checks reject incorrect identity and certificates", () => {
	const target = { ...productionTarget };
	const values = {
		RAILWAY_PROJECT_ID: target.project,
		RAILWAY_ENVIRONMENT_ID: target.environment,
		OIDC_ISSUER: "https://id.hapiinc.com",
		DATABASE_URL: "postgres://synthetic:synthetic@postgres.railway.internal:5432/railway"
	};
	assert.throws(() => validateTarget({ ...values, RAILWAY_PROJECT_ID: "wrong" }, "invalid", target));
	assert.throws(() => validateTarget(values, "invalid", target));
});