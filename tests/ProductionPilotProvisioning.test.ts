import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";

const script = "scripts/provision-production-pilot.mjs";
const applicationId = "123e4567-e89b-42d3-a456-426614174000";
const redirectUri = "https://certification.example.com/oidc-certification/callback";

describe("production pilot provisioning", () => {
	it("plan mode cannot write and emits the exact pilot shape", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri], {
			cwd: process.cwd(), encoding: "utf8"
		});
		expect(run.status).toBe(0);
		expect(run.stdout).toContain('"action": "plan-only"');
		expect(run.stdout).toContain('"grantTypes"');
		expect(run.stdout).toContain('"authorization_code"');
		expect(run.stdout).toContain('"authMethod": "client_secret_basic"');
		expect(run.stdout).toContain('"requirePkce": true');
		expect(run.stdout).not.toContain("refresh_token");
		expect(run.stdout).not.toContain("never-rendered");
	});

	it("execute mode refuses without explicit production acknowledgement", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", env: { ...process.env, DATABASE_URL: "postgresql://user:pass@localhost/db" }
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("Execution refused");
	});

	it("execute mode refuses a staging or disposable database hostname", () => {
		const run = spawnSync(process.execPath, [script, "--application-id", applicationId, "--redirect-uri", redirectUri, "--execute"], {
			cwd: process.cwd(), encoding: "utf8", env: {
				...process.env,
				HAPI_PILOT_PROVISIONING_ACKNOWLEDGED: "true",
				HAPI_PILOT_PROVISIONING_TARGET: "https://id.hapiinc.com",
				OIDC_ISSUER: "https://id.hapiinc.com",
				DATABASE_URL: "postgresql://user:pass@staging-db.example/db"
			}
		});
		expect(run.status).not.toBe(0);
		expect(run.stderr + run.stdout).toContain("disposable environment");
	});
});
