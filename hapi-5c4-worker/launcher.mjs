import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { execute } from "./execute.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const files = {
	"provision-production-pilot.mjs": "f3e5add7f236a59ca13138b980975a1c18fc7f9522023a95f06e96fca499ece8",
	"pilot-provisioning-transaction.mjs": "c48989f6ca0c6102286c1defb341f799681f19386b2097263c1a0d1371baaded"
};

try {
	const argumentsList = process.argv.slice(2);
	const manualExecution = argumentsList.length === 1 && argumentsList[0] === "--execute-once";
	const inspect = argumentsList.length === 1 && argumentsList[0] === "--inspect";
	const serve = argumentsList.length === 1 && argumentsList[0] === "--serve";
	if ((argumentsList.length !== 0 && !manualExecution && !inspect && !serve) || process.env.NODE_OPTIONS || process.env.PGOPTIONS) {
		throw new Error("unsupported invocation");
	}
	for (const [name, expected] of Object.entries(files)) {
		const actual = createHash("sha256").update(readFileSync(join(directory, "scripts", name))).digest("hex");
		if (actual !== expected) throw new Error("package integrity");
	}
	const result = spawnSync(process.execPath, [join(directory, "scripts", "provision-production-pilot.mjs"),
		"--application-id", "5716f2cc-519e-40d9-8b51-011e7be409a7",
		"--redirect-uri", "https://certification.hapiinc.com/oidc-certification/callback"], {
		encoding: "utf8", env: {}, stdio: ["ignore", "pipe", "pipe"], timeout: 10000
	});
	if (result.error || result.status !== 0) throw new Error("plan failed");
	const marker = "\nNo database changes made.";
	const markerIndex = result.stdout.indexOf(marker);
	if (markerIndex < 0) throw new Error("invalid plan");
	const plan = JSON.parse(result.stdout.slice(0, markerIndex));
	if (plan.action !== "plan-only" || plan.plan.applicationId !== "5716f2cc-519e-40d9-8b51-011e7be409a7" ||
		plan.plan.client.clientId !== "hapi-pilot-certification" ||
		plan.plan.client.redirectUri !== "https://certification.hapiinc.com/oidc-certification/callback" ||
		plan.plan.client.status !== "suspended") throw new Error("invalid plan");
	console.log("PLAN_ONLY_PASS: suspended client; no database changes");
	if (manualExecution) {
		await execute(process.env, join(directory, "locked-provision.mjs"));
		console.log("PROVISIONING_PASS: suspended client metadata verified");
	}
	if (inspect) {
		const result = await execute(process.env, join(directory, "locked-provision.mjs"), undefined, "inspect");
		console.log(result === "matched" ? "INSPECTION_PASS: matching suspended client" : "INSPECTION_PASS: no pilot metadata");
	}
	if (serve) setInterval(() => {}, 60000);
} catch {
	console.error("WORKER_FAIL: outcome may be uncertain; inspect metadata before any retry");
	process.exitCode = 1;
}