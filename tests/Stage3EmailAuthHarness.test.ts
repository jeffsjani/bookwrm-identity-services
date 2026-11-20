import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const mockFetch = `
let probes = 0;
globalThis.fetch = async (url) => {
	const scenario = process.env.TEST_SCENARIO;
	if (url.endsWith("/.well-known/openid-configuration")) return Response.json({
		issuer: scenario === "bad-issuer" ? "https://unexpected.invalid" : "https://id-staging.hapiinc.com",
		grant_types_supported: scenario === "bad-grants" ? ["authorization_code", "refresh_token"] : ["authorization_code"],
		jwks_uri: "https://id-staging.hapiinc.com/jwks",
		userinfo_endpoint: scenario === "bad-endpoint" ? "https://unexpected.invalid/userinfo" : "https://id-staging.hapiinc.com/userinfo"
	});
	if (url.endsWith("/jwks")) return Response.json({ keys: [{ kid: "synthetic" }] });
	if (url.endsWith("/v1/registration/complete")) {
		probes++;
		if (probes === 1) return Response.json({ error: scenario === "bad-evidence" ? "INVALID_REQUEST" : "INVALID_EVIDENCE" }, { status: scenario === "bad-correct" ? 401 : 400 });
		return Response.json({}, { status: scenario === "bad-incorrect" ? 400 : 401 });
	}
	if (url.endsWith("/v1/identity/email/start")) { console.error("MOCK_OTP_REACHED"); process.exit(77); }
	throw new Error("Unexpected request");
};`;

function runHarness(scenario: string, approved = true) {
	const preload = `data:text/javascript;base64,${Buffer.from(mockFetch).toString("base64")}`;
	return spawnSync(process.execPath, ["--import", preload, "scripts/stage3-email-auth-test.mjs",
		...(approved ? ["--staging-live-approved"] : []), "--register-identity"], {
		encoding: "utf8",
		env: { ...process.env, STAGING_WEB_CLIENT_SECRET: "x".repeat(32), STAGING_TEST_EMAIL: "test@example.invalid",
			STAGING_ISSUER: "https://id-staging.hapiinc.com", TEST_SCENARIO: scenario }
	});
}

describe("Stage 3 email harness preflight", () => {
	it.each(["bad-correct", "bad-evidence", "bad-incorrect", "bad-issuer", "bad-grants", "bad-endpoint"])(
		"stops before OTP for %s", scenario => {
			const result = runHarness(scenario);
			expect(result.status).toBe(1);
			expect(result.stderr).not.toContain("MOCK_OTP_REACHED");
		}
	);

	it("requires explicit approval before requests", () => {
		const result = runHarness("both-pass", false);
		expect(result.status).toBe(1);
		expect(result.stderr).not.toContain("MOCK_OTP_REACHED");
	});

	it("reaches the mocked OTP path only after both probes pass", () => {
		const result = runHarness("both-pass");
		expect(result.status).toBe(77);
		expect(result.stdout).toContain("secret.accepted");
		expect(result.stdout).toContain("secret.rejected");
		expect(result.stderr).toContain("MOCK_OTP_REACHED");
	});
});