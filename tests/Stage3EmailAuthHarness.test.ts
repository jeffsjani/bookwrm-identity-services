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

const mockTokenFlow = `
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
const require = createRequire(process.cwd() + "/package.json");
const { SignJWT, exportJWK, generateKeyPair } = await import(pathToFileURL(require.resolve("jose")).href);
const scenario = process.env.TEST_SCENARIO;
const algorithm = scenario === "bad-algorithm" ? "RS512" : "RS256";
const keys = await generateKeyPair(algorithm, { extractable: true });
const signingKeys = scenario === "bad-signature" ? await generateKeyPair(algorithm) : keys;
const publicKey = { ...await exportJWK(keys.publicKey), kid: "synthetic", alg: algorithm };
let probes = 0;
let nonce;
let codeChallenge;
let tokenExchanged = false;
process.stdin.resume = () => { process.nextTick(() => process.stdin.emit("data", Buffer.from("123456\\n"))); return process.stdin; };
process.stdin.pause = () => process.stdin;
globalThis.fetch = async (url, init = {}) => {
	if (tokenExchanged && scenario !== "replay-500") { console.error("MOCK_AFTER_TOKEN"); process.exit(77); }
	if (url.endsWith("/.well-known/openid-configuration")) return Response.json({
		issuer: "https://id-staging.hapiinc.com", grant_types_supported: ["authorization_code"],
		jwks_uri: "https://id-staging.hapiinc.com/jwks", userinfo_endpoint: "https://id-staging.hapiinc.com/userinfo"
	});
	if (url.endsWith("/jwks")) return Response.json({ keys: [
		scenario === "replay-500" && url.startsWith("https://identity.bookwrm.com") ? { ...publicKey, kid: "other" } : publicKey
	] });
	if (url.endsWith("/v1/registration/complete")) {
		probes++;
		return Response.json({ error: "INVALID_EVIDENCE" }, { status: probes === 1 ? 400 : 401 });
	}
	if (url.endsWith("/v1/authentication/email/start")) return Response.json({ challengeId: "challenge", expiresIn: 600 });
	if (url.endsWith("/v1/authentication/email/verify")) return Response.json({ authenticationResult: "synthetic-result", subject: "subject", expiresIn: 60 });
	if (url.endsWith("/authorize")) {
		const request = JSON.parse(init.body);
		if (nonce) return Response.json({}, { status: scenario === "replay-500" ? 500 : 400 });
		nonce = request.nonce;
		if (request.code_challenge_method !== "S256") throw new Error("PKCE S256 not requested");
		codeChallenge = request.code_challenge;
		return Response.json({ redirectUri: "https://staging-app.hapiinc.com/callback?code=synthetic-code&state=" + request.state });
	}
	if (url.endsWith("/token")) {
		if (tokenExchanged) return Response.json({ error: "invalid_grant" }, { status: 400 });
		const verifier = new URLSearchParams(init.body).get("code_verifier");
		if (!verifier || crypto.createHash("sha256").update(verifier).digest("base64url") !== codeChallenge) throw new Error("PKCE verifier mismatch");
		const now = Math.floor(Date.now() / 1000);
		const claims = {
			iss: scenario === "bad-token-issuer" ? "https://unexpected.invalid" : "https://id-staging.hapiinc.com",
			aud: scenario === "bad-audience" ? "other-client" : "staging-web",
			sub: scenario === "bad-subject" ? "other-subject" : "subject",
			nonce: scenario === "bad-nonce" ? "wrong" : nonce,
			iat: scenario === "future-iat" ? now + 120 : now,
			exp: scenario === "expired" ? now - 1 : now + 300
		};
		if (scenario === "missing-exp") delete claims.exp;
		if (scenario === "missing-iat") delete claims.iat;
		if (scenario === "missing-nonce") delete claims.nonce;
		const idToken = await new SignJWT(claims).setProtectedHeader({ alg: algorithm, kid: "synthetic" }).sign(signingKeys.privateKey);
		tokenExchanged = true;
		return Response.json({ access_token: "synthetic-access-token", id_token: idToken });
	}
	if (url.endsWith("/userinfo")) {
		return init.headers.authorization === "Bearer not-a-real-token"
			? Response.json({}, { status: 401 })
			: Response.json({ sub: "subject", email: "test@example.invalid" });
	}
	throw new Error("Unexpected request");
};`;

function runTokenFlow(scenario: string) {
	const preload = `data:text/javascript;base64,${Buffer.from(mockTokenFlow).toString("base64")}`;
	return spawnSync(process.execPath, ["--import", preload, "scripts/stage3-email-auth-test.mjs",
		"--staging-live-approved", ...(scenario === "replay-500" ? [] : ["--negative-verifier"])], {
		encoding: "utf8", timeout: 20000,
		env: { ...process.env, STAGING_WEB_CLIENT_SECRET: "x".repeat(32), STAGING_TEST_EMAIL: "test@example.invalid",
			STAGING_ISSUER: "https://id-staging.hapiinc.com", STAGING_CLIENT_ID: "staging-web",
			STAGING_REDIRECT_URI: "https://staging-app.hapiinc.com/callback", TEST_SCENARIO: scenario }
	});
}

describe("Stage 3 ID-token validation", () => {
	it.each(["bad-signature", "bad-token-issuer", "bad-audience", "bad-algorithm", "bad-nonce", "bad-subject",
		"expired", "future-iat", "missing-exp", "missing-iat", "missing-nonce"])(
		"stops all later requests for %s", scenario => {
			const result = runTokenFlow(scenario);
			expect(result.stdout).toContain("token.exchange");
			expect(result.status).toBe(1);
			expect(result.stderr).not.toContain("MOCK_AFTER_TOKEN");
			expect(result.stdout + result.stderr).not.toContain("synthetic-access-token");
			expect(result.stdout + result.stderr).not.toContain("synthetic-code");
			expect(result.stdout + result.stderr).not.toContain("123456");
		}
	);

	it("continues to the mocked UserInfo request with a valid ID token", () => {
		const result = runTokenFlow("valid");
		expect(result.status).toBe(77);
		expect(result.stdout).toContain("[PASS] negative.result-replay — replayed authentication_result -> HTTP 400");
		expect(result.stderr).toContain("MOCK_AFTER_TOKEN");
	});

	it("fails the report when authentication-result replay returns HTTP 500", () => {
		const result = runTokenFlow("replay-500");
		expect(result.status).toBe(1);
		expect(result.stdout).toContain("[FAIL] negative.result-replay — replayed authentication_result -> HTTP 500");
		expect(result.stdout).toMatch(/Summary: \d+ pass, 1 fail,/);
	});
});