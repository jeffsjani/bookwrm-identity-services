import { describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { readFileSync } from "node:fs";
import { createPrivateOIDCCertificationApp, verifyCertificationIdToken } from "../src/certification/PrivateOIDCCertificationClient.js";

const redirectUri = "https://certification.hapiinc.com/oidc-certification/callback";
const clientSecret = "independent-pilot-client-secret-at-least-32-characters";
const operatorPassword = "independent-operator-password-at-least-32-characters";

function env() {
	return {
		HAPI_CERTIFICATION_CLIENT_ID: "hapi-pilot-certification",
		HAPI_CERTIFICATION_CLIENT_SECRET: clientSecret,
		HAPI_CERTIFICATION_REDIRECT_URI: redirectUri,
		HAPI_CERTIFICATION_OPERATOR_USERNAME: "operator",
		HAPI_CERTIFICATION_OPERATOR_PASSWORD: operatorPassword
	};
}

function basic() {
	return `Basic ${Buffer.from(`operator:${operatorPassword}`).toString("base64")}`;
}

describe("private OIDC certification client", () => {
	it("certification module imports no main backend configuration", () => {
		const source = readFileSync(new URL("../src/certification/PrivateOIDCCertificationClient.ts", import.meta.url), "utf8");
		expect(source).not.toContain("ConfigurationService");
		expect(source).not.toContain("DATABASE_URL");
		expect(source).not.toContain("REDIS_URL");
		expect(source).not.toContain("JWT_PRIVATE_KEY");
		expect(source).not.toContain("PRIVATEID");
	});

	it("serves a secret-free liveness response without operator authentication", async () => {
		const app = await createPrivateOIDCCertificationApp({ env: env() });
		const response = await app.inject({ method: "GET", url: "/health/live" });
		expect(response.statusCode).toBe(200);
		expect(response.json()).toEqual({ status: "ok" });
		expect(response.payload).not.toContain(clientSecret);
		expect(response.payload).not.toContain("token");
		await app.close();
	});

	it("requires operator authentication before starting", async () => {
		const app = await createPrivateOIDCCertificationApp({ env: env() });
		const response = await app.inject({ method: "GET", url: "/oidc-certification" });
		expect(response.statusCode).toBe(401);
		await app.close();
	});

	it("returns four PASS results without exposing tokens or secrets", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS256");
		const jwk = await exportJWK(publicKey);
		jwk.kid = "cert-test-key";
		jwk.alg = "RS256";
		jwk.use = "sig";

		let nonce = "";
		const app = await createPrivateOIDCCertificationApp({
			env: env(),
			fetch: vi.fn(async (input, init) => {
				const url = String(input);
				if (url.endsWith("/jwks")) {
					return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "content-type": "application/json" } });
				}
				if (url.endsWith("/userinfo")) {
					return new Response(JSON.stringify({ sub: "cert-subject" }), { status: 200, headers: { "content-type": "application/json" } });
				}
				if (url.endsWith("/token")) {
					const body = String(init?.body ?? "");
					const params = new URLSearchParams(body);
					const verify = nonce;
					const idToken = await new SignJWT({ nonce: verify, sub: "cert-subject", amr: ["email"] })
						.setProtectedHeader({ alg: "RS256", kid: "cert-test-key" })
						.setIssuer("https://id.hapiinc.com")
						.setAudience("hapi-pilot-certification")
						.setSubject("cert-subject")
						.setIssuedAt()
						.setExpirationTime("5m")
						.sign(privateKey);
					expect(params.get("grant_type")).toBe("authorization_code");
					expect(params.get("code_verifier")).toBeTruthy();
					expect(params.has("refresh_token")).toBe(false);
					return new Response(JSON.stringify({ access_token: "never-rendered", id_token: idToken }),
						{ status: 200, headers: { "content-type": "application/json" } });
				}
				return new Response("{}", { status: 404 });
			}) as typeof fetch
		});

		const root = await app.inject({ method: "GET", url: "/oidc-certification", headers: { authorization: basic() } });
		const cookie = root.headers["set-cookie"] as string;
		const handleCookie = cookie.split(";")[0];
		const csrf = root.payload.match(/name="csrf" value="([^"]+)"/)?.[1] as string;
		const start = await app.inject({ method: "POST", url: "/oidc-certification/start",
			headers: { authorization: basic(), cookie: handleCookie, origin: "https://certification.hapiinc.com", "content-type": "application/x-www-form-urlencoded" },
			payload: new URLSearchParams({ csrf }).toString() });
		expect(start.statusCode).toBe(303);
		const location = new URL(start.headers.location as string);
		const state = location.searchParams.get("state") as string;
		nonce = location.searchParams.get("nonce") as string;
		expect(location.searchParams.get("code_challenge_method")).toBe("S256");

		const callback = await app.inject({
			method: "GET",
			url: `/oidc-certification/callback?state=${encodeURIComponent(state)}&code=one-time-code`,
			headers: { authorization: basic(), cookie: handleCookie }
		});
		const text = callback.payload;
		expect(callback.statusCode).toBe(200);
		expect(text.match(/<strong>PASS<\/strong>/g)?.length).toBe(4);
		expect(text).not.toContain("never-rendered");
		expect(text).not.toContain(clientSecret);
		await app.close();
	});

	it("rejects an invalid start origin or missing CSRF", async () => {
		const app = await createPrivateOIDCCertificationApp({ env: env() });
		const root = await app.inject({ method: "GET", url: "/oidc-certification", headers: { authorization: basic() } });
		const handleCookie = (root.headers["set-cookie"] as string).split(";")[0];
		const csrf = root.payload.match(/name="csrf" value="([^"]+)"/)?.[1] as string;
		const wrongOrigin = await app.inject({ method: "POST", url: "/oidc-certification/start",
			headers: { authorization: basic(), cookie: handleCookie, origin: "https://evil.example", "content-type": "application/x-www-form-urlencoded" },
			payload: new URLSearchParams({ csrf }).toString() });
		const missingCsrf = await app.inject({ method: "POST", url: "/oidc-certification/start",
			headers: { authorization: basic(), cookie: handleCookie, origin: "https://certification.hapiinc.com", "content-type": "application/x-www-form-urlencoded" },
			payload: "" });
		expect(wrongOrigin.statusCode).toBe(403);
		expect(missingCsrf.statusCode).toBe(400);
		await app.close();
	});

	it("rejects an ID token with a mismatched nonce", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS256");
		const jwk = await exportJWK(publicKey);
		jwk.kid = "nonce-test-key";
		jwk.alg = "RS256";
		jwk.use = "sig";
		const idToken = await new SignJWT({ nonce: "wrong-nonce", sub: "cert-subject" })
			.setProtectedHeader({ alg: "RS256", kid: "nonce-test-key" })
			.setIssuer("https://id.hapiinc.com")
			.setAudience("hapi-pilot-certification")
			.setSubject("cert-subject")
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(privateKey);
		await expect(verifyCertificationIdToken(idToken, "expected-nonce", "hapi-pilot-certification",
			"https://id.hapiinc.com", { keys: [jwk] })).rejects.toThrow();
	});

	it("fails a mismatched callback state", async () => {
		const app = await createPrivateOIDCCertificationApp({ env: env() });
		const root = await app.inject({ method: "GET", url: "/oidc-certification", headers: { authorization: basic() } });
		const handleCookie = (root.headers["set-cookie"] as string).split(";")[0];
		const csrf = root.payload.match(/name="csrf" value="([^"]+)"/)?.[1] as string;
		await app.inject({ method: "POST", url: "/oidc-certification/start",
			headers: { authorization: basic(), cookie: handleCookie, origin: "https://certification.hapiinc.com", "content-type": "application/x-www-form-urlencoded" },
			payload: new URLSearchParams({ csrf }).toString() });
		const callback = await app.inject({
			method: "GET",
			url: "/oidc-certification/callback?state=wrong&code=code",
			headers: { authorization: basic(), cookie: handleCookie }
		});
		expect(callback.payload).toContain("FAIL");
		await app.close();
	});
});
