import { createHash, generateKeyPairSync } from "node:crypto";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { exportJWK, importPKCS8, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { registerStagingTestConsole, STAGING_CONSOLE_CALLBACK, STAGING_ISSUER } from "../src/oidc/StagingTestConsole.js";
import { requestLogPath } from "../src/security/RequestLogging.js";
import { registerStagingConsoleCallbackAtBoot, STAGING_WEB_ORIGINAL_CALLBACK } from "../src/identity/StagingConsoleClientRegistration.js";
import { getRedisClient, oidcRedisKey } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import type { PostgresClient, TransactionRunner } from "../src/identity/infrastructure/PostgresInfrastructure.js";

const password = "operator-password-".padEnd(40, "x");
const secret = "oauth-secret-".padEnd(40, "y");
const env = { STAGING_TEST_CONSOLE_ENABLED: "true", STAGING_TEST_CONSOLE_USERNAME: "operator",
	STAGING_TEST_CONSOLE_PASSWORD: password, STAGING_WEB_CLIENT_SECRET: secret,
	HAPI_EMAIL_PROVIDER: "resend", HAPI_EMAIL_AUTHENTICATION_ENABLED: "true", HAPI_UNIVERSAL_LOGIN_ENABLED: "true" };
const authorization = "Basic " + Buffer.from(`operator:${password}`).toString("base64");
const headers = { host: "id-staging.hapiinc.com", "x-forwarded-proto": "https", authorization };

async function fixture(scenario = "valid", issuer = STAGING_ISSUER, config: NodeJS.ProcessEnv = env) {
	const app = Fastify({ trustProxy: false });
	await app.register(formbody);
	const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const privateKey = await importPKCS8(pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "RS256");
	const jwk = { ...await exportJWK(pair.publicKey), kid: "test", alg: "RS256" };
	let nonce = "";
	let challenge = "";
	let tokenCalls = 0;
	let jwksCalls = 0;
	let userinfoCalls = 0;
	app.post("/token", async (request, reply) => {
		tokenCalls++;
		const body = request.body as Record<string, string>;
		const expected = createHash("sha256").update(body.code_verifier).digest("base64url");
		if (scenario === "bad-pkce" || expected !== challenge) return reply.code(400).send({ error: "invalid_grant" });
		const idToken = await new SignJWT({ nonce: scenario === "bad-nonce" ? "wrong" : nonce })
			.setProtectedHeader({ alg: "RS256", kid: "test" }).setIssuer(scenario === "bad-issuer" ? "https://identity.bookwrm.com" : STAGING_ISSUER)
			.setAudience(scenario === "bad-audience" ? "other-client" : "staging-web").setSubject("test-subject").setIssuedAt()
			.setExpirationTime(scenario === "expired" ? "1 second ago" : "5 minutes").sign(privateKey);
		return { access_token: "test-access-token", id_token: scenario === "bad-signature" ? idToken + "bad" : idToken };
	});
	app.get("/jwks", async () => { jwksCalls++; return { keys: [jwk] }; });
	app.get("/userinfo", async () => { userinfoCalls++; return { sub: scenario === "bad-userinfo" ? "other-subject" : "test-subject",
		email: "jeff@hapiinc.com", email_verified: true }; });
	await registerStagingTestConsole(app, { issuer, env: config });
	await app.ready();
	async function start() {
		const index = await app.inject({ method: "GET", url: "/staging-console/", headers });
		const cookie = String(index.headers["set-cookie"]).split(";")[0];
		const csrf = /name="csrf" value="([^"]+)"/.exec(index.body)?.[1];
		expect(csrf).toBeTruthy();
		const response = await app.inject({ method: "POST", url: "/staging-console/start",
			headers: { ...headers, cookie, origin: STAGING_ISSUER, "content-type": "application/x-www-form-urlencoded" },
			payload: new URLSearchParams({ csrf: csrf! }).toString() });
		expect(response.statusCode).toBe(303);
		const url = new URL(String(response.headers.location));
		nonce = url.searchParams.get("nonce")!;
		challenge = url.searchParams.get("code_challenge")!;
		return { cookie, state: url.searchParams.get("state")!, csrf };
	}
	return { app, start, tokenCalls: () => tokenCalls, jwksCalls: () => jwksCalls, userinfoCalls: () => userinfoCalls };
}

describe("staging test console", () => {
	it("requires operator credentials on every endpoint regardless of forwarding headers", async () => {
		const f = await fixture();
		try {
			for (const url of ["/staging-console/", "/staging-console/callback", "/staging-console/results"]) {
				expect((await f.app.inject({ method: "GET", url, headers: { ...headers, authorization: "" } })).statusCode).toBe(401);
				expect((await f.app.inject({ method: "GET", url, headers: { ...headers, authorization: "Basic " + Buffer.from("operator:wrong").toString("base64") } })).statusCode).toBe(401);
			}
			expect((await f.app.inject({ method: "POST", url: "/staging-console/start", headers: { ...headers, authorization: "" } })).statusCode).toBe(401);
			expect((await f.app.inject({ method: "POST", url: "/staging-console/start",
				headers: { ...headers, authorization: "Basic " + Buffer.from("operator:wrong").toString("base64") } })).statusCode).toBe(401);
			expect((await f.app.inject({ method: "GET", url: "/staging-console/", headers })).statusCode).toBe(200);
		} finally { await f.app.close(); }
	});

	it("uses the actual Host and operator credentials, not forwarded headers or peer trust", async () => {
		const f = await fixture();
		try {
			const forwardedHeaders = await f.app.inject({ method: "GET", url: "/staging-console/",
				remoteAddress: "203.0.113.5",
				headers: { ...headers, "x-forwarded-proto": "http", "x-forwarded-host": "attacker.invalid",
					"x-forwarded-for": "203.0.113.1" } });
			expect(forwardedHeaders.statusCode).toBe(200);

			const forgedHost = await f.app.inject({ method: "GET", url: "/staging-console/",
				headers: { ...headers, host: "attacker.invalid", "x-forwarded-host": "id-staging.hapiinc.com" } });
			expect(forgedHost.statusCode).toBe(404);

			const privatePeerWithoutCredentials = await f.app.inject({ method: "GET", url: "/staging-console/",
				remoteAddress: "10.0.0.8", headers: { host: "id-staging.hapiinc.com", "x-forwarded-proto": "https",
					"x-forwarded-host": "id-staging.hapiinc.com", "x-forwarded-for": "198.51.100.10" } });
			expect(privatePeerWithoutCredentials.statusCode).toBe(401);

			const privatePeerWithCredentialsButNoSession = await f.app.inject({ method: "GET",
				url: "/staging-console/callback?code=forged&state=forged", remoteAddress: "10.0.0.8",
				headers: { ...headers, "x-forwarded-proto": "https", "x-forwarded-host": "id-staging.hapiinc.com",
					"x-forwarded-for": "198.51.100.10", cookie: `__Host-hapi_staging_test=${"A".repeat(43)}` } });
			expect(privatePeerWithCredentialsButNoSession.statusCode).toBe(400);
			expect(f.tokenCalls()).toBe(0);
		} finally { await f.app.close(); }
	});

	it("does not allow a forged forwarded address to bypass the operator rate limit", async () => {
		const f = await fixture();
		const bucket = oidcRedisKey(`staging_console:rate:${createHash("sha256").update("127.0.0.1").digest("base64url")}`);
		try {
			await getRedisClient().del(bucket);
			for (let i = 0; i < 120; i++) {
				const response = await f.app.inject({ method: "GET", url: "/staging-console/",
					headers: { ...headers, authorization: "", "x-forwarded-for": `192.0.2.${i}` } });
				expect(response.statusCode).toBe(401);
			}
			const response = await f.app.inject({ method: "GET", url: "/staging-console/",
				headers: { ...headers, "x-forwarded-for": "203.0.113.1" } });
			expect(response.statusCode).toBe(429);
		} finally { await getRedisClient().del(bucket); await f.app.close(); }
	});

	it("is off by default and cannot register against production", async () => {
		for (const [issuer, config] of [[STAGING_ISSUER, {}], ["https://identity.bookwrm.com", env]] as const) {
			const f = await fixture("valid", issuer, config);
			expect((await f.app.inject({ method: "GET", url: "/staging-console/", headers })).statusCode).toBe(404);
			await f.app.close();
		}
	});

	it("refuses to enable without the approved email-only feature configuration", async () => {
		for (const overrides of [
			{ HAPI_UNIVERSAL_LOGIN_ENABLED: "false" }, { HAPI_EMAIL_AUTHENTICATION_ENABLED: "false" },
			{ HAPI_APPLE_FEDERATION_ENABLED: "true" }, { HAPI_GOOGLE_FEDERATION_ENABLED: "true" },
			{ HAPI_REFRESH_GRANT_ENABLED: "true" }, { HAPI_PERSISTENT_SESSIONS_ENABLED: "true" }
		]) {
			await expect(fixture("valid", STAGING_ISSUER, { ...env, ...overrides })).rejects.toThrow(/email and Universal Login only/);
		}
	});

	it("requires an independent strong operator credential", async () => {
		for (const operatorPassword of [undefined, "short", secret]) {
			await expect(fixture("valid", STAGING_ISSUER, { ...env, STAGING_TEST_CONSOLE_PASSWORD: operatorPassword }))
				.rejects.toThrow(/independent operator credential/);
		}
	});

	it("rejects invalid CSRF, origin and state, and permits only one callback", async () => {
		const f = await fixture();
		try {
			const index = await f.app.inject({ method: "GET", url: "/staging-console/", headers });
			const initialCookie = String(index.headers["set-cookie"]).split(";")[0];
			const csrf = /name="csrf" value="([^"]+)"/.exec(index.body)![1];
			for (const [origin, value] of [[STAGING_ISSUER, "bad"], ["https://attacker.invalid", csrf]]) {
				const response = await f.app.inject({ method: "POST", url: "/staging-console/start",
					headers: { ...headers, cookie: initialCookie, origin, "content-type": "application/x-www-form-urlencoded" },
					payload: new URLSearchParams({ csrf: value }).toString() });
				expect(response.statusCode).toBe(400);
			}
			const { cookie, state } = await f.start();
			const badState = await f.app.inject({ method: "GET", url: "/staging-console/callback?code=secret-code&state=wrong",
				headers: { ...headers, cookie } });
			expect(badState.statusCode).toBe(400);
			const errorCallback = await f.app.inject({ method: "GET", url: `/staging-console/callback?code=secret-code&state=${state}&error=access_denied`,
				headers: { ...headers, cookie } });
			expect(errorCallback.statusCode).toBe(400);
			expect(f.tokenCalls()).toBe(0);
			const callback = `/staging-console/callback?code=secret-code&state=${state}`;
			const attempts = await Promise.all(Array.from({ length: 2 }, () =>
				f.app.inject({ method: "GET", url: callback, headers: { ...headers, cookie } })));
			expect(attempts.map(response => response.statusCode).sort()).toEqual([303, 400]);
			expect(f.tokenCalls()).toBe(1);
		} finally { await f.app.close(); }
	});

	it.each(["bad-pkce", "bad-nonce", "bad-signature", "bad-issuer", "bad-audience", "expired", "bad-userinfo"])("reports %s as FAIL without exposing tokens", async scenario => {
		const f = await fixture(scenario);
		try {
			const { cookie, state } = await f.start();
			const callback = await f.app.inject({ method: "GET", url: `/staging-console/callback?code=secret-code&state=${state}`,
				headers: { ...headers, cookie } });
			expect(callback.statusCode).toBe(303);
			const results = await f.app.inject({ method: "GET", url: "/staging-console/results", headers: { ...headers, cookie } });
			expect(results.body).toContain("Test failed");
			expect(results.body).toContain("FAIL:");
			for (const value of ["secret-code", "test-access-token", secret, password]) expect(results.body).not.toContain(value);
			if (scenario === "bad-pkce") expect(f.jwksCalls()).toBe(0);
			if (scenario !== "bad-userinfo") expect(f.userinfoCalls()).toBe(0);
		} finally { await f.app.close(); }
	});

	it("expires the pending state and PKCE session after ten minutes", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const f = await fixture();
		try {
			const { cookie, state } = await f.start();
			vi.setSystemTime(Date.now() + 600_001);
			const response = await f.app.inject({ method: "GET", url: `/staging-console/callback?code=secret-code&state=${state}`,
				headers: { ...headers, cookie } });
			expect(response.statusCode).toBe(400);
			expect(f.tokenCalls()).toBe(0);
		} finally { await f.app.close(); vi.useRealTimers(); }
	});

	it("expires completed results after ten minutes", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const f = await fixture();
		try {
			const { cookie, state } = await f.start();
			expect((await f.app.inject({ method: "GET", url: `/staging-console/callback?code=secret-code&state=${state}`,
				headers: { ...headers, cookie } })).statusCode).toBe(303);
			vi.setSystemTime(Date.now() + 600_001);
			expect((await f.app.inject({ method: "GET", url: "/staging-console/results", headers: { ...headers, cookie } })).statusCode).toBe(400);
		} finally { await f.app.close(); vi.useRealTimers(); }
	});

	it("redacts all queries from incoming request logs", () => {
		expect(requestLogPath("/staging-console/callback?code=secret&state=value")).toBe("/staging-console/callback");
		expect(requestLogPath(`/authorize?redirect_uri=${encodeURIComponent(STAGING_CONSOLE_CALLBACK)}&state=secret`)).toBe("/authorize");
		expect(requestLogPath("/authorize?client_id=client")).toBe("/authorize");
		expect(requestLogPath("/other?token=secret")).toBe("/other");
		expect(requestLogPath("/health")).toBe("/health");
	});

});

describe("staging callback registration", () => {
	it("is off by default and refuses production without touching the database", async () => {
		const run = vi.fn<TransactionRunner>();
		expect(await registerStagingConsoleCallbackAtBoot({ env: {}, runTransaction: run })).toBe("disabled");
		await expect(registerStagingConsoleCallbackAtBoot({ env: { STAGING_TEST_CONSOLE_REGISTER_CALLBACK: "true" },
			issuer: "https://identity.bookwrm.com", driver: "postgres", runTransaction: run })).rejects.toThrow();
		expect(run).not.toHaveBeenCalled();
	});

	it("appends only the new callback and remains idempotent", async () => {
		let uris = [STAGING_WEB_ORIGINAL_CALLBACK];
		const client: PostgresClient = {
			async query(text, values) {
				if (text.includes("<> ALL")) return { rows: [] };
				if (text.includes("client_id = 'staging-native'")) return { rows: [{ application_id: "app",
					token_endpoint_auth_method: "none", status: "active" }] };
				if (text.startsWith("UPDATE")) {
					uris = values![0] as string[];
					return { rows: [{ client_id: "staging-web" }] };
				}
				return { rows: [{ application_id: "app", status: "active", token_endpoint_auth_method: "client_secret_basic",
					require_pkce: true, redirect_uris: uris, grant_types: ["authorization_code"] }] };
			}
		};
		const run: TransactionRunner = async fn => fn(client);
		const deps = { env: { STAGING_TEST_CONSOLE_REGISTER_CALLBACK: "true" }, issuer: STAGING_ISSUER, driver: "postgres", runTransaction: run };
		expect(await registerStagingConsoleCallbackAtBoot(deps)).toBe("registered");
		expect(uris).toEqual([STAGING_WEB_ORIGINAL_CALLBACK, STAGING_CONSOLE_CALLBACK]);
		expect(await registerStagingConsoleCallbackAtBoot(deps)).toBe("unchanged");
		uris = [STAGING_WEB_ORIGINAL_CALLBACK, "https://attacker.invalid/callback"];
		await expect(registerStagingConsoleCallbackAtBoot(deps)).rejects.toThrow(/refused/);
	});
});
