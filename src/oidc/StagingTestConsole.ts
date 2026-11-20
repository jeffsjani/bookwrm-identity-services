import { createHash, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { renderHapiPage, csrfField } from "../presentation/HapiPagePresentation.js";
import { constantTimeStringEqual } from "../security/ServiceAuthentication.js";
import { getRedisClient, oidcRedisKey, type RedisClient } from "./infrastructure/RedisInfrastructure.js";
import { stagingConsoleInternalHeaders } from "./StagingConsoleInternal.js";

export const STAGING_ISSUER = "https://id-staging.hapiinc.com";
export const STAGING_CONSOLE_CALLBACK = `${STAGING_ISSUER}/staging-console/callback`;
const CLIENT = "staging-web";
const EMAIL = "jeff@hapiinc.com";
const COOKIE = "__Host-hapi_staging_test";
const TTL = 600_000;
const HANDLE = /^[A-Za-z0-9_-]{43}$/;
const random = () => randomBytes(32).toString("base64url");
const hash = (value: string) => createHash("sha256").update(value).digest("base64url");

type Flow = { csrf: string; state: string; nonce: string; verifier: string };
type Result = { name: string; passed: boolean };
type Options = {
	issuer: string;
	env: NodeJS.ProcessEnv;
	redis?: RedisClient;
};

function cookie(request: FastifyRequest): string | undefined {
	const value = request.headers.cookie?.split(";").map(part => part.trim())
		.find(part => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
	return value && HANDLE.test(value) ? value : undefined;
}

function page(reply: FastifyReply, status: number, title: string, body: string, referrerPolicy = "no-referrer") {
	const rendered = renderHapiPage({ title, heading: title, body, formActionSelf: true });
	return reply.code(status).header("Cache-Control", "no-store")
		.header("Referrer-Policy", referrerPolicy).header("X-Frame-Options", "DENY")
		.header("Content-Security-Policy", rendered.contentSecurityPolicy)
		.type("text/html; charset=utf-8").send(rendered.html);
}

export function validStagingConsoleProxy(value: string): boolean {
	const parts = value.split("/");
	const version = isIP(parts[0]);
	if (!version || parts.length > 2) return false;
	if (parts.length === 1) return true;
	if (!/^\d+$/.test(parts[1])) return false;
	const bits = Number(parts[1]);
	return bits > 0 && bits <= (version === 4 ? 32 : 128);
}

export async function registerStagingTestConsole(app: FastifyInstance, options: Options): Promise<void> {
	const { issuer, env } = options;
	if (env.STAGING_TEST_CONSOLE_ENABLED !== "true" || issuer !== STAGING_ISSUER) return;
	const username = env.STAGING_TEST_CONSOLE_USERNAME;
	const password = env.STAGING_TEST_CONSOLE_PASSWORD;
	const secret = env.STAGING_WEB_CLIENT_SECRET;
	if (!username || username.includes(":") || !password || password.length < 32 || !secret || secret.length < 32 ||
		password === secret || password === env.HAPI_PLATFORM_SERVICE_KEY || password === env.JWT_PRIVATE_KEY) {
		throw new Error("Staging console requires an independent operator credential and staging client secret");
	}
	if (env.HAPI_EMAIL_AUTHENTICATION_ENABLED !== "true" || env.HAPI_UNIVERSAL_LOGIN_ENABLED !== "true" ||
		env.HAPI_EMAIL_PROVIDER !== "resend" ||
		["HAPI_APPLE_FEDERATION_ENABLED", "HAPI_GOOGLE_FEDERATION_ENABLED", "HAPI_REFRESH_GRANT_ENABLED",
			"HAPI_PERSISTENT_SESSIONS_ENABLED"].some(flag => env[flag] !== undefined && env[flag] !== "false")) {
		throw new Error("Staging console requires email and Universal Login only; federation, refresh and persistent sessions must be off");
	}
	const redis = options.redis ?? getRedisClient();
	const key = (handle: string, suffix: string) => oidcRedisKey(`staging_console:${hash(handle)}:${suffix}`);
	const authenticate = async (request: FastifyRequest, reply: FastifyReply) => {
		reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer");
		if (request.protocol !== "https" || request.hostname !== new URL(STAGING_ISSUER).host) {
			return reply.code(404).send({ error: "not_found" });
		}
		const peer = request.socket.remoteAddress;
		if (!peer) throw new Error("Staging console proxy address unavailable");
		const bucket = oidcRedisKey(`staging_console:rate:${hash(peer)}`);
		const count = await redis.incr(bucket);
		if (count === 1) await redis.expire(bucket, 60);
		if (count > 120) return reply.code(429).send({ error: "too_many_requests" });
		const header = request.headers.authorization;
		const match = typeof header === "string" ? /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(header) : null;
		const decoded = match ? Buffer.from(match[1], "base64").toString("utf8") : "";
		const separator = decoded.indexOf(":");
		const valid = separator >= 0 && constantTimeStringEqual(decoded.slice(0, separator), username) &&
			constantTimeStringEqual(decoded.slice(separator + 1), password);
		if (!valid) return reply.code(401).header("WWW-Authenticate", 'Basic realm="HAPI staging test", charset="UTF-8"')
			.send({ error: "unauthorized" });
	};
	const errorHandler = (_error: Error, request: FastifyRequest, reply: FastifyReply) => {
		request.log.error({ event: "STAGING_CONSOLE_ERROR" }, "Staging console request failed");
		return page(reply, 503, "Test unavailable", "<p>The test could not be completed. Start again.</p>");
	};
	const route = { onRequest: authenticate, errorHandler };

	app.get("/staging-console/", route, async (_request, reply) => {
		const handle = random();
		const flow: Flow = { csrf: random(), state: random(), nonce: random(), verifier: random() };
		const saved = await redis.set(key(handle, "flow"), JSON.stringify(flow), "PX", TTL, "NX");
		if (saved !== "OK") throw new Error("Unable to create staging test");
		reply.header("Set-Cookie", `${COOKIE}=${handle}; Path=/; Max-Age=${TTL / 1000}; HttpOnly; Secure; SameSite=Lax`);
		return page(reply, 200, "HAPI ID Staging Test",
			`<p>Sign in or register with ${EMAIL}. The verification code will be sent to that mailbox.</p>` +
			`<form method="post" action="/staging-console/start">${csrfField(flow.csrf)}<button type="submit">Start test</button></form>`, "same-origin");
	});

	app.post("/staging-console/start", { ...route, bodyLimit: 1024 }, async (request, reply) => {
		const handle = cookie(request);
		const body = request.body as { csrf?: unknown } | undefined;
		const raw = handle ? await redis.get(key(handle, "flow")) : null;
		if (!handle || !raw || request.headers.origin !== STAGING_ISSUER || typeof body?.csrf !== "string") {
			return page(reply, 400, "Test expired", "<p>Return to the test console and start again.</p>");
		}
		const flow = JSON.parse(raw) as Flow;
		if (!constantTimeStringEqual(flow.csrf, body.csrf) ||
			await redis.set(key(handle, "started"), "1", "PX", TTL, "NX") !== "OK") {
			return page(reply, 400, "Test expired", "<p>Return to the test console and start again.</p>");
		}
		const query = new URLSearchParams({
			client_id: CLIENT, redirect_uri: STAGING_CONSOLE_CALLBACK, response_type: "code",
			scope: "openid profile email", state: flow.state, nonce: flow.nonce,
			code_challenge: hash(flow.verifier), code_challenge_method: "S256"
		});
		return reply.redirect(`${STAGING_ISSUER}/authorize?${query}`, 303);
	});

	app.get("/staging-console/callback", route, async (request, reply) => {
		const handle = cookie(request);
		const query = request.query as { state?: unknown; code?: unknown; error?: unknown };
		const raw = handle ? await redis.get(key(handle, "flow")) : null;
		if (!handle || !raw || query.error !== undefined || typeof query.state !== "string" || typeof query.code !== "string" ||
			!query.code || !await redis.get(key(handle, "started"))) {
			return page(reply, 400, "Test failed", "<p>Invalid or expired callback. Start again.</p>");
		}
		const flow = JSON.parse(raw) as Flow;
		if (!constantTimeStringEqual(flow.state, query.state) ||
			await redis.set(key(handle, "consumed"), "1", "PX", TTL, "NX") !== "OK") {
			return page(reply, 400, "Test failed", "<p>Invalid or expired callback. Start again.</p>");
		}
		await redis.del(key(handle, "flow"));
		const results: Result[] = [{ name: "Authorization and state", passed: true }];
		try {
			const basic = Buffer.from(`${encodeURIComponent(CLIENT)}:${encodeURIComponent(secret)}`).toString("base64");
			const token = await app.inject({
				method: "POST", url: "/token",
				headers: { ...stagingConsoleInternalHeaders(), authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({ grant_type: "authorization_code", code: query.code,
					redirect_uri: STAGING_CONSOLE_CALLBACK, code_verifier: flow.verifier }).toString()
			});
			const tokens: { id_token?: unknown; access_token?: unknown; refresh_token?: unknown } = token.json();
			const exchanged = token.statusCode === 200 && typeof tokens.id_token === "string" &&
				typeof tokens.access_token === "string" && !tokens.refresh_token;
			results.push({ name: "Authorization code exchange with PKCE S256", passed: exchanged });
			if (!exchanged) request.log.warn({ event: "STAGING_CONSOLE_TOKEN_FAILED" }, "Staging console token exchange failed");
			if (exchanged && typeof tokens.id_token === "string" && typeof tokens.access_token === "string") {
				const jwksResponse = await app.inject({ method: "GET", url: "/jwks", headers: stagingConsoleInternalHeaders() });
				if (jwksResponse.statusCode !== 200) throw new Error("JWKS unavailable");
				const jwks = jwksResponse.json() as JSONWebKeySet;
				let subject: string | undefined;
				try {
					const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
						issuer: STAGING_ISSUER, audience: CLIENT, algorithms: ["RS256"],
						requiredClaims: ["sub", "exp", "iat", "nonce"]
					});
					if (payload.nonce !== flow.nonce || payload.aud !== CLIENT || typeof payload.sub !== "string" ||
						typeof payload.iat !== "number" || payload.iat > Math.floor(Date.now() / 1000) + 60) {
						throw new Error("Invalid ID token claims");
					}
					subject = payload.sub;
					results.push({ name: "Signed ID token, issuer, audience, nonce and expiration", passed: true });
				} catch {
					results.push({ name: "Signed ID token, issuer, audience, nonce and expiration", passed: false });
					request.log.warn({ event: "STAGING_CONSOLE_ID_TOKEN_FAILED" }, "Staging console ID token validation failed");
				}
				if (subject) {
					const response = await app.inject({ method: "GET", url: "/userinfo",
						headers: { ...stagingConsoleInternalHeaders(), authorization: `Bearer ${tokens.access_token}` } });
					const info: { sub?: unknown; email?: unknown; email_verified?: unknown } = response.json();
					const matched = response.statusCode === 200 && info.sub === subject && info.email === EMAIL && info.email_verified === true;
					results.push({ name: "UserInfo matches the test mailbox", passed: matched });
					if (!matched) request.log.warn({ event: "STAGING_CONSOLE_USERINFO_FAILED" }, "Staging console UserInfo verification failed");
				}
			}
		} catch {
			results.push({ name: "OIDC verification", passed: false });
			request.log.error({ event: "STAGING_CONSOLE_VERIFICATION_FAILED" }, "Staging console verification failed");
		}
		await redis.set(key(handle, "results"), JSON.stringify(results), "PX", TTL);
		return reply.redirect("/staging-console/results", 303);
	});

	app.get("/staging-console/results", route, async (request, reply) => {
		const handle = cookie(request);
		const raw = handle ? await redis.get(key(handle, "results")) : null;
		if (!raw) return page(reply, 400, "Test expired", "<p>Return to the test console and start again.</p>");
		const results = JSON.parse(raw) as Result[];
		const rows = results.map(result => `<li>${result.passed ? "PASS" : "FAIL"}: ${result.name}</li>`).join("");
		return page(reply, 200, results.every(result => result.passed) ? "Test passed" : "Test failed",
			`<ul>${rows}</ul><p><a href="/staging-console/">Start another test</a></p>`);
	});
}
