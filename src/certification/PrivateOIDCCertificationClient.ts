import { createHash, randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { createLocalJWKSet, jwtVerify } from "jose";
import { constantTimeStringEqual } from "../security/ServiceAuthentication.js";
import formbody from "@fastify/formbody";

export const PRIVATE_CERTIFICATION_ISSUER = "https://id.hapiinc.com";
export const PRIVATE_CERTIFICATION_CALLBACK_PATH = "/oidc-certification/callback";
export const PRIVATE_CERTIFICATION_CALLBACK_URI = `https://certification.hapiinc.com${PRIVATE_CERTIFICATION_CALLBACK_PATH}`;
export const PRIVATE_CERTIFICATION_CLIENT_ID = "hapi-pilot-certification";

const COOKIE = "__Host-hapi_oidc_certification";
const TTL_MS = 10 * 60 * 1000;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type CertificationResult = { name: string; passed: boolean };
export type CertificationOptions = {
	issuer?: string;
	env: NodeJS.ProcessEnv;
	fetch?: typeof fetch;
};

type Flow = {
	state: string;
	nonce: string;
	verifier: string;
	csrf: string;
	expiresAt: number;
	consumed: boolean;
	results?: CertificationResult[];
};

const random = () => randomBytes(32).toString("base64url");
const sha256 = (value: string) => createHash("sha256").update(value).digest("base64url");

function cookieHandle(request: FastifyRequest): string | undefined {
	const cookie = request.headers.cookie?.split(";").map(part => part.trim())
		.find(part => part.startsWith(`${COOKIE}=`));
	const handle = cookie?.slice(COOKIE.length + 1);
	return handle && HANDLE_PATTERN.test(handle) ? handle : undefined;
}

function escapeHtml(value: string): string {
	return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function page(reply: FastifyReply, status: number, title: string, body: string) {
	return reply.code(status).header("Cache-Control", "no-store")
		.header("Referrer-Policy", "no-referrer").header("X-Frame-Options", "DENY")
		.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		.type("text/html; charset=utf-8")
		.send(`<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`);
}

export async function verifyCertificationIdToken(idToken: string, nonce: string, audience: string,
	issuer: string, jwksJson: unknown): Promise<{ sub: string }> {
	const { payload } = await jwtVerify(idToken, (await import("jose")).createLocalJWKSet(jwksJson as never), {
		issuer,
		audience,
		algorithms: ["RS256"],
		requiredClaims: ["sub", "exp", "iat", "nonce", "aud"]
	});
	if (payload.nonce !== nonce || typeof payload.sub !== "string" || payload.sub.length === 0) {
		throw new Error("ID token nonce or subject is invalid");
	}
	if (typeof payload.iat !== "number" || payload.iat > Math.floor(Date.now() / 1000) + 60) {
		throw new Error("ID token issued-at claim is invalid");
	}
	return { sub: payload.sub };
}

export async function createPrivateOIDCCertificationApp(options: CertificationOptions): Promise<FastifyInstance> {
	const app = Fastify({ logger: false });
	const issuer = options.issuer ?? PRIVATE_CERTIFICATION_ISSUER;
	const clientId = options.env.HAPI_CERTIFICATION_CLIENT_ID?.trim() || PRIVATE_CERTIFICATION_CLIENT_ID;
	const clientSecret = options.env.HAPI_CERTIFICATION_CLIENT_SECRET?.trim() ?? "";
	const redirectUri = options.env.HAPI_CERTIFICATION_REDIRECT_URI?.trim() ?? "";
	const username = options.env.HAPI_CERTIFICATION_OPERATOR_USERNAME?.trim() ?? "";
	const password = options.env.HAPI_CERTIFICATION_OPERATOR_PASSWORD?.trim() ?? "";
	const fetchImpl = options.fetch ?? globalThis.fetch;

	if (issuer !== PRIVATE_CERTIFICATION_ISSUER) throw new Error("Private certification client requires the production HAPI issuer");
	if (!redirectUri || redirectUri !== PRIVATE_CERTIFICATION_CALLBACK_URI) throw new Error("Exact approved HTTPS callback is required");
	if (new URL(redirectUri).protocol !== "https:") throw new Error("Approved HTTPS callback is required");
	if (!username || username.includes(":") || password.length < 32 || password === clientSecret) {
		throw new Error("Independent operator credentials and confidential client secret are required");
	}
	if (!clientSecret || clientSecret.length < 32) throw new Error("HAPI certification client secret is required");

	await app.register(formbody);
	const flows = new Map<string, Flow>();

	app.get("/health/live", async (_request, reply) => reply.code(200)
		.header("Cache-Control", "no-store")
		.header("X-Content-Type-Options", "nosniff")
		.send({ status: "ok" }));
	const operatorAuth = async (request: FastifyRequest, reply: FastifyReply) => {
		reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer");
		const match = typeof request.headers.authorization === "string"
			? /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(request.headers.authorization) : null;
		const decoded = match ? Buffer.from(match[1], "base64").toString("utf8") : "";
		const separator = decoded.indexOf(":");
		const valid = separator >= 0 && constantTimeStringEqual(decoded.slice(0, separator), username)
			&& constantTimeStringEqual(decoded.slice(separator + 1), password);
		if (!valid) {
			return reply.code(401).header("WWW-Authenticate", 'Basic realm="HAPI private OIDC certification", charset="UTF-8"')
				.send({ error: "unauthorized" });
		}
	};
	const route = { onRequest: operatorAuth };

	app.get("/oidc-certification", route, async (_request, reply) => {
		const handle = random();
		const csrf = random();
		flows.set(handle, { state: "", nonce: "", verifier: "", csrf, expiresAt: Date.now() + TTL_MS, consumed: false });
		reply.header("Set-Cookie", `${COOKIE}=${handle}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
		return page(reply, 200, "HAPI ID Private OIDC Certification",
			'<p>Operator access only. Starting a test sends you to the HAPI ID production issuer.</p>' +
			`<form method="post" action="/oidc-certification/start"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">Start test</button></form>`);
	});

	app.post("/oidc-certification/start", route, async (request, reply) => {
		const handle = cookieHandle(request);
		const body = request.body as { csrf?: unknown } | undefined;
		if (request.headers.origin !== "https://certification.hapiinc.com") {
			return page(reply, 403, "Test refused", '<p><a href="/oidc-certification">Start another test</a></p>');
		}
		const existing = handle ? flows.get(handle) : undefined;
		if (!handle || !existing || existing.expiresAt < Date.now() || typeof body?.csrf !== "string" ||
			!constantTimeStringEqual(existing.csrf, body.csrf)) {
			return page(reply, 400, "Test expired", '<p><a href="/oidc-certification">Start another test</a></p>');
		}
		const state = random();
		const nonce = random();
		const verifier = random();
		flows.set(handle, { state, nonce, verifier, csrf: existing.csrf, expiresAt: Date.now() + TTL_MS, consumed: false });
		const query = new URLSearchParams({
			client_id: clientId,
			redirect_uri: redirectUri,
			response_type: "code",
			scope: "openid email",
			state,
			nonce,
			code_challenge: sha256(verifier),
			code_challenge_method: "S256"
		});
		return reply.redirect(`${issuer}/authorize?${query}`, 303);
	});

	app.get("/oidc-certification/callback", route, async (request, reply) => {
		const handle = cookieHandle(request);
		const flow = handle ? flows.get(handle) : undefined;
		const query = request.query as { state?: unknown; code?: unknown; error?: unknown };
		const results: CertificationResult[] = [
			{ name: "Authorization response and state", passed: false },
			{ name: "Authorization code exchange with PKCE S256", passed: false },
			{ name: "Signed ID token issuer, audience, nonce and expiration", passed: false },
			{ name: "UserInfo subject matches ID token", passed: false }
		];

		if (!handle || !flow || flow.expiresAt < Date.now() || flow.consumed || typeof query.state !== "string" ||
			query.error !== undefined || typeof query.code !== "string" || !query.code) {
			flow && (flow.results = results);
			return renderResults(reply, results, flow?.csrf);
		}
		if (!constantTimeStringEqual(flow.state, query.state)) {
			flow.results = results;
			return renderResults(reply, results, flow.csrf);
		}
		flow.consumed = true;
		results[0].passed = true;

		try {
			const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64");
			const tokenResponse = await fetchImpl(`${issuer}/token`, {
				method: "POST",
				headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ grant_type: "authorization_code", code: query.code,
					redirect_uri: redirectUri, code_verifier: flow.verifier }).toString()
			});
			const token = await tokenResponse.json() as { id_token?: unknown; access_token?: unknown; refresh_token?: unknown };
			const idToken = typeof token.id_token === "string" ? token.id_token : undefined;
			const exchanged = tokenResponse.ok && idToken !== undefined && typeof token.access_token === "string" && !token.refresh_token;
			results[1].passed = exchanged;
			if (!exchanged || idToken === undefined) throw new Error("token exchange failed");

			let subject: string | undefined;
			try {
				const jwksResponse = await fetchImpl(`${issuer}/jwks`, { headers: { accept: "application/json" } });
				if (!jwksResponse.ok) throw new Error("JWKS unavailable");
				const jwks = await jwksResponse.json() as never;
				const { payload } = await jwtVerify(idToken, createLocalJWKSet(jwks as never), {
					issuer,
					audience: clientId,
					algorithms: ["RS256"],
					requiredClaims: ["sub", "exp", "iat", "nonce", "aud"]
				});
				if (payload.nonce !== flow.nonce || typeof payload.sub !== "string" || payload.sub.length === 0) throw new Error("invalid nonce or subject");
				if (typeof payload.iat !== "number" || payload.iat > Math.floor(Date.now() / 1000) + 60) throw new Error("invalid issued-at claim");
				subject = payload.sub;
				results[2].passed = true;
			} catch {
				results[2].passed = false;
			}

			if (subject) {
				const userResponse = await fetchImpl(`${issuer}/userinfo`, {
					headers: { authorization: `Bearer ${token.access_token}` }
				});
				const userInfo = await userResponse.json() as { sub?: unknown };
				results[3].passed = userResponse.ok && typeof userInfo.sub === "string" && userInfo.sub === subject;
			}
		} catch {
			// The callback is deliberately summary-only and never stores or renders token values.
		}

		flow.results = results;
		return renderResults(reply, results, flow.csrf);
	});

	app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: "not_found" }));
	return app;
}

function renderResults(reply: FastifyReply, results: CertificationResult[], csrf?: string) {
	const resultRows = results.map(result => `<li><strong>${result.passed ? "PASS" : "FAIL"}</strong>: ${escapeHtml(result.name)}</li>`).join("");
	const csrfField = csrf ? `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">` : "";
	return page(reply, 200, "HAPI ID OIDC Certification Results",
		`<ol>${resultRows}</ol><form method="post" action="/oidc-certification/start">${csrfField}<button type="submit">Start another test</button></form>`);
}
