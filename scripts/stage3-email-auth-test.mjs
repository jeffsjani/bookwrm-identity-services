#!/usr/bin/env node
// =============================================================================
// HAPI ID V2-E Stage 3 Phase D — staging direct-API email authentication test
// =============================================================================
// Deterministic, scripted Authorization Code + PKCE (S256) test against the
// ISOLATED staging issuer using the confidential client 'staging-web' and the
// HAPI_EMAIL method via the JSON authorization handoff (POST /authorize with
// authentication_result). Universal Login is NOT required or used:
// HAPI_UNIVERSAL_LOGIN_ENABLED stays false for this test.
//
// Flow exercised (all endpoints verified against src/ on 2026-11-19):
//   1. Discovery + staging JWKS (and production JWKS, fetched ONLY for the
//      local negative key-isolation check — no staging artifact is ever sent
//      to production).
//   2. Client-secret probes via POST /v1/registration/complete with a random
//      UUID: correct secret -> 400 (authenticated, evidence invalid);
//      wrong secret -> 401 (rejected). No OTP, no identity, no state beyond
//      audit rows.
//   2b. Optional --register-identity: H2/H3 round that creates (or idempotently
//      confirms) the ONE approved synthetic identity for STAGING_TEST_EMAIL:
//      POST /v1/identity/email/start (purpose REGISTRATION) -> hidden OTP ->
//      POST /v1/identity/email/verify -> POST /v1/registration/complete.
//      REQUIRED on a fresh staging registry: H4 email authentication never
//      creates identities (PostgresEmailAuthenticationRepository.establish has
//      "no creation/registration path"); without an eligible identity the
//      positive round below fails with NO_ELIGIBLE_IDENTITY after consuming an
//      OTP. Re-running against an existing identity is a safe idempotent reuse
//      (H3 Case B).
//   3. H4: POST /v1/authentication/email/start -> OTP email to the controlled
//      inbox; operator types the OTP at a hidden prompt (never echoed/printed).
//   4. POST /v1/authentication/email/verify -> authentication_result (held in
//      memory only).
//   5. POST /authorize (HTTP Basic + JSON body, PKCE S256 challenge, nonce,
//      state, registered redirect URI) -> JSON { redirectUri } containing the
//      authorization code (never printed). Exact redirect prefix + state echo
//      asserted. authentication_result replay then asserted rejected.
//   6. POST /token (client_secret_basic + code_verifier) -> tokens (never
//      printed). No Set-Cookie expected (persistent sessions off).
//   7. ID token verified LOCALLY against staging JWKS only: iss, aud, nonce
//      echo, sub consistency, RS256, exp/iat sanity. Then asserted to FAIL
//      against production JWKS locally (key isolation).
//   8. GET /userinfo with the access token -> sub/email match; garbage bearer
//      -> 401.
//   9. Negative: same code replayed at /token -> invalid_grant.
//  10. Optional --negative-verifier: a SECOND full OTP round whose only
//      purpose is proving a wrong code_verifier is rejected (the code is
//      consumed by that rejection — expected).
//
// Secrecy policy: this script NEVER prints OTPs, authorization codes, client
// secrets, access tokens, ID tokens, or authentication_result values. The
// client secret is read from the environment only and sent only inside TLS
// Basic-auth headers to the staging origin.
//
// Required environment:
//   STAGING_WEB_CLIENT_SECRET or STAGING_CLIENT_SECRET (environment only)
//   STAGING_TEST_EMAIL      the approved controlled test inbox address
// Optional:
//   STAGING_ISSUER          default https://id-staging.hapiinc.com (must match)
//   STAGING_CLIENT_ID       default staging-web
//   STAGING_REDIRECT_URI    default https://staging-app.hapiinc.com/callback
//
// Usage (after separate written Phase D approval only):
//   node scripts/stage3-email-auth-test.mjs --staging-live-approved \
//     [--register-identity] [--negative-verifier]
// =============================================================================

import crypto from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";

const EXPECTED_STAGING_ISSUER = "https://id-staging.hapiinc.com";
const PRODUCTION_ISSUER = "https://identity.bookwrm.com";

const args = new Set(process.argv.slice(2));
const issuer = process.env.STAGING_ISSUER ?? EXPECTED_STAGING_ISSUER;
const clientId = process.env.STAGING_CLIENT_ID ?? "staging-web";
const redirectUri = process.env.STAGING_REDIRECT_URI ?? "https://staging-app.hapiinc.com/callback";
const clientSecret = process.env.STAGING_WEB_CLIENT_SECRET ?? process.env.STAGING_CLIENT_SECRET;
const testEmail = process.env.STAGING_TEST_EMAIL;

const results = [];
function record(id, status, detail = "") {
	results.push({ id, status });
	const icon = { PASS: "✅", FAIL: "❌", INFO: "ℹ️ ", SKIP: "⏭️ " }[status] ?? "?";
	console.log(`${icon} [${status}] ${id}${detail ? ` — ${detail}` : ""}`);
}
function fatal(message) {
	console.error(`❌ ${message}`);
	process.exit(1);
}

// --- fail-closed preconditions ----------------------------------------------
if (!args.has("--staging-live-approved")) {
	fatal("Refusing to run: pass --staging-live-approved only after the separate written Phase D approval. " +
		"This script sends a real OTP email and performs live staging authentication.");
}
if (issuer !== EXPECTED_STAGING_ISSUER) fatal(`STAGING_ISSUER must be exactly ${EXPECTED_STAGING_ISSUER} (got "${issuer}")`);
if (!clientSecret || clientSecret.trim().length < 32) fatal("Client secret missing or too short (set via environment only; never argv)");
if (!testEmail || !testEmail.includes("@")) fatal("STAGING_TEST_EMAIL missing or invalid");
if (process.argv.some(a => a.includes(clientSecret))) fatal("Refusing to run: the client secret appears in argv — pass it via the environment only");

const basic = "Basic " + Buffer.from(
	`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64");

async function fetchJson(url, init) {
	const response = await fetch(url, { redirect: "manual", ...init });
	const text = await response.text();
	let json;
	try { json = JSON.parse(text); } catch { json = undefined; }
	return { response, json };
}

function promptHidden(label) {
	return new Promise(resolve => {
		process.stdout.write(label);
		const stdin = process.stdin;
		stdin.resume();
		stdin.setRawMode?.(true);
		let value = "";
		const onData = chunk => {
			for (const char of chunk.toString("utf8")) {
				if (char === "\r" || char === "\n" || char === "\u0004") {
					stdin.setRawMode?.(false);
					stdin.pause();
					stdin.off("data", onData);
					process.stdout.write("\n");
					resolve(value.trim());
					return;
				}
				if (char === "\u0003") { process.stdout.write("\n"); process.exit(130); }
				if (char === "\u007f" || char === "\b") { value = value.slice(0, -1); continue; }
				value += char;
			}
		};
		stdin.on("data", onData);
	});
}

// One OTP round: start -> hidden OTP prompt -> verify -> authentication_result.
async function emailAuthenticationRound(label) {
	const start = await fetchJson(`${issuer}/v1/authentication/email/start`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/json" },
		body: JSON.stringify({ email: testEmail })
	});
	if (start.response.status !== 200 || !start.json?.challengeId) {
		record(`${label}.start`, "FAIL", `POST /v1/authentication/email/start -> HTTP ${start.response.status}`);
		return undefined;
	}
	record(`${label}.start`, "PASS", `challenge created (expires in ${start.json.expiresIn}s); OTP sent to the controlled inbox`);
	const otp = await promptHidden(`Enter the OTP received at the controlled inbox for ${label} (input hidden): `);
	if (!otp) { record(`${label}.verify`, "FAIL", "no OTP entered"); return undefined; }
	const verify = await fetchJson(`${issuer}/v1/authentication/email/verify`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/json" },
		body: JSON.stringify({ challengeId: start.json.challengeId, code: otp })
	});
	if (verify.response.status !== 200 || !verify.json?.authenticationResult || !verify.json?.subject) {
		record(`${label}.verify`, "FAIL", `verify -> HTTP ${verify.response.status} (OTP wrong/expired, or identity not eligible — run with --register-identity on a fresh staging registry)`);
		return undefined;
	}
	record(`${label}.verify`, "PASS", "authentication_result issued (value withheld)");
	record(`${label}.verify.ttl`, verify.json.expiresIn === 60 ? "PASS" : "FAIL",
		`authentication_result expiresIn=${verify.json.expiresIn}s (expected exactly 60)`);
	return { authenticationResult: verify.json.authenticationResult, subject: verify.json.subject };
}

// Optional H2/H3 round: create (or idempotently confirm) the synthetic identity.
async function registerSyntheticIdentity() {
	const start = await fetchJson(`${issuer}/v1/identity/email/start`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/json" },
		body: JSON.stringify({ email: testEmail, purpose: "REGISTRATION" })
	});
	if (start.response.status !== 200 || !start.json?.challengeId) {
		record("register.start", "FAIL", `POST /v1/identity/email/start -> HTTP ${start.response.status}`);
		return false;
	}
	record("register.start", "PASS", "REGISTRATION challenge created; OTP sent to the controlled inbox");
	const otp = await promptHidden("Enter the OTP received at the controlled inbox for register (input hidden): ");
	if (!otp) { record("register.verify", "FAIL", "no OTP entered"); return false; }
	const verify = await fetchJson(`${issuer}/v1/identity/email/verify`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/json" },
		body: JSON.stringify({ challengeId: start.json.challengeId, code: otp, purpose: "REGISTRATION" })
	});
	if (verify.response.status !== 200 || verify.json?.verified !== true || !verify.json?.verificationId) {
		record("register.verify", "FAIL", `verify -> HTTP ${verify.response.status} (OTP wrong/expired)`);
		return false;
	}
	record("register.verify", "PASS", "REGISTRATION evidence verified");
	const complete = await fetchJson(`${issuer}/v1/registration/complete`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/json" },
		body: JSON.stringify({ verificationId: verify.json.verificationId })
	});
	const ok = complete.response.status === 200 && complete.json?.registered === true &&
		Boolean(complete.json?.subject) && complete.json?.emailVerified === true &&
		(complete.json?.email ?? "").toLowerCase() === testEmail.trim().toLowerCase();
	record("register.complete", ok ? "PASS" : "FAIL",
		`POST /v1/registration/complete -> HTTP ${complete.response.status}, registered=${complete.json?.registered}, email match=${(complete.json?.email ?? "").toLowerCase() === testEmail.trim().toLowerCase()} (synthetic identity exists; subject withheld)`);
	return ok;
}

// Authorization handoff: POST /authorize (Basic + JSON) -> { redirectUri } -> code.
async function authorizeHandoff(label, authenticationResult, { codeChallenge, nonce, state }) {
	const { response, json } = await fetchJson(`${issuer}/authorize`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/json" },
		body: JSON.stringify({
			client_id: clientId, redirect_uri: redirectUri, response_type: "code",
			scope: "openid profile email", state, nonce,
			code_challenge: codeChallenge, code_challenge_method: "S256",
			authentication_result: authenticationResult
		})
	});
	if (response.status !== 200 || !json?.redirectUri) {
		record(`${label}.authorize`, "FAIL", `POST /authorize -> HTTP ${response.status}`);
		return undefined;
	}
	if (response.headers.get("set-cookie")) {
		record(`${label}.authorize.no-cookie`, "FAIL", "POST /authorize set a cookie — persistent sessions must be OFF");
	} else {
		record(`${label}.authorize.no-cookie`, "PASS", "no Set-Cookie (persistent sessions off)");
	}
	let redirect;
	try { redirect = new URL(json.redirectUri); } catch {
		record(`${label}.authorize`, "FAIL", "redirectUri is not a valid URL");
		return undefined;
	}
	const prefixOk = `${redirect.origin}${redirect.pathname}` === redirectUri;
	const code = redirect.searchParams.get("code");
	const echoedState = redirect.searchParams.get("state");
	record(`${label}.authorize`, prefixOk && code && echoedState === state ? "PASS" : "FAIL",
		`JSON handoff -> redirect to registered URI=${prefixOk}, code present=${Boolean(code)}, state echo=${echoedState === state} (code withheld)`);
	return prefixOk && code && echoedState === state ? code : undefined;
}

async function tokenExchange(code, codeVerifier) {
	return fetchJson(`${issuer}/token`, {
		method: "POST",
		headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: codeVerifier
		}).toString()
	});
}

console.log("HAPI ID V2-E Stage 3 Phase D — staging direct-API email authentication test");
console.log(`issuer=${issuer} client=${clientId} redirect_uri=${redirectUri} universal_login=not used\n`);

// --- 1. Discovery + JWKS -----------------------------------------------------
const discovery = await fetchJson(`${issuer}/.well-known/openid-configuration`);
if (discovery.response.status !== 200 || !discovery.json) fatal(`discovery -> HTTP ${discovery.response.status}`);
record("discovery.issuer", discovery.json.issuer === issuer ? "PASS" : "FAIL", `issuer=${discovery.json.issuer}`);
record("discovery.grants", JSON.stringify(discovery.json.grant_types_supported) === '["authorization_code"]' ? "PASS" : "FAIL",
	`grant_types_supported=${JSON.stringify(discovery.json.grant_types_supported)}`);
if (discovery.json.issuer !== issuer || JSON.stringify(discovery.json.grant_types_supported) !== '["authorization_code"]') {
	fatal("Staging discovery issuer or grants do not match the approved configuration");
}
if (discovery.json.jwks_uri !== `${issuer}/jwks` || discovery.json.userinfo_endpoint !== `${issuer}/userinfo`) {
	fatal("Staging discovery endpoints do not match the approved issuer");
}

const stagingJwks = await fetchJson(discovery.json.jwks_uri);
const stagingKeys = stagingJwks.json?.keys ?? [];
record("jwks.staging", stagingKeys.length > 0 ? "PASS" : "FAIL", `kids=${stagingKeys.map(k => k.kid).join(", ")}`);
const prodJwks = await fetchJson(`${PRODUCTION_ISSUER}/jwks`);
const prodKeys = prodJwks.json?.keys ?? [];
record("jwks.production.fetched", prodKeys.length > 0 ? "PASS" : "FAIL", "fetched for LOCAL negative verification only");

// --- 2. Client-secret probes (no OTP, no identity) ---------------------------
const probeBody = JSON.stringify({ verificationId: crypto.randomUUID() });
const goodProbe = await fetchJson(`${issuer}/v1/registration/complete`, {
	method: "POST", headers: { authorization: basic, "content-type": "application/json" }, body: probeBody
});
const goodProbeAccepted = goodProbe.response.status === 400 && goodProbe.json?.error === "INVALID_EVIDENCE";
record("secret.accepted", goodProbeAccepted ? "PASS" : "FAIL",
	`correct secret + unknown evidence -> HTTP ${goodProbe.response.status} (expected 400 INVALID_EVIDENCE)`);
if (!goodProbeAccepted) fatal("Client authentication could not be verified; aborting before OTP delivery");
const wrongBasic = "Basic " + Buffer.from(`${encodeURIComponent(clientId)}:${crypto.randomBytes(24).toString("base64url")}`).toString("base64");
const badProbe = await fetchJson(`${issuer}/v1/registration/complete`, {
	method: "POST", headers: { authorization: wrongBasic, "content-type": "application/json" }, body: probeBody
});
record("secret.rejected", badProbe.response.status === 401 ? "PASS" : "FAIL",
	`incorrect secret -> HTTP ${badProbe.response.status} (expected 401)`);
if (badProbe.response.status !== 401) fatal("Incorrect client secret was not rejected; aborting before OTP delivery");

// --- 2b. Optional: create/confirm the synthetic identity (H2/H3) -------------
if (args.has("--register-identity")) {
	const registered = await registerSyntheticIdentity();
	if (!registered) fatal("synthetic identity registration failed; aborting before authentication");
} else {
	record("register", "SKIP", "pass --register-identity on a fresh staging registry (H4 never creates identities)");
}

// --- 3. Positive round: OTP -> handoff -> token -> userinfo ------------------
const round = await emailAuthenticationRound("auth");
if (!round) fatal("email authentication round failed; aborting before authorization");

const codeVerifier = crypto.randomBytes(32).toString("base64url");
const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
const nonce = crypto.randomUUID();
const state = crypto.randomUUID();

const code = await authorizeHandoff("auth", round.authenticationResult, { codeChallenge, nonce, state });
if (!code) fatal("authorization handoff failed; aborting");

// authentication_result is single-use: replay must be rejected.
const replayResult = await fetchJson(`${issuer}/authorize`, {
	method: "POST",
	headers: { authorization: basic, "content-type": "application/json" },
	body: JSON.stringify({
		client_id: clientId, redirect_uri: redirectUri, response_type: "code",
		scope: "openid profile email", state: crypto.randomUUID(), nonce: crypto.randomUUID(),
		code_challenge: codeChallenge, code_challenge_method: "S256",
		authentication_result: round.authenticationResult
	})
});
record("negative.result-replay", replayResult.response.status >= 400 && replayResult.response.status < 500 && !replayResult.json?.redirectUri ? "PASS" : "FAIL",
	`replayed authentication_result -> HTTP ${replayResult.response.status} (expected 4xx, no redirectUri)`);

const token = await tokenExchange(code, codeVerifier);
const tokenOk = token.response.status === 200 && token.json?.access_token && token.json?.id_token;
record("token.exchange", tokenOk ? "PASS" : "FAIL",
	`POST /token (client_secret_basic + PKCE) -> HTTP ${token.response.status}, access_token=${Boolean(token.json?.access_token)}, id_token=${Boolean(token.json?.id_token)} (values withheld)`);
record("token.no-cookie", token.response.headers.get("set-cookie") ? "FAIL" : "PASS",
	"no Set-Cookie on /token (persistent sessions off)");
record("token.no-refresh", token.json?.refresh_token ? "FAIL" : "PASS",
	"no refresh_token issued (refresh grant off)");
if (!tokenOk) fatal("token exchange failed; aborting");

// --- 4. ID-token validation (LOCAL, staging JWKS only) -----------------------
const idToken = token.json.id_token;
try {
	const header = decodeProtectedHeader(idToken);
	const { payload } = await jwtVerify(idToken, createLocalJWKSet({ keys: stagingKeys }), {
		issuer, audience: clientId, algorithms: ["RS256"], requiredClaims: ["sub", "iat", "exp", "nonce"]
	});
	const now = Math.floor(Date.now() / 1000);
	record("idtoken.verify", "PASS", `signature valid against staging JWKS; iss=${payload.iss} aud=${payload.aud} alg=${header.alg}`);
	record("idtoken.alg", header.alg === "RS256" ? "PASS" : "FAIL", `alg=${header.alg}`);
	const nonceOk = payload.nonce === nonce;
	record("idtoken.nonce", nonceOk ? "PASS" : "FAIL", "nonce echo matches the authorization request");
	if (!nonceOk) fatal("ID token nonce invalid; aborting before UserInfo");
	const subjectOk = payload.sub === round.subject;
	record("idtoken.sub", subjectOk ? "PASS" : "FAIL", "sub matches the authenticated subject");
	if (!subjectOk) fatal("ID token subject invalid; aborting before UserInfo");
	const timesOk = typeof payload.iat === "number" && Number.isFinite(payload.iat) &&
		typeof payload.exp === "number" && Number.isFinite(payload.exp) && payload.iat <= now + 60 && payload.exp > now;
	record("idtoken.times", timesOk ? "PASS" : "FAIL", "iat/exp sanity check");
	if (!timesOk) fatal("ID token timing claims invalid; aborting before UserInfo");
} catch {
	record("idtoken.verify", "FAIL", "signature or required claims invalid");
	fatal("ID token validation failed; aborting before UserInfo");
}
try {
	await jwtVerify(idToken, createLocalJWKSet({ keys: prodKeys }));
	record("negative.idtoken.cross-jwks", "FAIL", "staging ID token VERIFIED against production JWKS — key isolation broken");
} catch {
	record("negative.idtoken.cross-jwks", "PASS", "staging ID token rejected by production JWKS (local check)");
}

// --- 5. UserInfo + negative bearer -------------------------------------------
const userinfo = await fetchJson(discovery.json.userinfo_endpoint, {
	headers: { authorization: `Bearer ${token.json.access_token}` }
});
record("userinfo", userinfo.response.status === 200 && userinfo.json?.sub === round.subject &&
	(userinfo.json?.email ?? "").toLowerCase() === testEmail.trim().toLowerCase() ? "PASS" : "FAIL",
	`GET /userinfo -> HTTP ${userinfo.response.status}, sub match=${userinfo.json?.sub === round.subject}, email match=${(userinfo.json?.email ?? "").toLowerCase() === testEmail.trim().toLowerCase()}`);
const garbageBearer = await fetchJson(discovery.json.userinfo_endpoint, {
	headers: { authorization: "Bearer not-a-real-token" }
});
record("negative.userinfo.garbage-bearer", garbageBearer.response.status === 401 ? "PASS" : "FAIL",
	`garbage bearer -> HTTP ${garbageBearer.response.status} (expected 401)`);

// --- 6. Negative: authorization-code replay -----------------------------------
const replayCode = await tokenExchange(code, codeVerifier);
record("negative.code-replay", replayCode.response.status === 400 && replayCode.json?.error === "invalid_grant" ? "PASS" : "FAIL",
	`code replay -> HTTP ${replayCode.response.status} error=${replayCode.json?.error} (expected 400 invalid_grant)`);

// --- 7. Optional negative: wrong code_verifier (second OTP round) -------------
if (args.has("--negative-verifier")) {
	const second = await emailAuthenticationRound("negative-verifier");
	if (second) {
		const verifier2 = crypto.randomBytes(32).toString("base64url");
		const challenge2 = crypto.createHash("sha256").update(verifier2).digest("base64url");
		const state2 = crypto.randomUUID();
		const code2 = await authorizeHandoff("negative-verifier", second.authenticationResult,
			{ codeChallenge: challenge2, nonce: crypto.randomUUID(), state: state2 });
		if (code2) {
			const wrongVerifier = await tokenExchange(code2, crypto.randomBytes(32).toString("base64url"));
			record("negative.wrong-verifier", wrongVerifier.response.status === 400 && wrongVerifier.json?.error === "invalid_grant" ? "PASS" : "FAIL",
				`wrong code_verifier -> HTTP ${wrongVerifier.response.status} error=${wrongVerifier.json?.error} (expected 400 invalid_grant; code is consumed by this rejection)`);
		}
	}
} else {
	record("negative.wrong-verifier", "SKIP", "pass --negative-verifier to run (consumes one extra OTP round)");
}

// --- Summary ------------------------------------------------------------------
const failures = results.filter(entry => entry.status === "FAIL");
console.log(`\nSummary: ${results.filter(entry => entry.status === "PASS").length} pass, ${failures.length} fail, ` +
	`${results.filter(entry => entry.status === "SKIP").length} skipped`);
if (failures.length > 0) process.exit(1);
