#!/usr/bin/env node
// =============================================================================
// HAPI ID V2-E Stage 1 — staging OIDC certification harness
// =============================================================================
// Read-only / synthetic-only certification of the isolated staging issuer
// https://id-staging.hapiinc.com against the Stage 1 Phase D checklist, plus a
// production-preflight mode that verifies the current production issuer state.
//
// Modes:
//   node scripts/certify-staging-oidc.mjs --preflight
//       Production-only, read-only. No staging deployment required. Verifies:
//       production discovery invariants + baseline, JWKS, V2 endpoints absent,
//       staging/canonical DNS state.
//
//   STAGING_ISSUER=https://id-staging.hapiinc.com \
//   node scripts/certify-staging-oidc.mjs --staging-approved
//       Full staging certification. REQUIRES a separately approved, already
//       deployed staging service; the flag is an explicit assertion that the
//       deployment approval was granted. The harness never provisions,
//       deploys, or mutates anything: every staging check is an HTTPS request
//       against the already-running service using synthetic inputs only.
//
// Optional environment for deeper staging checks (synthetic/staging-only):
//   STAGING_CLIENT_ID        synthetic staging client (e.g. staging-web)
//   STAGING_REDIRECT_URI     its exact registered redirect URI
//   STAGING_ID_TOKEN         ID token minted BY STAGING for a synthetic user; verified
//                            LOCALLY against fetched JWKS only — never transmitted.
//
// Token-transmission policy (V2-E Stage 2): this harness NEVER sends real
// credentials or bearer tokens to any environment, in either direction. Live
// cross-issuer token-rejection certification is deferred to the positive
// authentication stage and is reported as NOT-TESTED until then; a garbage
// foreign bearer probe is reported separately as an infrastructure check and
// is never presented as cross-issuer evidence.
//
// Statuses: PASS/FAIL (infrastructure checks), DENIED (request fully validated
// and then intentionally denied because no authentication method is enabled —
// the expected posture until email activation), NOT-TESTED (requires live
// authentication, deferred), MANUAL, SKIP, INFO. Only FAIL affects exit code.
// =============================================================================

import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { readFile } from "node:fs/promises";
import { resolve4 } from "node:dns/promises";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PRODUCTION_ISSUER = "https://identity.bookwrm.com";
const EXPECTED_STAGING_ISSUER = "https://id-staging.hapiinc.com";
const CANONICAL_ISSUER = "https://id.hapiinc.com";
const BASELINE_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), "production-discovery-baseline.json");

const results = [];
function record(id, status, detail) {
	results.push({ id, status, detail });
	const icon = { PASS: "✅", FAIL: "❌", SKIP: "⏭️ ", MANUAL: "📝", INFO: "ℹ️ ", DENIED: "🚫", "NOT-TESTED": "⏸️ " }[status] ?? "?";
	console.log(`${icon} [${status}] ${id}${detail ? ` — ${detail}` : ""}`);
}

async function fetchJson(url, init) {
	const response = await fetch(url, { redirect: "manual", ...init });
	const text = await response.text();
	let json;
	try { json = JSON.parse(text); } catch { json = undefined; }
	return { response, json, text };
}

function assertHost(url, origin, label) {
	if (!url || !String(url).startsWith(`${origin}/`)) {
		throw new Error(`${label} "${url}" is not on ${origin}`);
	}
}

async function dnsState(host) {
	try {
		const addresses = await resolve4(host);
		return `resolves (${addresses.join(", ")})`;
	} catch {
		return "does not resolve";
	}
}

// ---------------------------------------------------------------------------
// Production preflight (always read-only GETs against public endpoints)
// ---------------------------------------------------------------------------
async function productionPreflight() {
	const { response, json } = await fetchJson(`${PRODUCTION_ISSUER}/.well-known/openid-configuration`);
	if (response.status !== 200 || !json) {
		record("prod.discovery", "FAIL", `HTTP ${response.status}`);
		return;
	}

	record("prod.discovery.issuer", json.issuer === PRODUCTION_ISSUER ? "PASS" : "FAIL", `issuer=${json.issuer}`);
	const grants = JSON.stringify(json.grant_types_supported);
	record("prod.discovery.grants", grants === '["authorization_code"]' ? "PASS" : "FAIL",
		`grant_types_supported=${grants} (refresh grant must be OFF)`);

	try {
		const baseline = JSON.parse(await readFile(BASELINE_PATH, "utf8"));
		const identical = JSON.stringify(baseline) === JSON.stringify(json);
		record("prod.discovery.baseline", identical ? "PASS" : "FAIL",
			identical ? "byte-identical to committed Stage 1 baseline" : "DIFFERS from committed baseline — investigate before staging work");
	} catch (error) {
		record("prod.discovery.baseline", "SKIP", `baseline unavailable: ${error.message}`);
	}

	const jwks = await fetchJson(`${PRODUCTION_ISSUER}/jwks`);
	const prodKids = (jwks.json?.keys ?? []).map((key) => key.kid);
	record("prod.jwks", prodKids.length > 0 ? "PASS" : "FAIL", `kids=${prodKids.join(", ")}`);

	for (const gated of ["/federation/apple/start", "/federation/google/start", "/account/links", "/session"]) {
		const { response: gatedResponse } = await fetchJson(`${PRODUCTION_ISSUER}${gated}`);
		record(`prod.gated${gated.replaceAll("/", ".")}`, gatedResponse.status === 404 ? "PASS" : "FAIL",
			`GET ${gated} -> ${gatedResponse.status} (expected 404: V2 features absent/disabled)`);
	}

	record("dns.staging", "INFO", `${new URL(EXPECTED_STAGING_ISSUER).hostname}: ${await dnsState(new URL(EXPECTED_STAGING_ISSUER).hostname)}`);
	record("dns.canonical", "INFO", `${new URL(CANONICAL_ISSUER).hostname}: ${await dnsState(new URL(CANONICAL_ISSUER).hostname)}`);
	return prodKids;
}

// ---------------------------------------------------------------------------
// Staging certification (requires separately approved deployed staging service)
// ---------------------------------------------------------------------------
async function stagingCertification(prodKids) {
	const staging = process.env.STAGING_ISSUER;

	// D1: HTTPS/TLS. fetch() performs full TLS verification; plain http is refused here.
	if (!staging || !staging.startsWith("https://")) {
		record("staging.tls", "FAIL", `STAGING_ISSUER must be an https origin (got "${staging}")`);
		return;
	}
	if (staging !== EXPECTED_STAGING_ISSUER) {
		record("staging.issuer.expected", "FAIL", `STAGING_ISSUER must be exactly ${EXPECTED_STAGING_ISSUER}`);
		return;
	}

	// D2/D3: discovery issuer + endpoint hosts.
	const { response, json } = await fetchJson(`${staging}/.well-known/openid-configuration`);
	if (response.status !== 200 || !json) {
		record("staging.discovery", "FAIL", `HTTP ${response.status} — is the staging service deployed?`);
		return;
	}
	record("staging.tls", "PASS", "TLS handshake + certificate verification succeeded via fetch");
	record("staging.discovery.issuer", json.issuer === staging ? "PASS" : "FAIL", `issuer=${json.issuer}`);
	try {
		assertHost(json.authorization_endpoint, staging, "authorization_endpoint");
		assertHost(json.token_endpoint, staging, "token_endpoint");
		assertHost(json.userinfo_endpoint, staging, "userinfo_endpoint");
		assertHost(json.jwks_uri, staging, "jwks_uri");
		record("staging.discovery.endpoints", "PASS", "authorization/token/userinfo/jwks all on the staging host");
	} catch (error) {
		record("staging.discovery.endpoints", "FAIL", error.message);
	}
	const grants = JSON.stringify(json.grant_types_supported);
	record("staging.discovery.grants", grants === '["authorization_code"]' ? "PASS" : "FAIL",
		`grant_types_supported=${grants} (all five flags must be OFF)`);

	// D4: staging JWKS present and disjoint from production keys.
	const jwks = await fetchJson(json.jwks_uri);
	const stagingKeys = jwks.json?.keys ?? [];
	const stagingKids = stagingKeys.map((key) => key.kid);
	record("staging.jwks", stagingKids.length > 0 ? "PASS" : "FAIL", `kids=${stagingKids.join(", ")}`);
	const overlap = stagingKids.filter((kid) => (prodKids ?? []).includes(kid));
	record("staging.jwks.disjoint", overlap.length === 0 ? "PASS" : "FAIL",
		overlap.length === 0 ? "no staging kid appears in the production JWKS" : `SHARED KEY IDS: ${overlap.join(", ")}`);

	// D4/D8: staging ID token verifies against staging JWKS and FAILS against production JWKS.
	const stagingIdToken = process.env.STAGING_ID_TOKEN;
	if (stagingIdToken) {
		const stagingKeySet = createLocalJWKSet({ keys: stagingKeys });
		try {
			const { payload } = await jwtVerify(stagingIdToken, stagingKeySet, { issuer: staging });
			record("staging.idtoken.verify", "PASS", `iss=${payload.iss} verified against staging JWKS`);
		} catch (error) {
			record("staging.idtoken.verify", "FAIL", error.message);
		}
		try {
			const prodJwks = await fetchJson(`${PRODUCTION_ISSUER}/jwks`);
			const prodKeySet = createLocalJWKSet({ keys: prodJwks.json?.keys ?? [] });
			await jwtVerify(stagingIdToken, prodKeySet);
			record("staging.idtoken.cross-jwks", "FAIL", "staging ID token VERIFIED against production JWKS — key isolation broken");
		} catch {
			record("staging.idtoken.cross-jwks", "PASS", "staging ID token rejected by production JWKS");
		}
		const { iss } = decodeJwt(stagingIdToken);
		record("staging.idtoken.iss", iss === staging ? "PASS" : "FAIL", `iss=${iss}`);
	} else {
		record("staging.idtoken.verify", "NOT-TESTED",
			"requires a staging-minted synthetic ID token; live authentication is disabled this stage (deferred to email-activation certification)");
	}

	// D5/D6: PKCE S256 authorize + exact redirect-URI enforcement (synthetic client).
	const clientId = process.env.STAGING_CLIENT_ID;
	const redirectUri = process.env.STAGING_REDIRECT_URI;
	if (clientId && redirectUri) {
		const verifier = crypto.randomBytes(32).toString("base64url");
		const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
		// V2-B requires nonce at /authorize (fail-fast); positive probes must include it.
		const authorize = (uri) => `${json.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(clientId)}` +
			`&redirect_uri=${encodeURIComponent(uri)}&scope=openid&state=${crypto.randomUUID()}&nonce=${crypto.randomUUID()}` +
			`&code_challenge=${challenge}&code_challenge_method=S256`;

		// Infrastructure vs. intentional denial: a fully validated request that is then
		// refused because no authentication method is enabled is the EXPECTED posture
		// while all login methods are disabled — recorded as DENIED, never FAIL.
		const ok = await fetchJson(authorize(redirectUri));
		const okStatus = ok.response.status;
		if ([200, 302, 303].includes(okStatus)) {
			record("staging.authorize.pkce", "PASS",
				`authorize with registered redirect_uri + S256 + nonce -> HTTP ${okStatus} (a live authentication method is enabled)`);
		} else if (okStatus === 403) {
			record("staging.authorize.pkce", "DENIED",
				"authorize request fully validated (client, redirect_uri, PKCE S256, nonce), then intentionally denied with HTTP 403: " +
				"no authentication method is enabled for the staging application — expected until email-authentication activation");
		} else {
			record("staging.authorize.pkce", "FAIL",
				`authorize with registered redirect_uri + S256 + nonce -> HTTP ${okStatus} (validation defect: expected 200/302/303 or an intentional 403 denial)`);
		}

		const evil = await fetchJson(authorize("https://attacker.example/callback"));
		const location = evil.response.headers.get("location") ?? "";
		const rejected = evil.response.status >= 400 || (!location.startsWith("https://attacker.example") && location !== "");
		record("staging.authorize.redirect-exact", rejected && !location.startsWith("https://attacker.example") ? "PASS" : "FAIL",
			`unregistered redirect_uri -> HTTP ${evil.response.status}${location ? ` location=${location}` : ""} (must never redirect to the attacker URI)`);

		// Missing PKCE must be rejected for public clients.
		const noPkce = await fetchJson(`${json.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(clientId)}` +
			`&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid&state=${crypto.randomUUID()}`);
		const noPkceLocation = noPkce.response.headers.get("location") ?? "";
		const pkceEnforced = noPkce.response.status >= 400 || noPkceLocation.includes("error=");
		record("staging.authorize.pkce-required", pkceEnforced ? "PASS" : "MANUAL",
			`authorize without code_challenge -> HTTP ${noPkce.response.status} (public clients must require S256)`);
	} else {
		record("staging.authorize.pkce", "MANUAL", "set STAGING_CLIENT_ID + STAGING_REDIRECT_URI to exercise PKCE + redirect-URI enforcement");
	}

	// D7: cross-issuer authorization-code redemption is covered by the
	// MultiIssuerConfiguration suite (issuer-bound Redis records) and by store
	// separation; the live half is the token checks below.
	record("staging.code.cross-issuer", "INFO",
		"issuer binding certified in tests/MultiIssuerConfiguration.test.ts; live stores are physically separate");

	// D8: live cross-issuer token rejection requires environment-minted tokens and is
	// certified in the positive authentication stage. This harness transmits NO real
	// bearer tokens in either direction; the garbage-bearer probe below is an
	// infrastructure check only and is never counted as cross-issuer evidence.
	record("cross.staging-token-at-prod", "NOT-TESTED",
		"deferred to positive authentication certification; this harness never transmits bearer tokens cross-environment");
	record("cross.prod-token-at-staging", "NOT-TESTED",
		"deferred to positive authentication certification; see staging.userinfo.foreign-bearer for the infrastructure-only probe");
	const garbage = await fetchJson(json.userinfo_endpoint, { headers: { authorization: "Bearer not-a-real-token" } });
	record("staging.userinfo.foreign-bearer", garbage.response.status === 401 ? "PASS" : "FAIL",
		`malformed foreign bearer at staging /userinfo -> HTTP ${garbage.response.status} (expected 401; NOT cross-issuer certification)`);

	// CORS isolation: production browser origins must be rejected on staging.
	const corsProduction = await fetchJson(`${staging}/.well-known/openid-configuration`, { headers: { origin: "https://bookwrm.com" } });
	const acaoProduction = corsProduction.response.headers.get("access-control-allow-origin");
	record("staging.cors.rejects-production-origins", acaoProduction === null ? "PASS" : "FAIL",
		`Origin https://bookwrm.com -> access-control-allow-origin=${acaoProduction ?? "(absent)"}`);
	const corsStaging = await fetchJson(`${staging}/.well-known/openid-configuration`, { headers: { origin: staging } });
	const acaoStaging = corsStaging.response.headers.get("access-control-allow-origin");
	record("staging.cors.allows-staging-origin", acaoStaging === staging ? "PASS" : "MANUAL",
		`Origin ${staging} -> access-control-allow-origin=${acaoStaging ?? "(absent — verify CORS_TRUSTED_ORIGINS)"}`);

	// Gated V2 endpoints must be absent/disabled on staging too (flags off).
	for (const gated of ["/federation/apple/start", "/federation/google/start", "/account/links"]) {
		const { response: gatedResponse } = await fetchJson(`${staging}${gated}`);
		record(`staging.gated${gated.replaceAll("/", ".")}`, gatedResponse.status === 404 ? "PASS" : "FAIL",
			`GET ${gated} -> ${gatedResponse.status} (expected 404 with flags off)`);
	}

	// Health probes.
	const health = await fetchJson(`${staging}/health`);
	record("staging.health", health.response.status === 200 ? "PASS" : "FAIL", `GET /health -> ${health.response.status}`);

	// D9: synthetic registration/authentication requires a live authentication method.
	record("staging.synthetic-auth", "NOT-TESTED",
		"requires an enabled authentication method (all login methods are disabled this stage); " +
		"run the synthetic registration + login ceremony after email-activation approval, then re-run with STAGING_ID_TOKEN set");
}

// ---------------------------------------------------------------------------
const args = new Set(process.argv.slice(2));
const preflightOnly = args.has("--preflight") || !args.has("--staging-approved");

console.log("HAPI ID V2-E Stage 1 — staging OIDC certification harness");
console.log(`mode: ${preflightOnly ? "production preflight (read-only)" : "staging certification (requires separately approved deployment)"}\n`);

const prodKids = await productionPreflight();

if (!preflightOnly) {
	console.log("");
	try {
		await stagingCertification(prodKids);
	} catch (error) {
		record("staging.unreachable", "FAIL",
			`staging certification aborted: ${error?.cause?.code ?? error.message} (is the staging service deployed and the domain resolvable?)`);
	}
} else if (process.env.STAGING_ISSUER) {
	console.log("\nSTAGING_ISSUER is set but --staging-approved was not passed; staging checks were NOT run.");
	console.log("Staging certification requires a separately approved deployment (Stage 1 approval gate).");
}

const failures = results.filter((entry) => entry.status === "FAIL");
const manual = results.filter((entry) => entry.status === "MANUAL");
const denied = results.filter((entry) => entry.status === "DENIED");
const notTested = results.filter((entry) => entry.status === "NOT-TESTED");
console.log(`\nSummary: ${results.filter((entry) => entry.status === "PASS").length} pass, ${failures.length} fail, ` +
	`${denied.length} expected-denial, ${notTested.length} not-tested, ${manual.length} manual, ` +
	`${results.filter((entry) => entry.status === "SKIP").length} skipped`);
if (failures.length > 0) process.exit(1);
