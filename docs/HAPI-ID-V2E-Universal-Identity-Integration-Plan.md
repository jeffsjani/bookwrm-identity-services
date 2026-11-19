# HAPI ID V2-E — Universal Identity Integration & Controlled Activation

## Readiness Assessment & Isolated Implementation Plan

Date: 2026-11-19
Repository: bookwrm-identity-services
Branch: `feature/hapi-id-v2d` (local only, never pushed)
Baseline head: `9a2ab06ff4fb7bf8494f4681286f2dabbf83a4f0`
Status: **Read-only assessment + planning. No issuer switch, no deployment, no live federation,
no identity modification, no push to any deploying branch.**

Companion documents: [V2-D Build & Certification Report](./HAPI-ID-V2D-Build-Certification-Report.md),
[V2-D Build Report](./HAPI-ID-V2D-Build-Report.md),
[V2-D Native-Client Readiness](./HAPI-ID-V2D-Native-Client-Readiness.md),
[V2-C Account-Linking API Design](./HAPI-ID-V2C-Account-Linking-API-Design.md).

---

## Deliverable 1 — V2-D final baseline and skipped-test assessment (Phase A)

All eight Phase A checks were re-executed empirically on this machine on 2026-11-19.

### 1.1 Baseline identity

| Check | Result |
| --- | --- |
| Final commit SHA | `9a2ab06ff4fb7bf8494f4681286f2dabbf83a4f0` |
| Working tree | clean (`git status` empty) |
| V2-D implementation commits present | ✅ `a0a6be1` (Phases 1-2), `50fcd12` (Phases 3-4), `40a6d8b` (Phase 6 tests), `21892b4` (Phase 5 + certification report), `9a2ab06` (build report) — exactly `d55480d..HEAD` |
| Railway deployment exposure | ✅ none: `git branch -r --contains` is empty for every V2-D commit; the repository contains no CI workflow, `railway.json`, `Dockerfile`, `Procfile`, or nixpacks config. Railway deploys only through its GitHub integration from pushed branches; this branch has never been pushed. |

### 1.2 Test baseline (re-run, not quoted)

Full suite, default (no-DB) configuration, Node v24 / Vitest 4.1.10:

```
Test Files  69 passed | 12 skipped (81)
     Tests  648 passed | 138 skipped (786)   — 0 failed
```

### 1.3 Classification of the 138 skipped tests

Every skipped test is gated by exactly one mechanism: `describe.skipIf(!databaseUrl)` on a
PostgreSQL connection variable. There are **no disabled, flaky-quarantined, or suppressed
security tests** anywhere in the suite.

| Suite | Skipped | Area | Gate variable |
| --- | --- | --- | --- |
| `HapiFaceEnrollment.postgres` | 45 | H5 face attachment durability | `HAPI_FACE_ENROLLMENT_TEST_DATABASE_URL` |
| `EmailAuthentication.postgres` | 24 | H4 identity resolution, single-use artifacts | `HAPI_AUTHENTICATION_TEST_DATABASE_URL` |
| `RefreshTokenRotation.postgres` | 10 | **V2-C refresh families (security-critical)** | `HAPI_REFRESH_TEST_DATABASE_URL` / `DATABASE_URL` |
| `HapiSession.postgres` | 9 | **V2-C persistent sessions (security-critical)** | `HAPI_SESSIONS_TEST_DATABASE_URL` / `DATABASE_URL` |
| `IdentityFederation.postgres` | 9 | **V2-B linking invariants (security-critical)** | `HAPI_FEDERATION_TEST_DATABASE_URL` / `DATABASE_URL` |
| `IdentityClaimProvenance.postgres` | 9 | claim provenance store | `DATABASE_URL` |
| `Registration.postgres` | 9 | H3 atomicity/concurrency | `HAPI_REGISTRATION_TEST_DATABASE_URL` |
| `EmailVerification.postgres` | 6 | H2 durable OTP semantics | `HAPI_EMAIL_TEST_DATABASE_URL` |
| `MultiClientFoundation.postgres` | 4 | multi-client link invariants | `HAPI_AUTHENTICATION_TEST_DATABASE_URL` |
| `P0SecurityGapAudit.synthetic` (gated describe) | 4 | **OTP attempt limiting under concurrency/restart (security-critical)** | `HAPI_EMAIL_TEST_DATABASE_URL` |
| `IdentityRegistry.postgres` | 3 | subject repository | `DATABASE_URL` |
| `SchemaVersioning.postgres` | 3 | migration idempotency | `DATABASE_URL` |
| `TenantApplicationFoundation.postgres` | 3 | H1 schema + backfill | `DATABASE_URL` |
| **Total** | **138** | | |

**Security-critical coverage gap assessment:** the four bolded groups (32 tests) cover
fail-closed *durable* semantics — concurrent refresh single-survivor, replay → family
revocation under real row locking, session revocation cascades, DB-unique
`(provider, issuer, subject)` linking, and OTP attempt limiting across instances. All of them
have in-memory contract-test counterparts that DID run green in the 648, so the gap is
**durability-only, not logic**. Required V2-E gate: run every PostgreSQL-gated suite green
against disposable PostgreSQL 16 (the reproducible configuration documented in the V2-C report
§4) **before any activation stage**, and make that a standing gate for each Phase F step.

### 1.4 Flags, behavioral freeze, and credential independence

| Check | Result |
| --- | --- |
| `HAPI_APPLE_FEDERATION_ENABLED` default | ✅ `false` (`FeatureFlagService.ts:43`) |
| `HAPI_GOOGLE_FEDERATION_ENABLED` default | ✅ `false` (`FeatureFlagService.ts:48`) |
| `HAPI_ACCOUNT_LINKING_API_ENABLED` default | ✅ `false` (`FeatureFlagService.ts:53`) |
| (also verified) `HAPI_PERSISTENT_SESSIONS_ENABLED`, `HAPI_REFRESH_GRANT_ENABLED` | ✅ both default `false` |
| HAPI email OTP + Bookwrm SSO unchanged | ✅ all 595 pre-existing V2-B/V2-C tests (incl. `UniversalLogin`, `EmailAuthentication`, `EmailVerification`, OIDC flow suites) pass unchanged inside the 648 |
| Live Apple/Google credentials needed by the suites | ✅ none: federation tests generate synthetic RS256 JWKS with `jose` (`generateKeyPair`/`SignJWT`) and inject the code exchanger; the HTTP exchanger is unreachable unless every provider credential is configured, and none are |

**Phase A verdict: baseline confirmed.** V2-E may proceed on top of `9a2ab06`.

---

## Deliverable 2 — `id.hapiinc.com` readiness report (Phase B)

### 2.1 Current issuer mechanics (audited)

- Issuer resolution order: injected `options.issuer` → `OIDC_ISSUER` env →
  `DEFAULT_ISSUER = "https://identity.bookwrm.com"` (`OIDCService.ts:213`, `resolveIssuer`,
  `ConfigurationService.getOidcIssuer`).
- Discovery, authorize/token/userinfo/jwks URLs are all derived from the resolved issuer —
  already host-correct.
- Nothing in PostgreSQL stores **our** issuer: `identity_subjects.oidc_subject` is
  issuer-independent; `external_identities.provider_issuer` is the *upstream provider's* issuer
  (Apple/Google), untouched by our cutover. Sessions and refresh families carry no issuer column.
- Cookies (`__Host-hapi_sid`, `__Host-hapi_login`) are host-scoped by construction: they cannot
  leak across hosts, and sessions on the old host simply do not exist on the new host
  (users re-authenticate once — benign).

### 2.2 Blockers found (small code changes required before any issuer configuration)

1. **Issuer pin (hard blocker):** `validateDiscoveryConfiguration` throws unless
   `discovery.issuer === DEFAULT_ISSUER` (`OIDCService.ts:1009`). Setting
   `OIDC_ISSUER=https://id.hapiinc.com` today fails discovery validation at boot. Fix: validate
   against the *resolved* issuer (optionally against a configured allowlist). One-line change +
   tests.
2. **CORS origin hardcode:** `CorsPolicy.ts:8` allowlists only `https://identity.bookwrm.com`.
   Must become configuration-driven and include `https://id.hapiinc.com`.
3. **PrivateID webhook hardcode:** `PrivateIDClient.ts:10` pins the webhook callback to
   `https://identity.bookwrm.com/privateid/webhook`. Must derive from the resolved issuer or
   dedicated config.

These three are the complete set of hardcoded-hostname touch points in `src/` (verified by
repository-wide search).

### 2.3 Readiness design (audit + design only; nothing executed)

| Area | Design |
| --- | --- |
| DNS | `id.hapiinc.com` CNAME → Railway edge target for the identity service. TTL ≤ 300 s during transition for fast rollback. No apex/ALIAS needed. |
| TLS | Railway-managed certificate issued on custom-domain attachment; verify full chain + OCSP before any client points at it. Add HSTS (`max-age` ramped: 300 → 86400 → 31536000) only after rollback confidence. |
| Railway custom domain | Attach `id.hapiinc.com` as an additional custom domain on the existing service (coexists with `identity.bookwrm.com`). Domain attach/detach is instant and reversible, independent of code deploys. |
| Discovery + JWKS | Already issuer-derived. After fixing §2.2.1, each host serves discovery with its own issuer value. JWKS served at `${issuer}/jwks` from the same key ring. |
| Endpoints | `/authorize`, `/token`, `/userinfo`, `/jwks`, logout and session endpoints are path-anchored, issuer-derived — no per-endpoint work. |
| Exact issuer/audience validation | Unchanged for upstream providers (Apple/Google verifiers pin *their* issuers). Downstream RPs must validate `iss` exactly; the cutover plan below never serves one issuer value from the other host. |
| Client registration compatibility | RP `redirect_uri`s are RP-side URLs — unaffected by our issuer change. RPs only need the new discovery URL / `iss` value. Apple/Google **provider** redirect URIs are issuer-anchored (`https://id.hapiinc.com/federation/{apple,google}/callback`) — register them only against the new issuer, never the old one. |
| Subject registry continuity | `oidc_subject` values are stable and issuer-independent: the same subject is asserted under the new issuer with an unchanged `sub`. No data migration, no rewrite. |
| Signing-key management | `OIDCKeyRotationService` loads `JWT_PRIVATE_KEY` PEM(s) or an `OIDC_JWKS_JSON` ring; `kid` derived from the public key; Redis-coordinated active-kid rotation (`OIDC_KEY_ROTATION_INTERVAL_SECONDS`, default 3600 s). The same ring may legitimately serve both issuers during coexistence (spec-compliant); recommended hygiene: introduce a fresh key into the ring at cutover so post-cutover tokens are observably distinct, retiring old kids after the longest token lifetime. |
| Historical `(issuer, sub)` binding preservation | RPs that stored `(https://identity.bookwrm.com, sub)` keep working until *that RP* is switched; on switch, only the issuer half changes, `sub` is bit-identical. Recommended RP migration: accept the new issuer, keyed migration `(old_iss, sub) → (new_iss, sub)` in the RP, never a heuristic match. Bookwrm SSO is migrated last, under its own approval. |
| Rollback & coexistence | **Strategy: dual-issuer coexistence via two Railway services** sharing the same code, PostgreSQL, and Redis, differing only in `OIDC_ISSUER` (one per host — the process model is one issuer per process). The legacy service keeps serving `identity.bookwrm.com` unchanged. Rollback at any point = repoint the affected RP back to the legacy discovery URL and/or detach the new domain. No stored data references our issuer, so rollback rewrites nothing. |

**Explicitly NOT done in this phase:** no production issuer switch, no Bookwrm SSO change, no
binding rewrite, no domain attachment. V2-E implementation work here is limited to the three
§2.2 code fixes plus tests, all inert under default configuration.

---

## Deliverable 3 — Session/refresh production certification plan (Phase C)

### 3.1 Scenario coverage audit (existing automated evidence)

| Required scenario | Existing automated coverage |
| --- | --- |
| Browser session establishment/cookie hygiene | `HapiSession.test.ts` — `__Host-` cookie, secret returned exactly once, only hashes persisted |
| Session fixation | `HapiSession.test.ts` — authentication mints a new session and revokes the presented one |
| Logout | `HapiSession.test.ts` — terminal server-side invalidation + cleared cookie; `RefreshTokenRotation.test.ts` — logout/session/device/subject revocation surfaces |
| Account switching | `HapiSession.test.ts` — active-session listings without secret exposure; cross-user isolation |
| Device revocation | `HapiSession.test.ts` (single device, others untouched) + refresh family `device_reference` revocation |
| Token rotation | `RefreshTokenRotation.test.ts` — one-time-use generations, terminal rotation |
| Concurrent refresh | `RefreshTokenRotation.test.ts` — fail-closed, exactly one successor survives |
| Reuse detection | `RefreshTokenRotation.test.ts` — replay revokes the entire family |
| Expired tokens | idle window per generation + absolute family ceiling + session idle/absolute expiry |
| Lost network responses | **fail-closed by design**: if the rotation response is lost and the client retries the consumed token, that is reuse ⇒ family revocation ⇒ interactive re-login. Covered by the replay tests; see §3.3. |

### 3.2 Certification gates (must all pass before `HAPI_REFRESH_GRANT_ENABLED` goes on for any production client)

1. **Durable-semantics gate:** `HapiSession.postgres` (9) + `RefreshTokenRotation.postgres` (10)
   green against PostgreSQL 16 with real connection concurrency (closes the §1.3 gap).
2. **Staging end-to-end gate:** on the staging issuer with `HAPI_PERSISTENT_SESSIONS_ENABLED=on`,
   manually execute the full §3.1 scenario list in a real browser, including: two parallel tabs
   racing one refresh token; mid-flight connection kill between `/token` request and response
   followed by client retry (must revoke family, must recover via interactive login); clock-skew
   check on idle windows.
3. **Load/soak gate:** sustained refresh traffic (≥ 10 rps, 24 h) with zero family-table growth
   anomalies and zero false reuse detections; alerting wired on `refresh_reuse_detected` and
   family-revocation rates.
4. **Review gate:** re-affirm the V2-C security review findings on the deployed configuration
   (hash-only storage, constant-time CSRF, `__Host-` cookies, fail-closed resolution).

### 3.3 Lost-network policy decision (recorded)

Strict one-time rotation is kept: a lost response costs one interactive re-login, never a
security downgrade. Clients must follow the native-readiness refresh discipline (single in-app
refresh mutex, never blind-retry, purge on `invalid_grant`). A server-side "grace reuse window"
is explicitly rejected for V2-E. Monitor family-revocation rates as the UX cost signal.

---

## Deliverable 4 — Apple Developer & Google Cloud configuration checklist (Phase D)

No credentials are requested in chat, stored in the repository, or configured by V2-E planning.
All values live exclusively in Railway environment configuration when the activation tranche is
separately approved. Partial configuration is safe by construction: the provider does not exist
at runtime unless **every** value is present.

### 4.1 Apple Developer (Sign in with Apple)

| # | Item | Resulting configuration |
| --- | --- | --- |
| 1 | App ID (Elite+ iOS bundle) with Sign in with Apple capability | — |
| 2 | **Services ID** (e.g. `com.hapiinc.id`) = OAuth `client_id` | `APPLE_SERVICES_ID` |
| 3 | Sign in with Apple **ES256 key**: create, note Key ID, download `.p8` once | `APPLE_KEY_ID`, `APPLE_CLIENT_SECRET_KEY` |
| 4 | Developer Team ID | `APPLE_TEAM_ID` |
| 5 | Registered return URL (exact, issuer-anchored): `https://id.hapiinc.com/federation/apple/callback` | `APPLE_REDIRECT_URI` |
| 6 | Domain verification for the issuer host | — |
| 7 | (Activation follow-up) server-to-server notification endpoint for revocation events | consumed in a later tranche |

Implementation already certified against this shape: per-exchange ES256 client-secret JWT
(`iss`=team, `sub`=services id, `aud`=`https://appleid.apple.com`, kid header, 5-min TTL), key
never logged/persisted/echoed; `form_post` callback; **private relay** addresses flagged by
claim + domain, displayable but never identity keys.

### 4.2 Google Cloud (OAuth)

| # | Item | Resulting configuration |
| --- | --- | --- |
| 1 | OAuth consent screen (external, production), scopes `openid email profile` | — |
| 2 | Web-application OAuth client | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| 3 | Authorized redirect URI (exact): `https://id.hapiinc.com/federation/google/callback` | `GOOGLE_REDIRECT_URI` |
| 4 | (Activation follow-up) RISC / Cross-Account Protection subscription | consumed in a later tranche |

### 4.3 Protocol behavior already certified (no provider work needed)

- 32-byte server-generated single-use `state` and `nonce` per transaction; state consumed before
  any processing; nonce REQUIRED and constant-time compared.
- Full server-side code exchange; id_token verification: JWKS RS256, exact issuer (both Google
  forms canonicalized), registered audience, expiry, stable `sub` extraction.
- **Revocation:** unlink or provider revocation between code issuance and `/token` ⇒
  `invalid_grant` (link-liveness re-check); push-based revocation (Apple S2S, Google RISC)
  deferred to activation.
- **Explicit linking & recovery:** login never links to an existing subject; linking happens only
  through the authenticated two-step API with 600 s step-up; provider denial/error returns the
  user to the chooser. No email-based matching anywhere.

**Hard rule restated:** no real Apple or Google login is started until separately approved.

---

## Deliverable 5 — Native iOS/Android client registration plan (Phase E)

The V2-D readiness design is adopted unchanged (see the Native-Client Readiness doc for the full
normative text). Registration summary:

| | Elite+ iOS | Elite+ Android |
| --- | --- | --- |
| `client_id` | `hapi-eliteplus-ios` | `hapi-eliteplus-android` |
| Type | public (`token_endpoint_auth_method=none`, **no secret**) | same |
| Grants | `authorization_code` (+ `refresh_token` once Phase F step 2 passes) | same |
| PKCE | S256 enforced (plain rejected platform-wide) | same |
| Redirect URIs (exact) | `https://id.hapiinc.com/native/ios/callback` (Universal Link, primary); `com.hapiinc.eliteplus://oauth/callback` (fallback) | `https://id.hapiinc.com/native/android/callback` (App Link, assetlinks-verified); same custom-scheme fallback |
| Browser context | `ASWebAuthenticationSession` (ephemeral **off**) | Custom Tabs |
| Token storage | Keychain, `AfterFirstUnlockThisDeviceOnly`, no iCloud sync | EncryptedSharedPreferences / Android Keystore (StrongBox where available) |

Verified in V2-D and re-affirmed: the existing `/authorize` + `/token` need **zero changes** —
public client, mandatory PKCE S256, replay and cross-client rejection, exact redirect matching,
60 s code TTL, mandatory nonce, `native_public` refresh lifetimes (14 d sliding / 90 d absolute)
are all green (`NativePublicClientCertification.test.ts`, 6/6 on this branch).

**Base44/Capacitor compatibility (confirmed approach):** the Capacitor app's own WebView NEVER
loads HAPI login. The flow uses the system-browser plugin (`@capacitor/browser`, backed by
`SFSafariViewController`/`ASWebAuthenticationSession` on iOS and Custom Tabs on Android — true
system browser contexts, not embedded WebViews), with the OS delivering the Universal Link /
App Link redirect back to the app (Capacitor `appUrlOpen` listener). This satisfies RFC 8252 §7.3
and Google's WebView login ban, and keeps provider cookies out of the app entirely — the app only
ever receives the final HAPI authorization code.

Prerequisites before registration: issuer host serving `apple-app-site-association` and
`assetlinks.json`; device-lab certification run per the readiness checklist; store-review
parity rule noted (Sign in with Apple must be live in iOS the moment any third-party login
ships there).

---

## Deliverable 6 — End-to-end pilot test scenarios (Phase F test matrix)

Each activation step below is independently flagged, independently gated, and independently
reversible. **Common gate for every step:** full default suite green (648+), all PostgreSQL-gated
suites green against PostgreSQL 16, zero regression in the Bookwrm email/OTP flow, and the
previous steps' monitors quiet for ≥ 72 h.

| Step | Flag / action | Pilot scenario gate (all must pass) | Rollback |
| --- | --- | --- | --- |
| 1. Persistent sessions | `HAPI_PERSISTENT_SESSIONS_ENABLED` | §3.2 gates 1-2; login → close browser → return within idle window resumes; fixation probe fails; logout terminal; cross-user revocation refused | flag off — cookies become inert, rows dormant |
| 2. Refresh rotation | `HAPI_REFRESH_GRANT_ENABLED` (pilot client only) | §3.2 gates 1-4 incl. parallel-tab race, lost-response retry ⇒ family revocation + clean re-login | flag off; families expire naturally |
| 3. Apple federation | `HAPI_APPLE_FEDERATION_ENABLED` | chooser → Apple → `form_post` callback → HAPI code → tokens with `amr=["apple","fed"]`; denial returns to chooser; private-relay email displayed, never keyed; replayed callback rejected; revoked-at-Apple login fails at `/token` | flag off — buttons/routes vanish; linked rows dormant |
| 4. Google federation | `HAPI_GOOGLE_FEDERATION_ENABLED` | same matrix with GET callback; unverified-email account shows no email; **email matching an existing HAPI account still creates a NEW subject after explicit choice (no merge)** | flag off |
| 5. Account linking | `HAPI_ACCOUNT_LINKING_API_ENABLED` | list/link/unlink round-trip; stale session 401; step-up 428 after 600 s; already-linked 409; cross-account 409 without owner disclosure; last-method 409; unlink revokes provider-established sessions + refresh families | flag off — API returns 404-equivalent; audit retained |
| 6. iOS native | register `hapi-eliteplus-ios` | device-lab: Universal Link round-trip, PKCE downgrade rejected, code replay rejected, Keychain storage audit, refresh discipline under airplane-mode toggles | deactivate client registration |
| 7. Android native | register `hapi-eliteplus-android` | same via App Links/Custom Tabs + assetlinks verification; StrongBox storage audit | deactivate client registration |

Recommended execution order: 1 → 2 → **4 (Google first: simpler GET callback)** → 3 → 5 → 6 → 7,
each first on the staging issuer, then production canary via the per-application `EXTERNAL_OIDC`
capability (a natural canary boundary), then general pilot.

**No automatic account merging based on matching email addresses** — restated as an invariant,
and structurally enforced: no code path performs an email-based identity lookup (tested).

---

## Deliverable 7 — Security threats and remaining blockers

Carried forward from V2-D (unchanged, still open for activation):

1. Provider-callback login-CSRF residual: single-use state mitigates; Google GET callback could
   additionally require the interaction cookie; Apple's cross-site `form_post` structurally
   cannot.
2. Push revocation not consumed (Apple S2S, Google RISC) — revocation takes effect at unlink or
   `/token` re-check only.
3. First-login race orphan subject rows (harmless; sweeper recommended).
4. Shared rate-limit buckets on the linking surface — dedicate a tighter `link/complete` bucket
   before activation.
5. No authentication-method management UI (API only).

New findings from this assessment (V2-E scope):

6. **Issuer pin** (`OIDCService.ts:1009`) blocks any non-default issuer — must be fixed before
   `id.hapiinc.com` can even be configured (§2.2.1).
7. **Hardcoded CORS origin** and **PrivateID webhook URL** must become configuration-driven
   (§2.2.2-3).
8. **No CI pipeline exists** — every Phase F gate currently depends on manual local runs.
   A gate runner (even a non-deploying workflow or a documented operator checklist) must execute
   the default suite + PostgreSQL-gated suites per stage. Note: adding GitHub Actions must be
   assessed against the Railway GitHub integration to ensure it cannot trigger a deploy.
9. **PostgreSQL-gated security suites (32 security-critical tests) have never run in a
   production-like environment** — mandatory first gate (§1.3, §3.2.1).
10. Single-process/single-issuer design means coexistence requires a second Railway service
    (or sequential RP cutover) — an operational decision to confirm before Stage B execution.

No new protocol-level vulnerabilities were identified in this read-only assessment.

---

## Deliverable 8 — Exact phased deployment and rollback plan

Every stage requires separate explicit approval before execution. Nothing below is executed by
V2-E planning.

| Stage | Action | Gate | Rollback |
| --- | --- | --- | --- |
| 0 | **Inert code ship**: V2-E fixes (§2.2 issuer-pin/CORS/PrivateID config + tests) merged and deployed with ALL flags off | full suite + PG-gated suites green; production behavior byte-identical (flag-off HTML/discovery unchanged on `identity.bookwrm.com`) | ordinary revert; no schema, no data |
| 1 | **Staging issuer**: second service with `OIDC_ISSUER=https://id-staging.hapiinc.com`; DNS+TLS verified; discovery/JWKS validated | OIDC conformance smoke (discovery, JWKS, full code+PKCE round-trip) | detach domain, delete service |
| 2 | **Sessions + refresh in staging** (Phase F steps 1-2) | §3.2 certification gates | flags off |
| 3 | **Federation in staging** (steps 4 then 3) with staging provider registrations | §4 + Phase F matrices live | flags off; staging provider clients disabled |
| 4 | **Production issuer coexistence**: attach `id.hapiinc.com` to a production service with the new issuer; `identity.bookwrm.com` untouched and still primary for Bookwrm | both discoveries correct simultaneously; key-ring hygiene per §2.3; zero Bookwrm impact for 7 days | detach domain; legacy host never changed |
| 5 | **Production sessions canary** (internal-tester application) | step-1 gate + 72 h quiet monitors | flag off |
| 6 | **Production Google federation canary** (per-application `EXTERNAL_OIDC`), then Apple | step-3/4 gates against live providers; `identity_link_audit` + auth-event + error-rate monitors | flag off (identities become dormant rows) |
| 7 | **Account-linking API in production** (step 5) | step-5 gate | flag off |
| 8 | **Native clients** (steps 6-7): AASA/assetlinks on issuer host, register clients, device lab, store submission | Phase E checklist | deactivate registrations |
| 9 | **Bookwrm SSO issuer migration** (last, separately approved): Bookwrm RP accepts new `iss`, keyed `(old_iss, sub)→(new_iss, sub)` migration, then legacy host enters deprecation | RP dual-accept verified; zero subject drift (sub values bit-identical) | repoint RP to legacy discovery (kept alive until formally retired) |

Universal rollback property: **no stage rewrites data** — rollback is always flag-off, domain
detach, or RP repoint.

---

## Deliverable 9 — Recommended first live integration milestone

**M1: Persistent HAPI sessions + Google federation for one internal-tester application on the
staging issuer (`id-staging.hapiinc.com`)** — i.e. Stages 1-3 above with Google only.

Rationale:

- Exercises the entire new stack (issuer config fix, DNS/TLS, discovery, sessions, federation
  transactions, identity resolution, honest `amr`) with **zero production exposure** and zero
  Bookwrm risk.
- Google before Apple: simpler GET callback, no ES256 client-secret operational dependency, no
  App Store parity obligations triggered.
- Produces the first real-provider evidence for the §3/§4 matrices, which every later production
  stage reuses.
- Its rollback is total (detach staging domain, disable staging OAuth client, flags off).

Prerequisites: Stage 0 inert ship (the three §2.2 fixes), the PostgreSQL-gated suite gate
(§1.3), and separately approved staging Google credentials placed directly into Railway staging
environment configuration.

---

## Compliance statement

This V2-E phase performed read-only assessment and planning only. Confirmed: no push to any
production-deploying branch, no Railway deployment, no issuer migration, no live federation
activation, no modification of any existing HAPI identity, no credential requested or stored.
The working tree contained only this document and remains otherwise clean.
