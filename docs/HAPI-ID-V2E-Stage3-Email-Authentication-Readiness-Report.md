# HAPI ID V2-E Stage 3 — Staging Email Authentication Readiness Report

**Status: READINESS REVIEW COMPLETE — CONDITIONAL GO for one staging-only controlled email
authentication test, pending the operator prerequisites in §9 and separate written approval.**

Everything in this report was produced by read-only inspection, external synthetic probes, and
isolated tests against a disposable local PostgreSQL 16 container. No Railway variable was
changed, no email login was enabled, no OTP message was sent, no code was deployed, no identity
was migrated, and production was not modified. No secret value appears in this report.

- Review date: 2026-11-19 (≈20:07–20:25 UTC)
- Staging issuer: `https://id-staging.hapiinc.com` (Railway project `charismatic-charm`,
  deployed SHA `787e73a774e3044cad6c17b8b1917a4c02ba0bc7`)
- Production issuer: `https://identity.bookwrm.com` (untouched; re-verified §1.6)

---

## 1. Phase A — Datastore-isolation evidence

External, read-only evidence only; no Railway CLI or `RAILWAY_TOKEN` exists in this workspace, so
Railway-side configuration itself could not be read (see §1.7).

| # | Requirement | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Staging PostgreSQL only in `charismatic-charm` | **SUPPORTED (external)** | Bidirectional client-registry separation proven live: `client_id=staging-web` at **production** `/authorize` → `400 invalid_client "Unknown client"`; `client_id=bookwrm-web` at **staging** `/authorize` → `400 invalid_client "Unknown client"`. The two services demonstrably read different `oidc_clients` data. Staging `/health/ready` reports `databaseConnected: true`. Direct plugin-scoping evidence requires Railway access (§1.7). |
| 2 | Staging Redis only in `charismatic-charm` | **SUPPORTED (external)** | Staging `/health/ready` reports `redisInitialized: true`. Namespace/instance scoping is not externally observable; Railway evidence outstanding (§1.7). Defense-in-depth regardless of store topology: `recordIssuerAccepted()` ([src/config/IssuerPolicy.ts](../src/config/IssuerPolicy.ts)) binds every stored authorization code / access token to its minting issuer, so artifacts cannot cross environments even through a hypothetically shared store. |
| 3 | No shared production DB, credential, or Redis namespace | **SUPPORTED (external)** | Same probes as #1 plus disjoint JWKS (#5). No production client, key, or identity is visible on staging. |
| 4 | Issuer pinned to `https://id-staging.hapiinc.com` | **PASS** | Live discovery `issuer` is exactly the staging origin. Code-level: `enforceDeploymentIssuerPin()` runs at boot ([src/server.ts](../src/server.ts) line 39) and **fails closed** unless `OIDC_ALLOWED_ISSUERS` contains exactly the one non-default issuer and `CORS_TRUSTED_ORIGINS` is explicit — the running service could not have booted mis-pinned. |
| 5 | Staging JWT keys distinct from production | **PASS** | Staging kid `rsa-1-Wm7qR81Kn_g9it6q` vs production kid `rsa-1-DOCW-KVBmBo4vKFr`; moduli compared cryptographically — the workspace `public_key.pem` matches **staging** JWKS and does **not** match production JWKS. ⚠️ See §8 finding F1: the matching staging **private** key is present in this shared workspace. |
| 6 | Production Bookwrm health/discovery unchanged | **PASS** | `--preflight` re-run 8/8 PASS at 20:14 UTC: discovery byte-identical to the committed Stage 1 baseline, grants `["authorization_code"]`, JWKS unchanged, gated endpoints 404, `/health` 200. No new production deployments (`fulfilling-spirit` latest remains `666dc75`, 2026-11-16). |

Also confirmed on staging right now: `/login`, `/login/email`, `/register`, and the email
authentication API all return 404 — email authentication and Universal Login are fully OFF, the
exact expected pre-Phase-D posture. `/health/ready` shows `dependencies.base44: "degraded"`,
consistent with the staging Identity-API stub (no production upstream configured).

### 1.7 Outstanding operator evidence
Diagnostics endpoints are service-key protected (no unauthenticated config exposure — correct
posture), and this workspace has no Railway access. To close items 1–3 fully, provide any one of:
(a) Railway dashboard evidence that the PostgreSQL and Redis plugins are attached only to
`charismatic-charm`; (b) a redacted variable listing showing staging `DATABASE_URL`/`REDIS_URL`
hosts differ from production and `OIDC_REDIS_NAMESPACE=oidc-staging`; or (c) a read-scoped
`RAILWAY_TOKEN` for direct verification. **Do not paste connection strings.**

## 2. Phase B — PostgreSQL 16 durability results

Run against a disposable local `postgres:16` (16.16) Docker container with per-run random
schemas — no live staging identity records were touched; the container was destroyed afterwards.

| Suite | Mode | Executed | Passed | Failed | Skipped |
| --- | --- | --- | --- | --- | --- |
| `HapiSession.postgres` | PG16 integration | 9 | 9 | 0 | 0 |
| `RefreshTokenRotation.postgres` | PG16 integration | 10 | 10 | 0 | 0 |
| `EmailAuthentication.postgres` | PG16 integration | 24 | 24 | 0 | 0 |
| `HapiSession`, `RefreshTokenRotation`, `NonceAndRefreshTokenPolicy`, `OIDCRefreshGrant`, `EmailAuthentication`, `UniversalLogin`, `UniversalLoginPages` | in-memory unit/regression | 109 | 109 | 0 | 0 |
| **Total** | | **152** | **152** | **0** | **0** |

Required invariants directly certified by named passing tests:
- **Atomic token-family rotation** — "rotates atomically: consumed generation is terminally
  rotated, exactly one successor is active"; "enforces at most one active generation per family at
  the database level"; "fails closed under true concurrent refresh".
- **Reuse detection** — "revokes the whole family in the same transaction when a consumed token is
  replayed".
- **Session expiry** — "caps the sliding idle window at the absolute ceiling inside the database
  (LEAST)"; "expires a family terminally once its absolute lifetime has passed".
- **Revocation** — "makes revocation terminal"; "fails closed when a subject tries to revoke
  another subject's session"; "associates families with sessions and cascades session revocation".
- **Email auth durability** — single-use OTP results, concurrent-verification races, transactional
  rollback of consumption + result issuance, 60-second result expiry, exact
  client/tenant/application binding.

Durability is certified. **This does not recommend activating persistent sessions or the refresh
grant** — both stay OFF in Phase D; the suites prove the foundations are sound for a later stage.

## 3. Phase C — Email/OIDC activation readiness

### 3.1 Exact feature flags / env required (staging service only)
From [EmailVerificationComposition.ts](../src/adapters/email/EmailVerificationComposition.ts) and
[OIDCService.ts](../src/oidc/OIDCService.ts):

| Variable | Value | Why |
| --- | --- | --- |
| `HAPI_EMAIL_PROVIDER` | `resend` | Only supported provider; absent today, so all email routes are 404. Composition fails closed on any other value. |
| `HAPI_EMAIL_VERIFICATION_SECRET` | fresh staging-only secret | Required by `VerificationSecrets`; boot fails without it. |
| `RESEND_API_KEY` | staging-only Resend key | Required by `ResendEmailDeliveryProvider`; boot fails without it. |
| `HAPI_EMAIL_FROM` | verified staging sender | Required; must belong to a Resend-verified sending domain. |
| `HAPI_EMAIL_AUTHENTICATION_ENABLED` | `true` | Gates H4 authentication + the `POST /authorize` email handoff; boot fails if `true` without `HAPI_EMAIL_PROVIDER`. |
| `HAPI_UNIVERSAL_LOGIN_ENABLED` | `true` | Gates the browser journey: `GET /authorize` → 302 `/login` → email OTP pages. Without it, GET /authorize still falls through to the Face path (today's 403 DENIED). |
| `RESEND_WEBHOOK_SECRET` | optional | Delivery-event webhook (svix-signed); not required for the test. |

OTP policy defaults ([VerificationPolicy.ts](../src/email/VerificationPolicy.ts)): 6-digit code,
600 s expiry, 5 attempts, 60 s resend cooldown, 10 sends/destination/hour — adequate; no override
needed. **Everything else stays unchanged**: `HAPI_PERSISTENT_SESSIONS_ENABLED=false`,
`HAPI_REFRESH_GRANT_ENABLED=false`, Apple/Google/account-linking/face flags false,
`PRIVATEID_MOCK_MODE=true`. Session-cookie establishment after login is independently gated by
`isPersistentSessionsEnabled()` (`maybeEstablishSession`), so no session cookie will be set.

### 3.2 Staging-only email sender
A **staging-dedicated Resend account/API key** with a verified sending domain is required (none
exists in this workspace; production Resend credentials are not approved and must not be used).
Verifying a domain for staging requires its DNS records in the `hapiinc.com` zone (operator step).

### 3.3 Test inbox
No reachable test inbox is available from this workspace. One controlled mailbox must be provided
for the single approved synthetic identity (recommended:
`stage3-test-001@staging-test.hapiinc.com` if that domain can receive mail, or any mailbox the
operator controls). The OTP arrives by real email; it must never be pasted into chat.

### 3.4 Browser-facing callback / test relying party
`staging-app.hapiinc.com` is **NXDOMAIN** — the registered redirect URI has no live host. A full
RP is **not required**: the final step is a server-side 303 redirect to
`https://staging-app.hapiinc.com/callback?code=…&state=…`, so the browser lands on a DNS error
page **with code and state intact in the address bar**. The tester captures them there and
completes token exchange out-of-band with `curl`. (Optionally, a minimal static callback host can
be stood up later for nicer UX; not a Phase D prerequisite.)

### 3.5 Can `staging-web` complete the full flow?
**Yes.** Two certified paths, both using the existing client — **no new client or redirect URI is
needed**:
- **Path 1 (recommended, browser / Universal Login):** `GET /authorize` (PKCE S256 + nonce) → 302
  `/login` → `POST /login/email` (sends OTP) → `POST /login/email/code` (verifies OTP; brand-new
  emails are handled inline as REGISTRATION, creating the one synthetic staging identity) → 303
  redirect with `code` → `POST /token` (`client_secret_basic` + `code_verifier`) → ID token +
  access token → `GET /userinfo`.
- **Path 2 (scriptable, no browser):** H2/H3 APIs to register the synthetic identity
  (`/v1/verification/*`, `/v1/registration/complete`), then H4
  `POST /v1/authentication/email/{start,verify}` → `authentication_result` → `POST /authorize` →
  JSON `{redirectUri}` containing the code → `POST /token`. All of these endpoints authenticate the
  client with HTTP Basic (confidential clients only), which `staging-web` satisfies.

The seeded `staging-native` (public, `token_endpoint_auth_method=none`) could complete Path 1
without any secret, but its custom-scheme redirect is less convenient; `staging-web` is preferred.

### 3.6 Client secret handling (confidential token exchange)
Yes — `staging-web` is `client_secret_basic`, so `/token` (and Path 2's APIs) require the secret.
Plan: the operator retrieves it from wherever the seed value was stored when
`seed-staging-clients.sql` ran (or directly from the staging `oidc_clients` row via a trusted
psql session) and injects it into the test shell **as an environment variable only** —
never in chat, never in git, never in logs; transmitted only inside TLS Basic auth headers to the
staging host. The secret is **not rotated** for this test.

### 3.7 Exact rollback procedure
1. In Railway `charismatic-charm`, set `HAPI_EMAIL_AUTHENTICATION_ENABLED=false` and
   `HAPI_UNIVERSAL_LOGIN_ENABLED=false`, and remove `HAPI_EMAIL_PROVIDER`, `RESEND_API_KEY`,
   `HAPI_EMAIL_FROM`, `HAPI_EMAIL_VERIFICATION_SECRET`, `RESEND_WEBHOOK_SECRET`. Redeploy the same
   SHA `787e73a`.
2. Verify restored posture: `/login`, `/register`, `/v1/authentication/email/*` all 404 again, and
   re-run `--staging-approved` expecting exactly the Stage 2 result shape (0 FAIL,
   `staging.authorize.pkce` back to **DENIED** 403).
3. Optionally delete the synthetic identity row from staging PostgreSQL (staging-only data; may
   also be retained for Stage 3 continuation).
4. Production requires no rollback action at any point — it is never touched.

## 4. Phase D — planned acceptance tests (post-approval; not executed)

**Positive:** full Path 1 round-trip with the one approved identity; ID token verified locally
against **staging JWKS only** (exact `iss=https://id-staging.hapiinc.com`, `aud=staging-web`,
`nonce` echo, stable `sub`, sane `exp/iat`); `GET /userinfo` with the provider-issued access token
returns the matching subject; harness re-run with `STAGING_ID_TOKEN` set converts
`staging.idtoken.verify`/`cross-jwks`/`iss` and `staging.synthetic-auth` to PASS.

**Negative:** second redemption of the same code → `invalid_grant` (replay); exchange with the
wrong client (`staging-native` credentials/identity) → rejected; wrong `code_verifier` →
`invalid_grant`; staging access token at **production** `/userinfo` → 401; staging ID token
verified against production JWKS **locally** → must fail (key isolation). Production→staging live
token rejection remains structurally NOT-TESTED: no synthetic production token can exist (production
has no enabled login method for synthetic identities) and transmitting a real user's production
token is prohibited; store separation + `recordIssuerAccepted` issuer binding + the Stage 2
garbage-bearer 401 remain the certified evidence.

**Phase E checks:** production preflight 8/8 before/after; exactly one new staging identity
(subject count delta = 1, no duplicates — uniqueness also DB-enforced and test-certified);
no `Set-Cookie` session establishment (flag off); staging discovery grants still
`["authorization_code"]`; gated endpoints still 404 on both services; no new production clients;
Bookwrm SSO `/health` + discovery unchanged.

## 5–8. Findings

- **F1 (security, remediate before Phase D):** the live **staging private signing key**
  (`private_key.pem`, with matching `public_key.pem`) is present in this shared, non-sandboxed
  development workspace. It is gitignored and was never committed, and it is **not** the
  production key — but anyone with workspace access could mint "staging-valid" tokens, which would
  undermine Phase D's ID-token provenance claims. Recommendation: generate a fresh staging keypair
  directly in Railway (or rotate via `OIDC_JWKS_JSON`), redeploy, confirm the new kid at
  `/jwks`, and delete both PEM files from this workspace. (Key material was not modified or moved
  by this review, per instruction.)
- **F2 (informational):** staging `/health/ready` reports `base44: "degraded"` — expected with the
  staging Identity-API stub; confirm it does not block registration completion during Phase D.
- **F3 (informational):** enabling `HAPI_UNIVERSAL_LOGIN_ENABLED` changes the Stage 2
  `staging.authorize.pkce` expectation from DENIED/403 to a 302 → `/login`; the certification
  harness already treats 302 as PASS.

## 9. Remaining blockers (all operator-side)

| # | Blocker | Owner |
| --- | --- | --- |
| B1 | Staging-only Resend API key + verified sending domain (`HAPI_EMAIL_FROM`) | Operator |
| B2 | One controlled, reachable test inbox for the approved synthetic identity | Operator |
| B3 | Secure provisioning of the `staging-web` secret to the test shell (env var only) | Operator |
| B4 | F1 remediation: rotate the staging signing key out of this workspace | Operator |
| B5 | Railway variable changes of §3.1 (this review changed none) | Operator (approval gate) |
| B6 | Direct Railway datastore-scoping evidence (§1.7) | Operator |

## 10. GO/NO-GO recommendation

**CONDITIONAL GO.** Code paths, protocol enforcement, durability invariants (152/152 tests), issuer
pinning, key disjointness, client-registry separation, and rollback are all certified or verified.
Nothing discovered argues against a single staging-only controlled email authentication test. The
GO becomes effective once B1–B5 are complete (B6 strongly recommended, and required before any
Stage 3 persistent-session activation) and you give the separate written Phase D approval. Until
then, nothing is activated and staging remains in its certified Stage 2 posture.
