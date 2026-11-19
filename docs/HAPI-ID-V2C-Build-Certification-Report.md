# HAPI ID V2-C — Build & Certification Report

Date: 2026-11-19
Branch: **`feature/hapi-id-v2c`** (created from `main` at `c0861a8`, the V2-B documentation commit)
Tranche authority: approved HAPI ID V2-C scope (persistent sessions, refresh security, federation
readiness), following the accepted V2-B tranche.

**Deployment constraints honored:** no Railway deployment, no push to any production-deploying
branch, no production database migration, no refresh-grant activation (default-off gate), no live
Apple/Google authentication, no native production OAuth client, no issuer change
(`https://identity.bookwrm.com` untouched; `https://id.hapiinc.com` not introduced), no PrivateID
activation, no automatic account merging, no production identity created or modified.

---

## 1. Phase 0 — repository and release safety findings

1. **Five V2-B commits confirmed** on local `main`, exactly the set `origin/main..main`:
   `4b88e10`, `6490d81`, `01f6398`, `3167f72`, `c0861a8`. Working tree was clean before branching.
2. **Deployment triggers inspected:** the repository contains no CI workflows, `railway.json`,
   `Dockerfile`, `Procfile`, or nixpacks config. Railway deploys via its GitHub integration from
   pushed branches — i.e. **pushing `main` to origin would trigger a production deployment**.
   Consequently nothing was pushed; all V2-C work lives on local branch `feature/hapi-id-v2c`.
3. **V2-B has not reached Railway:** `origin/main` is still `666dc75`, the commit the V2-B report
   §7 verified as deployed (GitHub deployments API + live `/health` uptime back-computation). No
   V2-B or V2-C commit exists on any remote branch.
4. **V2-B migrations remain additive/compatible:** `schema-federation.sql` contains only
   `CREATE TABLE IF NOT EXISTS` / `CREATE [UNIQUE] INDEX IF NOT EXISTS` statements referencing the
   deployed `identity_subjects` table; re-verified by applying the full DDL chain twice against
   fresh PostgreSQL 16 (idempotency assertions in the integration suites).
5. **131 vs 140 test-count reconciliation (empirical):**
   - The 9 tests in `tests/IdentityFederation.postgres.test.ts` run under **both** reported
     configurations because the suite falls back from `HAPI_FEDERATION_TEST_DATABASE_URL` to
     `DATABASE_URL` (`tests/IdentityFederation.postgres.test.ts:14`).
   - **131** = 27 (DATABASE_URL suites) + 104 (dedicated-env isolated suites) — double-counts
     those 9 federation tests once.
   - **140** = 9 (standalone federation run) + 27 + 104 — counts them a third time.
   - **Unique PostgreSQL-gated tests at the V2-B baseline: 122** (27 + 104 − 9).
   - Reproduced on this machine (disposable PostgreSQL 16 in Docker): DATABASE_URL set → 27/27;
     dedicated-env set → 104/104. The reproducible configuration is documented in §4.
   - Known pre-existing constraints re-verified unchanged at `c0861a8`:
     `SchemaVersioning.postgres` fails on a **fresh** database (its first statement `DELETE FROM
     schema_migrations` precedes bootstrap) and passes on a bootstrapped one; the
     `TenantApplicationFoundation` afterAll cleanup fails (FK) when sharing one database with
     `IdentityRegistry.postgres` in one process. Neither affects production code and both
     reproduce identically with V2-C stashed.

## 2. V2-C commits and files

| Commit | Content |
| --- | --- |
| `2e3a6a4` | Phases 1–2: persistent HAPI sessions + rotating refresh-token families + gated refresh grant |
| `ddfda81` | Phase 3: server-only Apple OIDC verification component |
| `cbf91d0` | Phase 4: authenticated account-linking API design document |
| (this commit) | Phase 5/deliverables: this certification report |

### New schemas (additive, idempotent; applied by `ensureIdentitySchema` in order)

| File | Content |
| --- | --- |
| `src/identity/schema-sessions.sql` | `hapi_sessions` — hashed session + CSRF secrets, client context, authentication context (`authentication_method`, `authenticated_at`), device metadata, independent `idle_expires_at`/`absolute_expires_at` (DB-checked `idle <= absolute`), terminal status transitions, unique `token_hash`. |
| `src/identity/schema-refresh.sql` | `refresh_token_families` + `refresh_tokens` — exactly the approved V2-B design plus `session_id`/`device_reference` association columns; partial unique index enforcing **one active generation per family**; unique `token_hash`. |

Schema version bumped to **1.2.0** ("Persistent HAPI sessions and refresh-token families (V2-C)");
versions 1.0.0/1.1.0 rows are preserved and recorded exactly once (idempotent bootstrap re-tested).

### New services and files

| File | Role |
| --- | --- |
| `src/models/HapiSession.ts`, `src/models/RefreshTokenFamily.ts` | Domain types + secret-free `HapiSessionView`. |
| `src/identity/sessions/HapiSessionRepository.ts` (+ `Postgres…`, `InMemory…`) | Session system of record: hash-only lookup, DB-side `LEAST()` absolute ceiling on touch, terminal revocation, fail-closed cross-subject revocation (`FOR UPDATE`). |
| `src/identity/sessions/HapiSessionService.ts` | Policy layer: `__Host-hapi_sid` HttpOnly/Secure/SameSite=Lax cookie, 32-byte secrets (hash-only persistence), CSRF double-submit (constant-time), fixation supersession, idle (30 d) + absolute (90 d) expiry, logout, per-device/per-subject revocation, account-selection listings, recent-authentication step-up check. |
| `src/oidc/refresh/RefreshTokenFamilyRepository.ts` (+ `Postgres…`, `InMemory…`) | Family system of record: atomic consume+mint rotation in one transaction, same-transaction family revocation on reuse, partial-unique-index fail-closed concurrency, revocation by family/token/subject/session/device. |
| `src/oidc/refresh/RefreshTokenRotationService.ts` | Policy layer: `hrt_`-prefixed 32-byte opaque tokens, approved lifetimes (native 14 d sliding / 90 d absolute; confidential 24 h / 30 d), typed error contract, RFC 7009-style revocation. |
| `src/identity/federation/AppleIdentityTokenVerifier.ts` | Phase 3 verifier (see §6) + `toAppleLinkRequest`. |
| `src/config/FeatureFlagService.ts` | `HAPI_PERSISTENT_SESSIONS_ENABLED`, `HAPI_REFRESH_GRANT_ENABLED` — both default **false**. |
| `src/oidc/OIDCService.ts` | Gated `grant_type=refresh_token` handler; gated family issuance at code exchange; conditional `grant_types_supported`. Gate-off behavior byte-identical to V2-B (regression-proven). |
| `docs/HAPI-ID-V2C-Account-Linking-API-Design.md` | Phase 4 deliverable. |

New tests: `tests/HapiSession.test.ts` (14), `tests/HapiSession.postgres.test.ts` (9),
`tests/RefreshTokenRotation.test.ts` (12), `tests/RefreshTokenRotation.postgres.test.ts` (10),
`tests/AppleIdentityTokenVerifier.test.ts` (12), `tests/OIDCRefreshGrant.test.ts` (10) = **67**.

## 3. Security certification matrix (Phase 5)

| Requirement | Proven by |
| --- | --- |
| Session fixation | `HapiSession.test.ts` "protects against session fixation" + PG lifecycle test — authentication always mints a new secret and revokes the presented one. |
| Session expiry (idle + absolute) | Idle terminal-expiry test; absolute-ceiling test (activity never extends past ceiling; DB `LEAST()` proven in PG suite). |
| Logout | Server-side terminal revocation + cleared `Max-Age=0` cookie; idempotent re-logout. |
| Cross-user session isolation | In-memory + PG "fails closed when a subject tries to revoke another subject's session" (`wrong_subject`, no existence oracle); `revokeAllForSubject` never crosses subjects. |
| CSRF | Double-submit token, constant-time hash comparison; cookie alone can never authorize state changes. |
| Refresh rotation + replay | One-time consumption; replay → whole-family revocation (`reuse_detected`) in the same transaction (PG-proven); successor dead after replay. |
| Concurrent refresh races | PG true-concurrency test: at most one successor ever exists; losers fail closed (`invalid_grant`). Documented explicit behavior: serialized losers observe the consumed token and trigger family revocation — clients MUST NOT blindly retry refreshes. |
| Wrong client / subject / family | `client_mismatch` rejects without consuming; unknown/foreign tokens `invalid_grant`; subject lifecycle binding revokes families of non-ACTIVE subjects at the endpoint. |
| Session/device revocation | Per-device, per-session (cascade to families via `session_id`), per-subject revocation surfaces tested in-memory + PG. |
| Apple valid/invalid tokens | §6 matrix — 12 synthetic-key tests. |
| Account-linking conflicts / duplicate external identities | Verified-Apple→federation tests: duplicate provider identity → `conflict` (owner never revealed); idempotent re-link; explicit relink-after-unlink. |
| Last-method unlink rejection | Re-certified via V2-B suites (federation 13 + 9 PG) which all still pass. |
| No secret leakage | Hash-only persistence asserted against raw rows (sessions + refresh); error bodies asserted not to echo token material; raw secrets exist only in return values/cookies; no logging of token values anywhere in new code. |
| Existing HAPI email OTP + Bookwrm OIDC preservation | Full default suite unchanged and green; gate-off refresh behavior byte-identical (exact V2-B error body + legacy refresh token asserted). |

## 4. Full test results (reproducible configuration)

Environment: Node v24, Vitest 4.1.10, disposable PostgreSQL 16 (Docker, fresh databases),
`npx tsc --noEmit` and `npm run build` clean (build copies both new `.sql` files to `dist/`).

| Run | Command | Result |
| --- | --- | --- |
| Full default suite | `npx vitest run` (no DB env) | **64 files / 595 tests passed, 0 failed** (138 DB-gated tests skipped by design) — V2-B baseline was 60/547/119, re-verified before changes |
| DATABASE_URL set | `DATABASE_URL=… IDENTITY_REGISTRY_DRIVER=postgres npx vitest run tests/{SchemaVersioning,TenantApplicationFoundation,IdentityRegistry,IdentityClaimProvenance,IdentityFederation,HapiSession,RefreshTokenRotation}.postgres.test.ts --no-file-parallelism` against a **bootstrapped** database (run `ensureIdentitySchema` once first — pre-existing SchemaVersioning constraint, §1.5) | **46/46 passed** |
| Dedicated-env isolated set | `HAPI_{AUTHENTICATION,EMAIL,FACE_ENROLLMENT,REGISTRATION,FEDERATION,SESSIONS,REFRESH}_TEST_DATABASE_URL=… npx vitest run` over the 9 isolated-schema suites, fresh DB | **123/123 passed** |

Totals: 595 default + 169 PostgreSQL-configuration runs (46 + 123, of which 19 + 19 are the new
V2-C integration tests and 9 federation tests appear in both sets by design). V2-C adds **67**
tests; every pre-existing test passes unchanged.

## 5. Session and refresh-token threat model

**Assets:** HAPI session secrets (browser cookies), refresh tokens (client storage), the
identity-subject binding they represent.

| Threat | Mitigation |
| --- | --- |
| Session/refresh theft from the database (SQL injection, backup leak, insider) | Only SHA-256 hashes stored; possession of the database never yields usable credentials. |
| Cookie theft via XSS | `HttpOnly` cookie (script-unreadable); CSRF token is per-session and hash-verified, so markup injection cannot mint one. |
| Cookie theft via network | `Secure` + `__Host-` prefix (never sent over HTTP, host-locked, Path=/). |
| CSRF | SameSite=Lax + mandatory double-submit CSRF token on state changes, constant-time comparison. |
| Session fixation | Secrets are only ever minted server-side at authentication; any presented pre-auth session is revoked in the same establishment step. |
| Indefinite session lifetime | Sliding idle window hard-capped by a database-enforced absolute ceiling (`LEAST()`, CHECK constraint). |
| Stolen refresh token replayed | One-time consumption; replay of a consumed generation revokes the entire family transactionally and forces interactive re-authentication for everyone (OAuth 2.1 response). |
| Attacker races the legitimate client | Row locks + partial unique index: at most one active generation can ever exist; losers fail closed with `invalid_grant`. |
| Token issued to client A redeemed by client B | Family is client-bound; mismatch rejects without consuming; confidential clients additionally re-authenticate with their secret on every refresh. |
| Locked/disabled account keeps refreshing | Endpoint revokes the family (`subject_locked`) whenever the subject is not ACTIVE. |
| Device lost / user signs out | Per-device, per-session and per-subject revocation surfaces; session revocation cascades to associated refresh families. |
| Secrets in logs | Raw values never logged; typed error codes only; error bodies tested not to echo token material; audit rows carry hashes. |
| Future-activation hazard (V2-B §1 risk 4) | Legacy Redis tokens remain non-redeemable: the gated refresh handler consults only the family store, so a pre-existing legacy token can never be replayed into the new grant. |

**Residual risks (documented):** a serialized concurrent refresh (e.g. network retry) presents a
consumed token and therefore destroys the family — strict by design; client integration docs must
mandate single-flight refresh. Session cookies are bearer secrets within their TTL on a fully
compromised browser; device-bound sessions (DPoP/TLS token binding) are out of scope for V2-C.

## 6. Apple federation verification results (Phase 3)

Component: `AppleIdentityTokenVerifier` — server-only, not wired to any route, no Apple
credentials required (synthetic JWKS injected for tests; remote JWKS URL used only if ever
constructed without one, which no wired code does).

| Requirement | Outcome (synthetic-key tests, 12/12 green) |
| --- | --- |
| Exact Apple issuer validation | ✅ `https://appleid.apple.com` only; lookalike issuer → `wrong_issuer` |
| JWKS key + signature verification | ✅ RS256-only; rogue-key signature → `invalid_signature`; non-RS256 rejected |
| Audience validation | ✅ must match a registered client context; others → `wrong_audience` |
| Nonce validation | ✅ mandatory, constant-time; mismatch/absent/empty-expectation → `nonce_mismatch` |
| Expiration validation | ✅ expired → `token_expired`; `exp` required by jose verification |
| Subject validation | ✅ missing/empty `sub` → `missing_subject` |
| Apple private relay handling | ✅ flagged via `is_private_email` (string-boolean normalized) **and** `@privaterelay.appleid.com` domain; relay addresses never participate in identity keying |
| Provider-identity uniqueness | ✅ verified identity → federation layer: second subject → `conflict`, owner never revealed; same-email different-subject tokens never link accounts |
| Revocation/relinking policy | ✅ unlink frees the provider identity; relinking is explicit-only (tested); V2-B last-method protection intact |
| No production surface | ✅ no route, no sign-in button, no real provider identity, no live JWKS fetch in any wired path |

## 7. Backward-compatibility assessment for Bookwrm

- **Gate-off (production default) behavior is byte-identical to V2-B**, asserted by tests:
  `/token` rejects `refresh_token` grants with the exact V2-B error body; discovery advertises
  only `authorization_code`; the legacy Bookwrm confidential client still receives its legacy
  Redis-stored refresh token at code exchange; the full pre-existing suite (547 tests) passes
  unchanged.
- Persistent sessions are additive and unwired: no existing flow reads or sets the new cookie.
- Schema 1.2.0 is purely additive (new tables/indexes only); boot-time `ensureIdentitySchema`
  remains idempotent — verified by double-application and by re-running every pre-existing
  PostgreSQL suite against the extended DDL chain.
- With the gate **on** (future): the Bookwrm client's observable change is that its refresh token
  becomes redeemable and rotating. The authorization-code response shape is unchanged (tested).
  Activation still requires the §8 plan.

## 8. Production deployment dependencies and rollback plan

**This tranche does not deploy.** Shipping V2-B+V2-C later requires, in order:

1. Push gate: explicit approval to push to the Railway-connected branch (`main`); nothing else in
   this repo triggers deployment.
2. Database compatibility check: confirm the deployed database accepts the additive 1.1.0+1.2.0
   DDL (it is applied automatically and idempotently at boot); take a Railway PostgreSQL snapshot
   first.
3. Regression gate: full default suite + both PostgreSQL configurations green at the release SHA.
4. Config gate: `HAPI_PERSISTENT_SESSIONS_ENABLED` and `HAPI_REFRESH_GRANT_ENABLED` unset/false in
   Railway → deployed behavior identical to `666dc75` + V2-B policy changes already certified.
5. Post-deploy verification: discovery unchanged (`grant_types_supported=["authorization_code"]`),
   `/health/ready` green, schema version reports `1.2.0`.

**Rollback:** redeploy the previous image/commit (Railway deployment history). The additive tables
are inert under old code (no old code path references them), so no schema rollback is required;
if ever desired, `DROP TABLE refresh_tokens, refresh_token_families, hapi_sessions` is safe while
both flags are off. Flag activation rollback is config-only (unset the flag): issued family tokens
simply stop being redeemable, which is fail-safe.

**Refresh-grant activation (separate, later approval)** additionally requires: client integration
docs (single-flight refresh requirement), registration of the target client with the
`refresh_token` grant, monitoring on `reuse_detected` revocations, and an RFC 7009 `/revoke`
endpoint (designed, not yet implemented).

## 9. Proposed V2-D implementation scope (requires separate approval)

1. **Controlled V2-B+V2-C deployment to Railway** under the §8 gates (flags off).
2. **Account-linking HTTP surface** implementing
   `docs/HAPI-ID-V2C-Account-Linking-API-Design.md` behind default-off
   `HAPI_ACCOUNT_LINKING_API_ENABLED`, wiring `HapiSessionService` (session + CSRF + step-up) and
   the provider verifiers; Google ID-token verifier sibling of the Apple one.
3. **RFC 7009 `/revoke` endpoint** over `RefreshTokenRotationService.revokePresentedToken`,
   plus a background expiry sweep for families/generations/sessions.
4. **Session issuance wiring** into Universal Login behind
   `HAPI_PERSISTENT_SESSIONS_ENABLED` (establish on successful email-OTP/face authentication;
   account selection on `/authorize` re-entry), with full regression gating of existing flows.
5. **Refresh-grant staged activation plan** for the first native Elite+ client (development
   client first; no production client until the V2-D certification passes).

Explicitly out of scope without further approval: issuer migration to `https://id.hapiinc.com`,
live Apple/Google credentials, PrivateID changes, automatic merging of any kind.
