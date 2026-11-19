# HAPI ID V2-E Stage 3 — Final Activation Preparation Build Report

**Status: BUILD CERTIFIED — all Stage 3 preparation deliverables built and verified; blocker B4
(staging signing-key rotation) confirmed REMEDIATED live. Staging remains in its certified
pre-activation posture. Phase D live execution still requires operator prerequisites B1–B3 + B5
and the separate written approval.**

Everything in this report was produced from committed workspace code, read-only external probes,
and isolated verification against a disposable local PostgreSQL 16 container (created and
destroyed within this session). No Railway variable was changed, no email login was enabled, no
OTP was sent, no code was deployed, no identity was created or migrated, and production was not
modified. No secret value appears in this report.

- Build/report date: 2026-11-19 (≈22:59–23:05 UTC)
- Build commit: `0dc1cdb` — *feat: V2-E Stage 3 staging rotation script + email auth
  certification harness* (working tree clean; nothing uncommitted)
- Staging issuer: `https://id-staging.hapiinc.com` (Railway `charismatic-charm`)
- Production issuer: `https://identity.bookwrm.com` (untouched)
- Predecessor: [Stage 3 Email Authentication Readiness Report](./HAPI-ID-V2E-Stage3-Email-Authentication-Readiness-Report.md)
  (CONDITIONAL GO, blockers B1–B6)

---

## 1. Scope — what this build delivers

This build closes every *workspace-side* gap between the Stage 3 CONDITIONAL GO and a runnable
Phase D controlled test. Three deliverables, all in commit `0dc1cdb`:

| # | Deliverable | File | Purpose |
| --- | --- | --- | --- |
| D1 | Leak-safe staging client-secret rotation | [`scripts/rotate-staging-web-secret.sql`](../scripts/rotate-staging-web-secret.sql) | Enables B3 (secure secret provisioning): the operator can rotate `staging-web` to a fresh secret known only to the secret manager and the test shell, without the value ever reaching argv, files, chat, git, or PostgreSQL server logs. |
| D2 | Stage 3 Phase D live-test harness | [`scripts/stage3-email-auth-test.mjs`](../scripts/stage3-email-auth-test.mjs) | Deterministic, scripted execution of the entire approved Phase D acceptance matrix (positive + negative) with a strict no-secret-output policy. |
| D3 | Production hardening requirement record | [`docs/Production-Hardening-Hashed-Client-Secrets.md`](./Production-Hardening-Hashed-Client-Secrets.md) | Records hashed-at-rest OAuth client credentials as an OPEN production requirement discovered during D1 design (plaintext `oidc_clients.client_secret`), explicitly out of scope for staging certification. |

No `src/` runtime code changed in this build; the deployed staging/production services are
behaviorally identical to the Stage 2–certified build.

## 2. D1 — `rotate-staging-web-secret.sql` design + verification

### 2.1 Design summary
- **Secret format verified against source:** `oidc_clients.client_secret` is stored as
  **plaintext**; all three comparison sites (`OIDCService.ts` `/token`,
  `H1ClientAuthority.ts`, `routes/registration.ts`) hash only for constant-time equality.
  A direct plaintext `UPDATE` is therefore the exact correct mechanism (writing a hash would
  break authentication). The at-rest weakness is recorded separately as D3.
- **Three-phase leak-safety:** PostgreSQL logs the full text of any erroring statement
  (`log_min_error_statement='error'` default), so (Phase 1) every fail-closed guard runs with
  **no secret present**; (Phase 2) the secret travels environment → `\getenv` psql variable →
  one session-local GUC — never argv, never a file, never echoed; (Phase 3) the mutation block
  references the secret only via `current_setting()`, so no failable statement's text ever
  contains it. The session GUC is `RESET` before disconnect.
- **Fail-closed guards (Phase 1, secret-free):** refuses when `log_statement` ∈ {`all`,`mod`},
  `log_min_duration_statement ≠ -1`, or `pg_stat_statements.track_utility=on`; refuses any
  database containing a non-staging OIDC client or the `BOOKWRM` application, or missing the
  active `hapi-staging` tenant; refuses if `staging-web` deviates from the certified Stage 2
  shape (confidential, `client_secret_basic`, PKCE required, exact redirect URI, grants
  `["authorization_code"]`, active) or `staging-native` is not a public client.
- **Phase 3 invariants:** re-acquires `staging-web` `FOR UPDATE` and re-validates; requires a
  generated secret ≥ 32 chars (placeholder-pattern rejected); asserts exactly 1 row updated;
  proves `staging-native` byte-identical afterward; emits only length + an 8-char md5
  fingerprint for out-of-band confirmation. Any `RAISE` rolls the whole mutation back.
- **Rollback:** re-run with the previous secret from the operator secret manager; nothing else
  changes.

### 2.2 Verification (re-executed this session, disposable PostgreSQL 16.16 container)
Schemas applied from `src/`, clients seeded via the committed
[`scripts/seed-staging-clients.sql`](../scripts/seed-staging-clients.sql); container destroyed
afterwards. All six cases behaved exactly as designed:

| # | Case | Expected | Result |
| --- | --- | --- | --- |
| T1 | `NEW_STAGING_WEB_SECRET` unset | Fail closed on a **secret-free** syntax error (`:'new_secret'` unexpanded + `ON_ERROR_STOP`); no change | **PASS** — secret fingerprint unchanged |
| T2 | Secret too short (`tooshort`) | Fail closed: "missing or not a generated value of at least 32 characters"; no change | **PASS** |
| T3 | Valid 48-char generated secret | Rotated; NOTICE fingerprint equals the locally computed md5-8 fingerprint; `staging-native` untouched | **PASS** — fingerprints matched (`909e4636` = `909e4636`); `staging-native.updated_at` byte-identical |
| T4 | Idempotent re-run (same secret) | NOTICE "unchanged (idempotent re-run)", same fingerprint; `staging-native` untouched | **PASS** |
| T5 | Database with `BOOKWRM` application (production-like) | Fail closed before any mutation | **PASS** — "BOOKWRM application present … this is not the staging database" (and a database merely *missing* `hapi-staging` also failed closed) |
| T6 | `log_statement='all'` on the target database | Fail closed before the secret-bearing `SET` | **PASS** — "log_statement=all would write the secret to server logs" |

## 3. D2 — `stage3-email-auth-test.mjs` coverage map

Syntax-validated (`node --check` clean); **not executed live** — it hard-refuses without
`--staging-live-approved`, which maps to the separate written Phase D approval. Universal Login
is *not* used or required: the harness drives Path 2 (direct-API H4 + JSON `POST /authorize`
handoff), so `HAPI_UNIVERSAL_LOGIN_ENABLED` can stay `false` for the controlled test.

Fail-closed preconditions: exact issuer pin (`https://id-staging.hapiinc.com` only),
`STAGING_CLIENT_SECRET` ≥ 32 chars from the environment only (refuses if the secret appears in
argv), valid `STAGING_TEST_EMAIL`. Secrecy policy: OTPs are typed at a hidden raw-mode prompt and
never echoed; client secret, authorization codes, `authentication_result`, access and ID tokens
are never printed.

Mapping to the Phase D acceptance matrix defined in the readiness report (§4):

| Readiness §4 requirement | Harness check(s) |
| --- | --- |
| Discovery/issuer/grants posture | `discovery.issuer`, `discovery.grants` (`["authorization_code"]` exactly) |
| Client-secret validity without consuming an OTP | `secret.accepted` (correct secret + random evidence → 400) / `secret.rejected` (wrong secret → 401) |
| Synthetic identity creation (one approved identity) | flag-gated `--register-identity` H2/H3 round (`register.start/verify/complete`) — **required on a fresh registry** because H4 email authentication never creates identities (`PostgresEmailAuthenticationRepository.establish` has no registration path); re-run is idempotent H3 Case B |
| Full positive round-trip | `auth.start` → hidden-OTP `auth.verify` → `auth.authorize` (PKCE S256, nonce, state echo, registered redirect prefix) → `token.exchange` → `userinfo` (sub + email match) |
| `authentication_result` 60 s TTL | `auth.verify.ttl` asserts `expiresIn === 60` exactly |
| No session establishment (flags off) | `auth.authorize.no-cookie`, `token.no-cookie` (no `Set-Cookie` anywhere) |
| No refresh grant | `token.no-refresh` (no `refresh_token` in the response) |
| ID-token validation against **staging JWKS only** | `idtoken.verify` (local verify: iss, aud), `idtoken.alg` (RS256), `idtoken.nonce`, `idtoken.sub`, `idtoken.times` |
| Key isolation (negative, **local only**) | `negative.idtoken.cross-jwks` — staging ID token must fail against production JWKS locally; production JWKS is fetched but **no staging artifact is ever sent to production** |
| `authentication_result` single-use | `negative.result-replay` (second `POST /authorize` with the same result → 4xx, no redirectUri) |
| Authorization-code replay | `negative.code-replay` (→ 400 `invalid_grant`) |
| Wrong `code_verifier` | flag-gated `negative.wrong-verifier` (second OTP round; → 400 `invalid_grant`; code consumed by the rejection — expected) |
| Garbage bearer at userinfo | `negative.userinfo.garbage-bearer` (→ 401) |

Exit code is non-zero on any FAIL, so the harness output is directly usable as Phase D
certification evidence.

## 4. Blocker status update (readiness report §9)

| # | Blocker | Status |
| --- | --- | --- |
| B1 | Staging-only Resend key + verified sending domain | **OPEN** (operator) |
| B2 | Controlled, reachable test inbox | **OPEN** (operator) |
| B3 | Secure provisioning of the `staging-web` secret | **TOOLING COMPLETE (D1)** — operator executes the verified rotation, keeping the value in the secret manager + test-shell environment only |
| B4 | F1 remediation: rotate the staging signing key out of this workspace | **REMEDIATED — verified live** (§5) |
| B5 | Railway variable changes (readiness §3.1) | **OPEN** (operator approval gate; this build changed none) |
| B6 | Direct Railway datastore-scoping evidence | **OPEN** (operator; strongly recommended, required before any persistent-session activation) |

## 5. B4/F1 remediation — live verification

- Staging `/jwks` now serves kid **`rsa-1-OXX7VucDdDJvBUEB`** — the compromised-exposure kid
  `rsa-1-Wm7qR81Kn_g9it6q` from the readiness report is gone. Tokens signed with the old
  workspace-exposed key can no longer verify against staging.
- **No `private_key.pem` / `public_key.pem` exists in this workspace** any more (and neither was
  ever committed; the git tree at `0dc1cdb` is clean).
- Production `/jwks` still serves exactly **`rsa-1-DOCW-KVBmBo4vKFr`** — unchanged, and disjoint
  from the new staging kid (key isolation preserved).
- Staging service redeployed recently (uptime ≈ 1.9 h at probe time) and fully healthy:
  `/health/ready` → `ready`, `databaseConnected: true`, `redisInitialized: true`,
  `keysLoaded: true` (`base44: "degraded"` — expected staging stub, informational F2).

## 6. Staging/production posture re-verification (read-only, this session)

| Check | Result |
| --- | --- |
| Staging discovery `issuer` | **PASS** — exactly `https://id-staging.hapiinc.com` |
| Staging `grant_types_supported` | **PASS** — `["authorization_code"]` only |
| Staging `/login`, `/login/email`, `/register` | **PASS** — all 404 (email auth + Universal Login still fully OFF; certified Stage 2 posture intact) |
| Production JWKS | **PASS** — single kid `rsa-1-DOCW-KVBmBo4vKFr`, unchanged |

## 7. Build + regression certification

Run this session at commit `0dc1cdb`:

| Validation | Result |
| --- | --- |
| `npm run build` (tsc + schema asset copy) | **PASS** — clean compile |
| `node --check scripts/stage3-email-auth-test.mjs` | **PASS** |
| Full in-memory vitest suite | **677 passed, 0 failed** (70 files; 138 skipped = PG-gated suites without a database, by design) |
| `HapiSession.postgres` (PG 16.16 integration) | **9/9 passed** |
| `RefreshTokenRotation.postgres` (PG 16.16 integration) | **10/10 passed** |
| `EmailAuthentication.postgres` (PG 16.16 integration) | **24/24 passed** |
| D1 rotation verification matrix (§2.2) | **6/6 as designed** |

All PostgreSQL verification used a disposable local `postgres:16` (16.16) container with no
connection to any live environment; the container and both scratch databases were destroyed at
the end of the session.

## 8. Remaining path to Phase D activation

1. Operator completes B1 (staging Resend key + verified sender) and B2 (controlled inbox).
2. Operator rotates the `staging-web` secret with D1 against the staging database and places the
   new value in the secret manager + test-shell environment (closes B3 operationally).
3. Operator applies the readiness §3.1 Railway variables to `charismatic-charm` only
   (`HAPI_EMAIL_PROVIDER=resend`, `HAPI_EMAIL_VERIFICATION_SECRET`, `RESEND_API_KEY`,
   `HAPI_EMAIL_FROM`, `HAPI_EMAIL_AUTHENTICATION_ENABLED=true`; `HAPI_UNIVERSAL_LOGIN_ENABLED`
   may remain `false` for the harness-driven Path 2 test) and redeploys (B5 — approval gate).
4. With the separate written Phase D approval, run:
   `STAGING_CLIENT_SECRET=… STAGING_TEST_EMAIL=… node scripts/stage3-email-auth-test.mjs
   --staging-live-approved --register-identity --negative-verifier`
5. Execute the readiness §3.7 rollback and Phase E before/after checks (production preflight,
   subject-count delta = 1, gated endpoints restored to 404).
6. B6 (Railway datastore-scoping evidence) remains strongly recommended now and **required**
   before any later persistent-session activation.

## 9. Conclusion

**BUILD CERTIFIED.** The Stage 3 final-activation toolkit is complete, committed, and verified:
the rotation script is leak-safe and fail-closed under all six tested failure modes, the Phase D
harness covers the entire approved acceptance matrix with a strict no-secret-output policy, the
workspace key-exposure finding (F1/B4) is remediated and live-verified, regression suites are
green (677 + 43 PG16, 0 failures), and both environments remain exactly in their certified
pre-activation posture. The CONDITIONAL GO from the readiness report stands, now gated only on
operator-side prerequisites B1–B3 + B5 and the separate written Phase D approval.
