# HAPI ID V2-E Stage 2 — Staging Deployment Certification Report

**Status: CERTIFIED — STAGE 2 PASSED (0 FAIL).**
All checks were external, read-only, and synthetic-only, using the approved no-bearer-token
harness. No real credentials or bearer tokens were transmitted in either direction. Nothing was
provisioned, deployed, seeded, or mutated by this certification. Production Railway configuration,
DNS, and the live `identity.bookwrm.com` service are untouched and were independently re-verified
as unchanged (§6).

This report supersedes the 2026-11-19 17:07–17:10 UTC FAILED report (staging issuer then
unreachable). All three prior FAILs — `staging.unreachable`, missing staging DNS, and unverifiable
deployed SHA — are now remediated and re-certified below.

- Certification date: 2026-11-19 (≈19:57–20:03 UTC)
- Branch: `release/hapi-id-staging`
- Pinned SHA: `787e73a774e3044cad6c17b8b1917a4c02ba0bc7` (verified: `origin/release/hapi-id-staging` resolves to exactly this commit)
- Staging issuer: `https://id-staging.hapiinc.com`
- Harness: `scripts/certify-staging-oidc.mjs` (`--preflight`, then the approved
  `--staging-approved` mode with `STAGING_CLIENT_ID=staging-web` and its registered redirect URI
  `https://staging-app.hapiinc.com/callback`; no `STAGING_ID_TOKEN`, consistent with the
  no-bearer-token policy)

---

## 1. Deployed Git SHA verification (PASS — previously FAIL)

| Check | Result | Evidence |
| --- | --- | --- |
| Railway deployment of `787e73a` | **PASS** | GitHub deployments API now lists environment **`charismatic-charm / production`** (the Railway staging project) with `ref=787e73a774e3044cad6c17b8b1917a4c02ba0bc7` — exactly the pinned `release/hapi-id-staging` SHA. Deployment id `7923286866`, created `2026-11-19T19:16:10Z`, latest status **`success`** at `2026-11-19T19:52:51Z`. |
| Service freshness consistent with deployment | **PASS** | Staging `GET /health` uptime ≈ 2 759 s at 20:02 UTC — process start ≈ 19:16 UTC, matching the deployment timestamp. |
| Production trigger unchanged | **PASS** | The production environment `fulfilling-spirit / production` has no new deployments (latest remains `666dc75` from `main`, 2026-11-16). The staging SHA was never deployed to production. |

## 2. Staging DNS / TLS / health (PASS — previously FAIL)

| Check | Result | Evidence |
| --- | --- | --- |
| DNS `id-staging.hapiinc.com` | **PASS** | Authoritative GoDaddy nameservers now serve `CNAME id-staging.hapiinc.com → 6hqjo46p.up.railway.app` (TTL 3600), resolving to A `153.52.255.55`. The prior NXDOMAIN is remediated (P1/P2 complete). |
| TLS | **PASS** | Valid certificate `CN=id-staging.hapiinc.com`, issuer Let's Encrypt (`YR1`), valid 2026-11-19 → 2027-02-17. Full verification also exercised by `fetch()` in the harness (`staging.tls` PASS). |
| `GET /health` | **PASS** | HTTP 200, `{"status":"alive","service":"Bookwrm Identity Services","version":"6A.1"}`. |
| Canonical issuer `id.hapiinc.com` | **PASS (constraint upheld)** | Still does not resolve — the canonical issuer has **not** been migrated, as required. |

## 3. Harness execution results

### 3.1 `--preflight` (production, read-only) — 8 PASS / 0 FAIL

```
✅ prod.discovery.issuer      issuer=https://identity.bookwrm.com
✅ prod.discovery.grants      grant_types_supported=["authorization_code"] (refresh OFF)
✅ prod.discovery.baseline    byte-identical to committed Stage 1 baseline
✅ prod.jwks                  kids=rsa-1-DOCW-KVBmBo4vKFr
✅ prod.gated./federation/apple/start   -> 404
✅ prod.gated./federation/google/start  -> 404
✅ prod.gated./account/links            -> 404
✅ prod.gated./session                  -> 404
ℹ️ dns.staging    id-staging.hapiinc.com: resolves (153.52.255.55)
ℹ️ dns.canonical  id.hapiinc.com: does not resolve
```

### 3.2 `--staging-approved` (approved mode, synthetic-only) — 23 PASS / 0 FAIL / 1 DENIED / 4 NOT-TESTED

Exit code 0. Full result set (production preflight re-ran green inside this run; staging-side
results below):

```
✅ staging.tls                          TLS handshake + certificate verification succeeded via fetch
✅ staging.discovery.issuer             issuer=https://id-staging.hapiinc.com
✅ staging.discovery.endpoints          authorization/token/userinfo/jwks all on the staging host
✅ staging.discovery.grants             grant_types_supported=["authorization_code"] (all five flags OFF)
✅ staging.jwks                         kids=rsa-1-Wm7qR81Kn_g9it6q
✅ staging.jwks.disjoint                no staging kid appears in the production JWKS
🚫 staging.authorize.pkce               fully validated (client, redirect_uri, PKCE S256, nonce) then 403 —
                                        no authentication method enabled (EXPECTED posture)
✅ staging.authorize.redirect-exact     unregistered redirect_uri -> HTTP 400, never redirected to attacker URI
✅ staging.authorize.pkce-required      authorize without code_challenge -> HTTP 400
✅ staging.userinfo.foreign-bearer      malformed bearer at /userinfo -> HTTP 401 (infrastructure probe only)
✅ staging.cors.rejects-production-origins  Origin https://bookwrm.com -> ACAO (absent)
✅ staging.cors.allows-staging-origin   Origin https://id-staging.hapiinc.com -> ACAO=https://id-staging.hapiinc.com
✅ staging.gated./federation/apple/start   -> 404
✅ staging.gated./federation/google/start  -> 404
✅ staging.gated./account/links            -> 404
✅ staging.health                       GET /health -> 200
⏸️ staging.idtoken.verify               NOT-TESTED (needs staging-minted synthetic ID token; post email activation)
⏸️ cross.staging-token-at-prod          NOT-TESTED (no bearer tokens transmitted cross-environment, by policy)
⏸️ cross.prod-token-at-staging          NOT-TESTED (no bearer tokens transmitted cross-environment, by policy)
⏸️ staging.synthetic-auth               NOT-TESTED (requires an enabled authentication method)
ℹ️ staging.code.cross-issuer            issuer binding certified in tests/MultiIssuerConfiguration.test.ts
Summary: 23 pass, 0 fail, 1 expected-denial, 4 not-tested, 0 manual, 0 skipped
```

## 4. OAuth client recognition (PASS)

The seeded synthetic client `staging-web` is recognized and fully validated by the staging
authorization endpoint:

- A complete authorize request (`client_id=staging-web`, exact registered redirect URI, `scope=openid`,
  `state`, `nonce`, `code_challenge` with `S256`) passed **all** validation and was then
  intentionally refused with HTTP 403 solely because no authentication method is enabled —
  recorded as **DENIED**, the expected posture until email-authentication activation. An unknown
  or unseeded client would have failed validation with 400, not reached the 403 denial.
- Redirect-URI enforcement is exact: `https://attacker.example/callback` → HTTP 400 with **no**
  redirect to the attacker origin.
- PKCE is mandatory: omitting `code_challenge` → HTTP 400.

## 5. Key and origin isolation (PASS)

| Check | Result | Evidence |
| --- | --- | --- |
| JWKS present on staging | **PASS** | Single kid `rsa-1-Wm7qR81Kn_g9it6q`. |
| JWKS disjoint from production | **PASS** | Production kid `rsa-1-DOCW-KVBmBo4vKFr`; zero overlap — staging-only signing key confirmed (P4 key requirement). |
| CORS rejects production origins | **PASS** | `Origin: https://bookwrm.com` → no `access-control-allow-origin` header. |
| CORS allows staging origin | **PASS** | `Origin: https://id-staging.hapiinc.com` echoed back exactly. |
| Feature gates disabled | **PASS** | `grant_types_supported=["authorization_code"]` only (refresh OFF); `/federation/apple/start`, `/federation/google/start`, `/account/links` all 404 on staging. |

## 6. Production unchanged (PASS)

| Check | Result | Evidence |
| --- | --- | --- |
| Discovery byte-identical to Stage 1 baseline | **PASS** | `prod.discovery.baseline` PASS in both harness runs. |
| Refresh grant off | **PASS** | `grant_types_supported=["authorization_code"]`. |
| Gated V2 endpoints absent | **PASS** | Apple/Google federation, account links, `/session` all 404. |
| JWKS unchanged | **PASS** | Single kid `rsa-1-DOCW-KVBmBo4vKFr` (identical to Stage 1). |
| Health / no restart | **PASS** | `GET /health` → 200, version `6A.1`, uptime ≈ 271 551 s (≈ 3.1 days) — no restart or redeploy across the entire Stage 2 window, including the staging deployment event. |
| No new production deployments | **PASS** | `fulfilling-spirit / production` latest deployment remains `666dc75` (2026-11-16). |

## 7. Consolidated Stage 2 result matrix

**PASS (29 total: 23 harness + 6 external)**
- Production preflight — 8/8 harness checks (both runs).
- Staging TLS, discovery issuer, endpoint hosts, grants posture.
- Staging JWKS present + disjoint from production.
- Exact redirect-URI enforcement; mandatory PKCE S256.
- Malformed-bearer 401 at `/userinfo` (infrastructure probe only).
- CORS: production origins rejected, staging origin allowed.
- Gated V2 endpoints 404 on staging; staging `/health` 200.
- External: branch/SHA pin integrity; Railway deployment of `787e73a` verified `success`;
  staging DNS + certificate; canonical issuer not migrated; production deployments/health
  unchanged.

**FAIL (0)**

**DENIED — expected, by design (1)**
1. `staging.authorize.pkce` — fully validated authorize request for `staging-web` intentionally
   refused with HTTP 403 because no authentication method is enabled. This is the **required**
   Stage 2 posture and is the positive signal of OAuth client recognition (§4).

**NOT-TESTED — deferred by design, per the no-bearer-token policy (4)**
1. `staging.idtoken.verify` (+ cross-JWKS rejection + iss check) — requires a staging-minted
   synthetic ID token; possible only after email-authentication activation.
2. `cross.staging-token-at-prod` — live cross-issuer rejection; deferred to positive
   authentication certification.
3. `cross.prod-token-at-staging` — ditto; `staging.userinfo.foreign-bearer` (PASS) is an
   infrastructure-only probe and is never counted as cross-issuer evidence.
4. `staging.synthetic-auth` — synthetic registration/login ceremony; requires an enabled
   authentication method.

**Outstanding operator evidence (not harness-observable; carried to Stage 3 gate)**
- PostgreSQL/Redis independence: Railway/operator evidence of dedicated staging plugins
  (distinct hosts from production `DATABASE_URL`/`REDIS_URL`) and
  `OIDC_REDIS_NAMESPACE=oidc-staging`. Indirect positives observed (staging-only JWKS kid and a
  seeded `staging-web` client absent from production), but direct datastore evidence remains a
  Stage 3 prerequisite.

**Constraints honored:** no code deployed, no credentials modified, no authentication methods
enabled, no production changes; email OTP, Apple, Google, persistent sessions and refresh grants
remain off; no production identities created; the canonical issuer was not migrated; PrivateID was
not activated.

## 8. Stage 2 verdict

**Stage 2 is CERTIFIED.** The green criteria defined in the prior report (§7 P6) are met exactly:
zero FAIL; `staging.authorize.pkce` recorded as DENIED (expected posture); live-authentication
items recorded as NOT-TESTED; production preflight 8/8 in both runs.

## 9. Stage 3 (persistent-session activation) — exact prerequisites

Stage 3 may not begin until every item below holds:

1. **Stage 2 green: ✅ COMPLETE** (this report).
2. **Verified deployment identity: ✅ COMPLETE** — `charismatic-charm` runs
   `release/hapi-id-staging` @ `787e73a` (deployment `7923286866`, `success`); production trigger
   is still `main` only. Re-verify immediately before Stage 3 begins.
3. **Datastore independence certified: ⏳ OUTSTANDING** — operator/Railway evidence of dedicated
   staging PostgreSQL and Redis plugins (distinct hosts from production
   `DATABASE_URL`/`REDIS_URL`), plus `OIDC_REDIS_NAMESPACE=oidc-staging`.
4. **Email-authentication activation approval (staging only): ⏳ OUTSTANDING** — explicit approval
   to enable `HAPI_EMAIL` OTP for the `hapi-staging-app` application using synthetic
   `*@staging-test.hapiinc.com` identities only; then execute the synthetic registration + login
   ceremony and re-run the harness with `STAGING_ID_TOKEN` set, converting
   `staging.idtoken.verify`, `staging.idtoken.cross-jwks`, `staging.idtoken.iss` and
   `staging.synthetic-auth` from NOT-TESTED to PASS (including rejection of the staging token by
   the production JWKS), and converting `staging.authorize.pkce` from DENIED to PASS.
5. **Session suite green: ⏳ OUTSTANDING** — `HapiSession.postgres` passing against a
   staging-grade PostgreSQL 16 (`RefreshTokenRotation.postgres` is NOT part of Stage 3).
6. **Explicit flag approval: ⏳ OUTSTANDING** — separate written approval to set
   `HAPI_PERSISTENT_SESSIONS_ENABLED=true` **in the staging environment only**. All other V2 flags
   (Apple, Google, account linking, refresh grants) remain off; production flags remain untouched.
7. **Post-activation invariants: ⏳ DEFINED** — staging `/session` becomes live with
   `__Host-`-prefixed, host-scoped cookies (no `Domain=` attribute); production `/session` must
   still return 404 and production discovery must remain byte-identical to the committed baseline.
