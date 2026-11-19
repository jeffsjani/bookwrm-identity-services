# HAPI ID V2-E Stage 2 — Staging Deployment Certification Report

**Status: CERTIFICATION FAILED — STAGING ISSUER UNREACHABLE AND DEPLOYMENT UNVERIFIABLE.**
All checks were external, read-only, and synthetic-only. No real credentials or bearer tokens were
transmitted in either direction. Nothing was provisioned, deployed, seeded, or mutated. Production
Railway configuration, DNS, and the live `identity.bookwrm.com` service are untouched and were
independently re-verified as unchanged (§5).

- Certification date: 2026-11-19 (17:07–17:10 UTC)
- Expected branch: `release/hapi-id-staging`
- Expected SHA: `787e73a774e3044cad6c17b8b1917a4c02ba0bc7`
- Expected staging issuer: `https://id-staging.hapiinc.com`
- Harness: `scripts/certify-staging-oidc.mjs` at the expected SHA (`--preflight`, then the
  approved `--staging-approved` mode with `STAGING_CLIENT_ID=staging-web` and its registered
  redirect URI; no `STAGING_ID_TOKEN`, consistent with the no-bearer-token policy)

---

## 1. Source integrity (PASS)

| Check | Result | Evidence |
| --- | --- | --- |
| Branch pin | **PASS** | `origin/release/hapi-id-staging` resolves to exactly `787e73a774e3044cad6c17b8b1917a4c02ba0bc7`. |
| Expected content at SHA | **PASS** | `787e73a` is the Stage 2 commit (harness corrections + fail-closed `scripts/seed-staging-clients.sql`); parents are the Stage 1 (`d60cc71`) and Stage 0 (`d0f9a6e`) commits. |
| Synthetic client definitions (static) | **PASS** | Seed defines exactly `staging-web` (confidential, `client_secret_basic`, `require_pkce`, redirect `https://staging-app.hapiinc.com/callback`, grants `{authorization_code}`) and `staging-native` (public, `none`, `require_pkce`, redirect `com.hapi.staging:/callback`), under tenant `hapi-staging` / application `HAPI_STAGING` with methods exactly `{HAPI_EMAIL}`; all drift paths RAISE (fail closed); staging-only and weak-secret guards present. |

## 2. Deployed Git SHA verification (FAIL — no verifiable deployment evidence)

| Check | Result | Evidence |
| --- | --- | --- |
| Railway deployment of `787e73a` | **FAIL (unverifiable)** | GitHub deployments API for this repository lists **only** `fulfilling-spirit / production` across its entire history (latest: 2026-11-16, `666dc75` lineage from `main`). There are **zero** deployment events for SHA `787e73a` or ref `release/hapi-id-staging`. No `hapi-id-staging` project/environment has ever reported a deployment. |
| Railway-side evidence from this workspace | **FAIL (unavailable)** | No Railway CLI and no `RAILWAY_TOKEN` exist in this workspace, so the `hapi-id-staging` project cannot be queried directly. The running service also could not be probed for its build (host unreachable, §3). |

The deployed-SHA requirement therefore **cannot be certified**. If the `hapi-id-staging` project
was deployed without the GitHub integration reporting deployments, the evidence must be supplied
(see prerequisites P3, §7).

## 3. Staging DNS / TLS / health (FAIL)

| Check | Result | Evidence |
| --- | --- | --- |
| DNS `id-staging.hapiinc.com` | **FAIL** | **NXDOMAIN at the authoritative nameservers.** Both Google DoH and Cloudflare DoH independently return `Status: 3` with the `hapiinc.com` SOA (`ns01.domaincontrol.com` / GoDaddy, serial `2026100400`) for A and CNAME queries. This is an authoritative "record does not exist", not a propagation delay (negative TTL 600 s). The custom-domain CNAME was never created. |
| TLS | **NOT-TESTED** | Blocked: no DNS record, so no TLS endpoint exists to verify. |
| `GET /health` | **NOT-TESTED** | Blocked: `curl` fails with "Could not resolve host". |
| Canonical issuer `id.hapiinc.com` | **PASS (constraint upheld)** | No A/CNAME record — the canonical issuer has **not** been migrated, as required. |
| `hapiinc.com` zone | **INFO** | Zone is live (A `216.24.57.1`), so the missing staging record is a zone-content gap, not a zone outage. |

## 4. Harness execution results

### 4.1 `--preflight` (production, read-only) — 8 PASS / 0 FAIL

```
✅ prod.discovery.issuer      issuer=https://identity.bookwrm.com
✅ prod.discovery.grants      grant_types_supported=["authorization_code"] (refresh OFF)
✅ prod.discovery.baseline    byte-identical to committed Stage 1 baseline
✅ prod.jwks                  kids=rsa-1-DOCW-KVBmBo4vKFr
✅ prod.gated./federation/apple/start   -> 404
✅ prod.gated./federation/google/start  -> 404
✅ prod.gated./account/links            -> 404
✅ prod.gated./session                  -> 404
ℹ️ dns.staging    id-staging.hapiinc.com: does not resolve
ℹ️ dns.canonical  id.hapiinc.com: does not resolve
```

### 4.2 `--staging-approved` (approved mode, synthetic-only) — aborted fail-closed

```
❌ staging.unreachable — staging certification aborted: ENOTFOUND
Summary: 8 pass, 1 fail, 0 expected-denial, 0 not-tested, 0 manual, 0 skipped   (exit 1)
```

The harness never reached the staging service, so **no staging-side check could execute**.

## 5. Production unchanged (PASS)

| Check | Result | Evidence |
| --- | --- | --- |
| Discovery byte-identical to Stage 1 baseline | **PASS** | `prod.discovery.baseline` PASS in both harness runs. |
| Refresh grant off | **PASS** | `grant_types_supported=["authorization_code"]`. |
| Gated V2 endpoints absent | **PASS** | Apple/Google federation, account links, `/session` all 404. |
| JWKS unchanged | **PASS** | Single kid `rsa-1-DOCW-KVBmBo4vKFr` (identical to Stage 1). |
| Health | **PASS** | `GET /health` → 200, version `6A.1`, uptime ≈ 3 days (no restart/redeploy since the Stage 1 observation window). |

## 6. Consolidated Stage 2 result matrix

**PASS (6)**
1. Branch/SHA pin integrity of `release/hapi-id-staging` (§1).
2. Static synthetic-client configuration at the pinned SHA (§1).
3. Canonical issuer `id.hapiinc.com` not migrated (§3).
4. Production preflight — 8/8 harness checks (§4.1).
5. Production health and uptime continuity (§5).
6. Production JWKS/discovery/flag posture unchanged (§5).

**FAIL (3)**
1. `staging.unreachable` — `ENOTFOUND` for `id-staging.hapiinc.com` in the approved certification run (§4.2).
2. Staging DNS — authoritative NXDOMAIN at the GoDaddy nameservers; custom-domain record absent (§3).
3. Deployed-SHA verification — no Railway deployment evidence for `787e73a` on any environment; no Railway access from this workspace (§2).

**DENIED (0)**
- None recorded. The expected `staging.authorize.pkce` DENIED (fully validated request refused
  because no authentication method is enabled) **could not be observed** — the service is
  unreachable, which is a FAIL, not an expected denial. Nothing is misreported as DENIED.

**NOT-TESTED (blocked by unreachable staging — 11)**
1. `staging.tls` — TLS handshake/certificate.
2. `staging.discovery.issuer` — exact issuer `https://id-staging.hapiinc.com`.
3. `staging.discovery.endpoints` — authorization/token/userinfo/jwks hosts.
4. `staging.discovery.grants` — `["authorization_code"]` only (five flags off).
5. `staging.jwks` + `staging.jwks.disjoint` — staging keys distinct from production.
6. `staging.authorize.*` — PKCE S256 enforcement, exact redirect-URI enforcement, expected 403 denial.
7. `staging.gated.*` — federation/account-linking endpoints 404 on staging.
8. `staging.cors.*` — production-origin rejection / staging-origin allowance.
9. `staging.userinfo.foreign-bearer` — malformed-bearer 401 (infrastructure probe).
10. `staging.health` — staging `/health` 200.
11. PostgreSQL/Redis independence — requires a reachable service plus operator/Railway evidence of
    separate plugins, distinct `DATABASE_URL`/`REDIS_URL` hosts, and `OIDC_REDIS_NAMESPACE=oidc-staging`.

**NOT-TESTED (deferred by design, per the Stage 2 token-transmission policy — 3)**
1. `staging.idtoken.verify` / cross-JWKS rejection — requires a staging-minted synthetic ID token (post email activation).
2. `cross.staging-token-at-prod` and `cross.prod-token-at-staging` — live cross-issuer token rejection (positive authentication stage).
3. `staging.synthetic-auth` — synthetic registration/login ceremony (requires an enabled authentication method).

**Constraints honored:** email OTP, Apple, Google, persistent sessions and refresh grants were not
activated; no production identities were created; Railway production configuration was not changed;
the canonical issuer was not migrated; PrivateID was not activated.

## 7. Remediation — exact prerequisites to re-run Stage 2 to green

- **P1 — Custom domain:** in the Railway `hapi-id-staging` project, attach `id-staging.hapiinc.com`
  to the staging service; Railway will issue a CNAME target (`*.up.railway.app`).
- **P2 — DNS record:** in the GoDaddy `hapiinc.com` zone, create `CNAME id-staging` → that target.
  Authoritative negative-cache TTL is 600 s; Railway then provisions the Let's Encrypt certificate.
- **P3 — Deployment evidence:** make the deployed SHA externally verifiable by any one of:
  (a) connecting the Railway GitHub integration so `hapi-id-staging` deployments appear in the
  GitHub deployments API with `ref=release/hapi-id-staging`; (b) providing a read-scoped
  `RAILWAY_TOKEN` in the certification workspace; or (c) supplying the Railway dashboard deployment
  record showing commit `787e73a` on `release/hapi-id-staging`.
- **P4 — Environment:** confirm the service env matches `.env.staging.example`
  (`OIDC_ISSUER`/`OIDC_ALLOWED_ISSUERS` exactly the staging issuer, explicit
  `CORS_TRUSTED_ORIGINS`, staging-only `DATABASE_URL`/`REDIS_URL`,
  `OIDC_REDIS_NAMESPACE=oidc-staging`, freshly generated staging-only signing key). The Stage 1
  boot pin refuses to serve otherwise.
- **P5 — Client seed:** run `scripts/seed-staging-clients.sql` against the staging PostgreSQL only,
  with `__STAGING_WEB_SECRET__` replaced by a generated ≥32-char secret.
- **P6 — Re-run:** `node scripts/certify-staging-oidc.mjs --preflight`, then
  `STAGING_ISSUER=https://id-staging.hapiinc.com STAGING_CLIENT_ID=staging-web`
  `STAGING_REDIRECT_URI=https://staging-app.hapiinc.com/callback node scripts/certify-staging-oidc.mjs --staging-approved`.
  Green = 0 FAIL, with `staging.authorize.pkce` recorded as **DENIED** (expected posture) and the
  live-authentication items as **NOT-TESTED**.

## 8. Stage 3 (persistent-session activation) — exact prerequisites

Stage 3 may not begin until every item below holds:

1. **Stage 2 green:** a `--staging-approved` run against `https://id-staging.hapiinc.com` with
   zero FAIL, the authorize probe recorded as DENIED, JWKS disjointness PASS, CORS isolation PASS,
   gated endpoints 404, and production preflight still 8/8 (§7 P1–P6 complete).
2. **Verified deployment identity:** Railway evidence that the staging service runs
   `release/hapi-id-staging` at the approved SHA (P3), and that the production service trigger is
   still `main` only.
3. **Datastore independence certified:** operator/Railway evidence of dedicated staging
   PostgreSQL and Redis plugins (distinct hosts from production `DATABASE_URL`/`REDIS_URL`),
   plus `OIDC_REDIS_NAMESPACE=oidc-staging`.
4. **Email-authentication activation approval (staging only):** explicit approval to enable
   `HAPI_EMAIL` OTP for the `hapi-staging-app` application using synthetic
   `*@staging-test.hapiinc.com` identities only; then execute the synthetic registration + login
   ceremony and re-run the harness with `STAGING_ID_TOKEN` set, converting
   `staging.idtoken.verify`, `staging.idtoken.cross-jwks`, `staging.idtoken.iss` and
   `staging.synthetic-auth` from NOT-TESTED to PASS (including rejection of the staging token by
   the production JWKS).
5. **Session suite green:** `HapiSession.postgres` (and `RefreshTokenRotation.postgres` if refresh
   is in scope later — it is NOT part of Stage 3) passing against a staging-grade PostgreSQL 16.
6. **Explicit flag approval:** a separate written approval to set
   `HAPI_PERSISTENT_SESSIONS_ENABLED=true` **in the staging environment only**. All other V2 flags
   (Apple, Google, account linking, refresh grants) remain off; production flags remain untouched.
7. **Post-activation invariants:** staging `/session` becomes live with `__Host-`-prefixed,
   host-scoped cookies (no `Domain=` attribute); production `/session` must still return 404 and
   production discovery must remain byte-identical to the committed baseline.
