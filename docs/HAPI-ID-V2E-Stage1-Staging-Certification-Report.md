# HAPI ID V2-E Stage 1 — Isolated Staging Environment Certification Report

**Status: STAGING PREPARATION COMPLETE — STOPPED AT THE DEPLOYMENT READINESS GATE.**
Nothing was provisioned, deployed, pushed, or credentialed. Production Railway configuration,
DNS, and the live `identity.bookwrm.com` service were inspected read-only and are untouched.

- Stage 0 baseline: `d0f9a6eb8c2a1bea70b848446c24a6e98ec00b32` (`feature/hapi-id-v2e-stage0`, local only)
- Staging issuer (future): `https://id-staging.hapiinc.com`
- Production issuer (current, unchanged): `https://identity.bookwrm.com`
- Canonical production issuer (future, out of scope here): `https://id.hapiinc.com`

Stage 1 artifacts delivered in this commit:

| Artifact | Purpose |
| --- | --- |
| `src/config/IssuerPolicy.ts` → `enforceDeploymentIssuerPin()` | Boot-time fail-closed pin: non-default issuers require `OIDC_ALLOWED_ISSUERS` = exactly the service's own issuer and an explicit `CORS_TRUSTED_ORIGINS`. |
| `src/server.ts` | Calls the pin at boot, before serving traffic. |
| `tests/MultiIssuerConfiguration.test.ts` ("V2-E Stage 1" block) | Certifies the pin (5 new cases, fail-closed + production-unchanged). |
| `.env.staging.example` | Exact staging environment-variable names and non-secret values. |
| `scripts/certify-staging-oidc.mjs` | Executable Phase D certification harness (preflight + post-approval staging modes). |
| `scripts/production-discovery-baseline.json` | Byte-exact production discovery baseline for "production unchanged" certification. |

---

## 1. Current Railway production state (Phase A, read-only)

Observed via the GitHub deployments API and read-only HTTPS/DNS probes on 2026-11-19. No Railway
API token exists in this workspace, so service-internal settings (plugin topology, environment
variables) could not be enumerated and are listed as operator-confirmation items.

| Item | Observed state |
| --- | --- |
| Railway project / environment | `fulfilling-spirit` / `production` — the **only** environment ever deployed (30/30 GitHub deployments). |
| Deploy branch | `main` only. Every deployed ref is contained in `origin/main`. No other branch has ever triggered a deployment. |
| Deployed code | Latest deployment 2026-11-16 (`666dc75` lineage). Live `/health` reports version `6A.1`, uptime ≈ 3 days. **Production is running pre-V2C/D/E code** — the V2 feature routes do not exist in the running build (independently confirmed: all gated endpoints return 404). |
| Stage 0 exposure | `feature/hapi-id-v2e-stage0` has never been pushed (`git branch -r --contains d0f9a6e` is empty). Zero Railway exposure. |
| Custom domain | `identity.bookwrm.com` CNAME → `0a8fk79k.up.railway.app` (Railway edge). |
| TLS | Let's Encrypt, CN/SAN exactly `identity.bookwrm.com`, valid 2026-10-09 → 2027-01-07. HSTS `max-age=31536000; includeSubDomains` active. |
| Discovery | `issuer` exactly `https://identity.bookwrm.com`; all endpoints on that host; `grant_types_supported=["authorization_code"]`; S256 only. Byte-exact snapshot committed as `scripts/production-discovery-baseline.json`. |
| JWKS | Single RSA/RS256 signing key, `kid=rsa-1-DOCW-KVBmBo4vKFr`. |
| PostgreSQL / Redis | Required by the code (`DATABASE_URL`, `REDIS_URL`; registry driver defaults to `postgres`). Plugin/instance topology not visible without Railway access — **operator confirmation item O1**. |
| Staging DNS | `id-staging.hapiinc.com` does not resolve (no record exists yet). `id.hapiinc.com` does not resolve. `hapiinc.com` zone is live. |
| New-service safety (Phase A.3) | Yes: Railway services each carry their own GitHub trigger. A new staging service tracking a non-production branch (e.g. `release/hapi-id-staging`) deploys independently; creating it does not modify the production service's `main` trigger. Deployment history confirms production has only ever deployed from `main`. |
| Rollback options (Phase A.9) | (a) Railway per-service redeploy of a previous deployment (instant); (b) custom-domain detach/re-attach, independent of code deploys; (c) staging teardown deletes the service + plugins with zero production references. |

## 2. Staging configuration and isolation matrix (Phase B)

| Dimension | Production (`identity.bookwrm.com`) | Staging (`id-staging.hapiinc.com`) | Isolation mechanism |
| --- | --- | --- | --- |
| Railway service | Existing service, `main` trigger | **New** service, staging branch trigger | Separate services; production trigger untouched |
| Issuer | Default (`OIDC_ISSUER` unset) | `OIDC_ISSUER=https://id-staging.hapiinc.com` | Exact-match HTTPS origin validation (Stage 0) |
| Issuer allowlist | Optional (default-issuer back-compat) | `OIDC_ALLOWED_ISSUERS=https://id-staging.hapiinc.com` **only** | **New Stage 1 boot enforcement**: non-default issuer refuses to boot unless the allowlist is exactly its own single issuer |
| PostgreSQL | Production instance | Dedicated staging PostgreSQL 16, bootstrapped by `ensureIdentitySchema()` | Separate instance; no FDW/replication/shared credential |
| Redis | Production instance, `oidc` namespace | Dedicated staging Redis + `OIDC_REDIS_NAMESPACE=oidc-staging` | Separate instance + namespace + Stage 0 issuer binding on codes/tokens |
| Signing keys | Production `JWT_PRIVATE_KEY` | Freshly generated staging-only key ring | Disjoint keys ⇒ cross-environment signature failure (verified by harness JWKS-disjointness check) |
| Sessions / refresh tokens | Production stores (flags off) | Staging PostgreSQL + Redis only | Separate stores; `__Host-` host-scoped cookies cannot cross hosts; no `Domain=` attribute anywhere |
| OAuth clients | Bookwrm/Base44 client only | `staging-web`, `staging-native` synthetic clients only (§5) | No client registered in both environments; `OIDC_BASE44_*` unset in staging |
| Identities | Real users | Synthetic only (`*@staging-test.hapiinc.com`) | Staging never connects to the production identity registry or Base44 API |
| CORS | Default production allowlist | `CORS_TRUSTED_ORIGINS` explicit staging origins | **New Stage 1 boot enforcement**: non-default issuer refuses to boot without an explicit list (silent production-default fallback is impossible) |
| Cookies | Bound to `identity.bookwrm.com` | Bound to `id-staging.hapiinc.com` | `__Host-` prefix by construction |
| Logging/monitoring | Production service logs/metrics | Staging service logs (pino JSON) + separate `prom-client` metrics and audit stream `oidc-staging:audit` | Railway per-service log/metric separation |
| Production tokens at staging | n/a | **Rejected**: foreign `iss`, foreign signature, absent from staging stores; legacy issuer-less records honored only by the default Bookwrm issuer (Stage 0 `recordIssuerAccepted`) | Certified in `MultiIssuerConfiguration.test.ts`; live check in harness |

## 3. Exact required environment-variable names (Phase B / F.3)

Authoritative template: `.env.staging.example` (no secret values). Summary:

- **Required at boot (fail-closed):** `OIDC_ISSUER`, `OIDC_ALLOWED_ISSUERS` (exactly the staging issuer), `CORS_TRUSTED_ORIGINS`, `DATABASE_URL`, `REDIS_URL`, `JWT_PRIVATE_KEY` (+ `JWT_PUBLIC_KEY`, optionally `OIDC_JWKS_JSON`).
- **Required for isolation:** `OIDC_REDIS_NAMESPACE=oidc-staging`.
- **Flags, all explicitly off:** `HAPI_APPLE_FEDERATION_ENABLED`, `HAPI_GOOGLE_FEDERATION_ENABLED`, `HAPI_ACCOUNT_LINKING_API_ENABLED`, `HAPI_PERSISTENT_SESSIONS_ENABLED`, `HAPI_REFRESH_GRANT_ENABLED` (plus pre-V2 flags `HAPI_EMAIL_AUTHENTICATION_ENABLED`, `HAPI_FACE_ENROLLMENT_ENABLED`, `HAPI_FACE_SETUP_ENABLED`, `HAPI_UNIVERSAL_LOGIN_ENABLED`).
- **Runtime:** `NODE_ENV=production`, `MOCK_AUTH_ENABLED=false`, `METRICS_ENABLED=true`, `OIDC_ENABLED=true`, `REDIS_ENABLED=true`, `CACHE_ENABLED=true`, `OIDC_KEY_ROTATION_INTERVAL_SECONDS`.
- **Never set in staging:** any production credential — `BOOKWRM_IDENTITY_API_KEY`, `HAPI_PLATFORM_SERVICE_KEY`, production `BASE44_BASE_URL`, production `PRIVATEID_*` keys, production `RESEND_API_KEY`, any `OIDC_BASE44_*` client registration, `OIDC_TEST_USER_*`.
- **PrivateID:** inactive for the pilot (`PRIVATEID_MOCK_MODE=true`, callbacks unset; staging callbacks documented in the template for a future, separately approved activation).

## 4. DNS and TLS setup instructions (Phase A.4–5 / F.4 — requires approval, not executed)

1. Create the Railway staging service first and attach the custom domain `id-staging.hapiinc.com`
   in its settings; Railway shows the exact edge target to point at.
2. In the `hapiinc.com` zone, add: `id-staging CNAME <railway-edge-target>` with TTL ≤ 300 s.
3. Railway provisions a Let's Encrypt certificate automatically on domain verification. Before
   any client uses it, verify: full chain, SAN exactly `id-staging.hapiinc.com`, validity/OCSP
   (`openssl s_client -connect id-staging.hapiinc.com:443 -servername id-staging.hapiinc.com`).
4. No HSTS on staging initially (zero rollback friction); staging is never preloaded.
5. Gate: `curl https://id-staging.hapiinc.com/.well-known/openid-configuration` must return
   `"issuer": "https://id-staging.hapiinc.com"` exactly — the harness automates this.

## 5. Staging OAuth client-registration plan (Phase B / F.5)

Seeded directly into the **staging PostgreSQL** (synthetic tenant → application → client rows via
the existing registration surfaces), after deployment approval:

| Client | Type | Auth method | PKCE | Redirect URIs | Scopes |
| --- | --- | --- | --- | --- | --- |
| `staging-web` | confidential web | `client_secret_basic` | S256 required | `https://staging-app.hapiinc.com/callback` | `openid profile email` |
| `staging-native` | public native | `none` | S256 **required** | native loopback/app-claimed URI per the V2-D native-client readiness design (e.g. `com.hapi.staging:/callback`) | `openid profile email` |

Rules: secrets generated for staging only, rotated/discarded at teardown; exact-match redirect
URIs only; the production Bookwrm/Base44 `client_id` is never registered in staging and no
staging client is ever registered in production.

## 6. OIDC certification results (Phase D / F.6)

**Staging has not been deployed — certification against `https://id-staging.hapiinc.com` was NOT
run and cannot run until the deployment is separately approved** (the host does not resolve).
The harness `scripts/certify-staging-oidc.mjs` encodes every Phase D check and is ready to
execute post-approval (`--staging-approved` + `STAGING_ISSUER`). Mapping:

| Phase D check | Harness check id | Pre-deployment status |
| --- | --- | --- |
| 1. HTTPS/TLS | `staging.tls` | pending deployment |
| 2. Discovery issuer exact | `staging.discovery.issuer` | pending deployment |
| 3. Endpoints on staging host | `staging.discovery.endpoints` | pending deployment |
| 4. Staging keys verify staging ID tokens | `staging.jwks`, `staging.jwks.disjoint`, `staging.idtoken.*` | pending deployment |
| 5. Code + PKCE S256 with synthetic clients | `staging.authorize.pkce`, `staging.authorize.pkce-required` | pending deployment |
| 6. Exact redirect-URI enforcement | `staging.authorize.redirect-exact` (negative) | pending deployment |
| 7. No cross-issuer code redemption | code-level ✅ (see §7) + physically separate stores | code-level certified |
| 8. No cross-issuer access/refresh-token use | `cross.staging-token-at-prod`, `cross.prod-token-at-staging` (negative) + code-level ✅ | code-level certified |
| 9. Synthetic registration/authentication | `staging.synthetic-auth` (manual ceremony) | pending deployment |
| 10. Production Bookwrm login unchanged | `prod.discovery.baseline` byte-compare + full preflight | ✅ **PASS today** |

**Production preflight executed now (read-only): 8/8 PASS, 0 FAIL** — issuer exact, grants
`["authorization_code"]`, discovery byte-identical to the committed baseline, JWKS served, all
four gated V2 endpoints 404, staging/canonical DNS confirmed absent.

## 7. Cross-environment rejection results (Phase D.7–8 / F.7 — code-level, executed now)

`tests/MultiIssuerConfiguration.test.ts`: **35/35 PASS** (Stage 0 suite + 5 new Stage 1 cases),
including: authorization codes, access tokens, and legacy refresh tokens minted under one issuer
are rejected for redemption/use under any other issuer even on a deliberately shared store;
issuer-less legacy records are honored only by the default Bookwrm issuer; discovery/ID-token
`iss` always equals the configured issuer; and the new boot pin refuses a staging service whose
allowlist names any second issuer. Live bidirectional token-rejection checks run via the harness
after deployment approval (§6). Signature-level rejection is guaranteed by disjoint key material
(§2) and verified by the harness (`staging.idtoken.cross-jwks`).

## 8. Remaining security blockers (Phase C/E / F.8)

Phase C confirmation (code defaults + live production probes): **all five V2 flags disabled** —
Apple federation, Google federation, account-linking API, persistent sessions, refresh grants
(`FeatureFlagService` defaults false; production discovery exposes only `authorization_code`;
gated endpoints 404). PrivateID remains disabled for the staging pilot.

Activation blockers (none block Stage 1 staging certification itself; ALL block their respective
feature activations):

| # | Blocker | Stage gate it blocks | Status |
| --- | --- | --- | --- |
| B1 | Provider-callback login-CSRF residual (Google GET callback should additionally require the interaction cookie; Apple `form_post` structurally cannot) | Apple/Google activation | **Open** — close before any real federation |
| B2 | Push revocation not consumed (Apple server-to-server notifications, Google RISC); revocation effective only at unlink or `/token` re-check | Federation activation | **Open** — define revocation event handling |
| B3 | Provider login-transaction cleanup: establish TTL sweep/cleanup for federation transaction rows | Federation activation | **Open** — certify on staging |
| B4 | Shared rate-limit buckets on the linking surface; dedicate a tighter `link/complete` bucket and re-verify linking authorization | Account-linking activation | **Open** |
| B5 | Persistent sessions + refresh rotation never certified on a production-like PostgreSQL (32 PostgreSQL-gated security tests) | Persistent-session / refresh activation | **Open** — the staging DB is the designated venue (§10) |
| B6 | Safe account recovery and unlinking verification (last-method unlink refusal, recovery ceremony) | Account-linking activation | **Open** — certify on staging |
| B7 | First-login race can orphan subject rows (harmless; sweeper recommended) | Hygiene | Open, low severity |
| B8 | No CI pipeline — all gates run manually; adding CI must be assessed against the Railway GitHub integration so it cannot trigger a deploy | Process | Open |
| B9 | No authentication-method management UI (API only) | UX completeness | Open |
| — | Stage 0 issuer pin hard-block, hardcoded CORS origin, hardcoded PrivateID webhook URL | — | **Resolved** by Stage 0 (`d0f9a6e`) |

New blocker found during Stage 1 preparation (now **resolved in this change**): a non-default
issuer service could previously boot without `OIDC_ALLOWED_ISSUERS` (pin optional) and would
silently fall back to the **production** CORS allowlist when `CORS_TRUSTED_ORIGINS` was unset.
`enforceDeploymentIssuerPin()` makes both fail closed at boot for any non-default issuer while
leaving the default Bookwrm issuer untouched (tested).

## 9. Deployment and rollback procedure (F.9 — requires approval, not executed)

Deployment (operator, in order; full checklist in the Stage 0 design §12):

1. Merge/push Stage 0+1 code to the production lineage; deploy to production; verify
   `identity.bookwrm.com` unchanged (`node scripts/certify-staging-oidc.mjs --preflight` must
   remain 8/8 PASS; verify `PRIVATEID_CALLBACK_URL=https://identity.bookwrm.com/privateid/webhook`
   is set in the production service **before** this deploy — Stage 0 starts honoring it).
2. Create staging branch (e.g. `release/hapi-id-staging`); create the Railway staging service
   tracking it; confirm the production service's trigger is untouched.
3. Provision staging PostgreSQL 16 + staging Redis (empty).
4. Set variables per `.env.staging.example`; generate fresh staging signing keys (compare JWKS
   thumbprints ≠ production).
5. Attach `id-staging.hapiinc.com` + DNS per §4; verify TLS.
6. Seed synthetic clients per §5; run
   `STAGING_ISSUER=https://id-staging.hapiinc.com node scripts/certify-staging-oidc.mjs --staging-approved`,
   then the manual synthetic ceremony and token-based negative checks.
7. Run the PostgreSQL-gated suites against the staging database (per-suite DB isolation per the
   Phase 3 operational notes).

Rollback (any point, production-safe by construction): detach the staging domain (instant,
reversible) → scale/delete the staging service → delete staging PostgreSQL/Redis. Nothing in
production references staging; staging data is synthetic and disposable. Production rollback is
the standard Railway redeploy of the previous deployment. Rehearse domain detach/re-attach and
record timings.

## 10. Next action for persistent HAPI sessions in staging (F.10)

After Stage 1 certification passes (and with its own approval):

1. Run the PostgreSQL-gated session/refresh security suites against the **staging** database:
   `HapiSession.postgres.test.ts`, `RefreshTokenRotation.postgres.test.ts` (+ supporting
   `IdentityRegistry.postgres`, `SchemaVersioning.postgres`) — this clears blocker B5.
2. Set `HAPI_PERSISTENT_SESSIONS_ENABLED=true` **in the staging service only**; redeploy staging.
3. Certify on staging with synthetic users: login → browser close → return resumes within the
   idle window; fixation probe fails; logout is terminal; cross-user revocation refused;
   `__Host-hapi_sid` never visible to other hosts.
4. Only then consider `HAPI_REFRESH_GRANT_ENABLED=true` for the synthetic pilot client
   (rotation + reuse ⇒ family-revocation gates), as its own stage.

---

## Deployment readiness gate — items requiring your explicit approval

Stage 1 preparation is complete. **Everything below is blocked pending your approval; none of it
was performed:**

1. **Push** the Stage 0+1 commits to a remote branch (any push to `main` lineage will deploy to
   production via Railway's GitHub integration).
2. **Deploy Stage 0+1 to production** (`identity.bookwrm.com`) with all flags off — prerequisite
   checklist item before staging work, including confirming the production
   `PRIVATEID_CALLBACK_URL` variable first.
3. **Create the Railway staging service** (+ choice of staging branch name).
4. **Provision staging PostgreSQL 16 and staging Redis.**
5. **Create the DNS record** `id-staging.hapiinc.com` and attach the Railway custom domain (TLS
   issuance follows automatically).
6. **Enter staging secrets** (generated staging signing keys, staging DB/Redis URLs) into the
   Railway staging environment.
7. **Seed synthetic staging OAuth clients** and run the live Phase D certification
   (`--staging-approved`).

Operator-confirmation items (read-only, need Railway dashboard access I don't have):
**O1** — confirm production PostgreSQL/Redis plugin topology and that the staging plugins are
created as separate instances, never shared; **O2** — audit the staging service environment
against §3's "never set in staging" list before first boot.
