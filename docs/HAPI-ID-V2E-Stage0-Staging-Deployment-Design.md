# HAPI ID V2-E Stage 0 — Multi-Service Staging Deployment Design (`id-staging.hapiinc.com`)

**Status: DESIGN ONLY — nothing in this document has been provisioned, deployed, or configured.**
Stage 0 ships inert, environment-configurable code; executing any part of this design requires
separate explicit approval (V2-E plan, Deliverable 8, Stage 1).

Scope: a fully separate Railway service hosting the staging issuer
`https://id-staging.hapiinc.com`, certified against synthetic data only, with zero connectivity
to the production identity registry and zero possibility of staging↔production credential or
session crossover. The canonical production issuer `https://id.hapiinc.com` is explicitly **out
of scope** here and retains its own future plan (V2-E plan §2.3 and Stage 4+), including
production registry continuity (`oidc_subject` values are issuer-independent; no data migration
at cutover).

---

## 1. DNS and TLS

| Item | Design |
| --- | --- |
| DNS record | `id-staging.hapiinc.com` CNAME → the Railway-provided edge target for the **staging** service (never the production service's target). TTL ≤ 300 s for fast detach/rollback. |
| TLS | Railway-managed certificate issued on custom-domain attachment. Before any client is pointed at it, verify: full chain, SAN exactly `id-staging.hapiinc.com`, OCSP/validity. |
| HSTS | None initially on staging (keep rollback friction at zero); staging is never listed in any preload set. |
| Verification gate | `curl https://id-staging.hapiinc.com/.well-known/openid-configuration` returns `"issuer": "https://id-staging.hapiinc.com"` exactly, and `${issuer}/jwks` serves the staging key ring. |

## 2. Railway service and environment configuration

A **new, separate Railway service** (same repository/build, distinct service + environment), never a
new domain on the production service.

Environment (staging service only — production Railway configuration is untouched):

| Variable | Staging value | Purpose |
| --- | --- | --- |
| `OIDC_ISSUER` | `https://id-staging.hapiinc.com` | Authoritative issuer (Stage 0 validation: exact https origin, fail closed). |
| `OIDC_ALLOWED_ISSUERS` | `https://id-staging.hapiinc.com` | Defense-in-depth pin: boot fails closed if the issuer is ever misconfigured. |
| `CORS_TRUSTED_ORIGINS` | staging browser origins only (e.g. `https://id-staging.hapiinc.com,https://staging-app.hapiinc.com`) | Stage 0 explicit allowlist; the production/Bookwrm origins are deliberately absent. |
| `PRIVATEID_CALLBACK_URL` | `https://id-staging.hapiinc.com/privateid/webhook` | Stage 0 configurable webhook callback (origin is in the supported host set). Set only if/when PrivateID is exercised in staging; PrivateID remains **inactive** otherwise. |
| `OIDC_REDIS_NAMESPACE` | `oidc-staging` | Hard namespace separation of authorization codes, access tokens, legacy refresh tokens, rate-limit buckets, and audit stream — required even though a dedicated Redis is also used (defense in depth). |
| `DATABASE_URL` | staging-only PostgreSQL | See §3. |
| `REDIS_URL` | staging-only Redis | See §4. |
| `JWT_PRIVATE_KEY` / `OIDC_JWKS_JSON` | staging-only key material | See §7. |
| All five HAPI feature flags | **unset (default OFF)** | `HAPI_PERSISTENT_SESSIONS_ENABLED`, `HAPI_REFRESH_GRANT_ENABLED`, `HAPI_APPLE_FEDERATION_ENABLED`, `HAPI_GOOGLE_FEDERATION_ENABLED`, `HAPI_ACCOUNT_LINKING_API_ENABLED` stay off until their own stage gates. |
| `BASE44_BASE_URL` / `IDENTITY_API_PATH` / `BOOKWRM_IDENTITY_API_KEY` | staging stubs / synthetic | Staging must **not** hold production identity-API credentials (§10). |

Railway GitHub integration: the staging service deploys only from an explicitly chosen branch
(e.g. `release/hapi-id-staging`), never from the production-deploying branch, and the production
service's trigger configuration is not modified.

## 3. PostgreSQL (staging)

- Dedicated PostgreSQL 16 instance (Railway PostgreSQL plugin or managed instance) — **never** a
  schema or database inside the production cluster.
- Bootstrapped by the service's own `ensureIdentitySchema()` migration path
  (`schema_migrations` row `1.x`), matching the Phase 3 certification procedure.
- Contains **synthetic identity records only** (`identity_subjects`, `external_identities`,
  `hapi_sessions`, refresh-token family tables, OTP/registration tables). No production row is
  ever copied, restored, or replicated into it.
- No network path, foreign-data wrapper, logical replication, or shared credential between the
  staging and production databases.
- Operational note from Phase 3 certification: the PostgreSQL-gated suites expect per-suite
  database isolation (shared databases trip FK-coupled cleanup in
  `TenantApplicationFoundation`), and `SchemaVersioning` expects a once-bootstrapped database.

## 4. Redis (staging)

- Dedicated staging Redis service (preferred) **and** `OIDC_REDIS_NAMESPACE=oidc-staging`.
- Rationale: Stage 0 adds issuer binding to authorization codes, access tokens, and legacy
  refresh tokens (rejected cross-issuer even on a shared store), but store separation remains the
  primary control; the issuer binding is defense in depth, not a license to share Redis.
- Rate-limiter buckets, Redlock locks, provider adapter state, and the OIDC audit stream all live
  under the staging namespace on the staging instance.

## 5. Authorization-code and refresh-token stores

- Authorization codes + access tokens + legacy refresh tokens: staging Redis only (§4), and every
  record carries `issuer: https://id-staging.hapiinc.com` (Stage 0), so even a misconfigured
  shared store cannot redeem them against another issuer.
- V2-C rotating refresh-token families: staging PostgreSQL only (§3). Families have no issuer
  column; their isolation is the separate database — this is why §3's "no shared database" rule
  is a hard requirement, re-verified in the deployment checklist.

## 6. Cookie scope

- `__Host-hapi_sid`, `__Host-hapi_login`, and the PrivateID browser-return cookie are `__Host-`
  prefixed / host-scoped: they are bound to `id-staging.hapiinc.com` by construction and cannot
  be presented to `identity.bookwrm.com` or `id.hapiinc.com` (and vice versa).
- No `Domain=` attribute is ever added to any cookie (that would be the only way to leak scope —
  treat any such change as a release blocker).

## 7. Signing-key material

- Generate a **fresh staging RSA key pair** (or JWKS ring) used nowhere else. Production
  `JWT_PRIVATE_KEY` material is never copied into the staging service.
- Consequence (intended): staging-signed JWTs fail signature verification against the production
  JWKS and vice versa — token forgery across environments is cryptographically impossible, in
  addition to the exact-`iss` rejection certified in Phase 2.
- Key rotation (`OIDC_KEY_ROTATION_INTERVAL_SECONDS`) runs independently in staging.

## 8. Identity data and OAuth clients

- **Synthetic identity records only**: all subjects are created through staging flows with
  test-reserved addresses (e.g. `*@staging-test.hapiinc.com`); no real-user PII, no production
  PUIDs, no production `oidc_subject` values.
- **Test-only OAuth client registrations**: synthetic tenant/application/client rows registered
  directly in the staging PostgreSQL (e.g. `staging-web`, `staging-native`), with staging-only
  redirect URIs (e.g. `https://staging-app.hapiinc.com/callback`). No production `client_id`
  (e.g. the Bookwrm/Base44 client) is registered in staging, and no staging client is ever
  registered in production.
- Client secrets are generated for staging only and are rotated/discarded at teardown.

## 9. Provider callback and redirect URIs (future stages, documented now)

- PrivateID (if exercised in staging): webhook `https://id-staging.hapiinc.com/privateid/webhook`,
  browser redirect `https://id-staging.hapiinc.com/privateid/callback` — registered with the
  PrivateID **test** tenant/API key, never the production key. Stage 0 keeps PrivateID inactive.
- Apple/Google federation (Stage 3, flags off until then): provider-side redirect URIs
  `https://id-staging.hapiinc.com/federation/apple/callback` and
  `https://id-staging.hapiinc.com/federation/google/callback`, registered under **staging-only**
  provider applications with staging-only credentials. Production provider registrations never
  list staging URIs, and staging registrations never list production URIs.

## 10. Staging↔production crossover prevention (hard rules)

1. Different issuer (`iss`) + Phase 2 certified exact-issuer validation → staging tokens are
   rejected by production RPs and endpoints, and cross-issuer codes/tokens are rejected even on a
   shared store (Stage 0 issuer binding).
2. Different signing keys (§7) → signature-level rejection both directions.
3. Different PostgreSQL + Redis (+namespace) → no shared session, code, token, family, or OTP
   state.
4. Host-scoped `__Host-` cookies (§6) → no session crossover in browsers.
5. No production credentials of any kind in the staging service environment (identity API keys,
   PrivateID keys, SMTP/Svix, provider secrets). Staging holds synthetic/test credentials only.
6. No staging client registered in production; no production client registered in staging (§8).
7. Staging is **not connected to the production identity registry** during initial certification:
   `BASE44_BASE_URL`/identity-API configuration points at a stub or staging fixture, never at the
   production Base44/identity API.

## 11. Logging, observability, rollback

- Logging: pino JSON logs with the existing OIDC request log fields (requestId, clientId, flow,
  latency, success, error, correlationId); staging logs are tagged by the service identity in
  Railway and never mixed with production log sinks.
- Metrics: existing `prom-client` metrics endpoint per service; staging dashboards/alerts are
  separate. Minimum watch list during certification: discovery/token/userinfo error rates,
  rate-limit rejections, Redis/PostgreSQL health probes (`/health` readiness).
- Audit: OIDC audit stream (`oidc-staging:audit`) and `identity_link_audit` reviewed as part of
  each stage gate.
- Rollback: detach the `id-staging.hapiinc.com` domain and/or delete the staging service,
  databases, and Redis. Nothing in production referenced staging, so rollback rewrites nothing.
  Staging data is disposable by design.

---

## 12. First controlled staging deployment checklist (requires separate approval)

Pre-deployment (operator):

- [ ] Explicit approval for Stage 1 recorded (this checklist executes nothing by itself).
- [ ] Stage 0 code merged and deployed to production with all five flags off and behavior
      verified unchanged on `identity.bookwrm.com` (discovery byte-identical, default CORS list
      identical, PrivateID webhook callback unchanged).
- [ ] Verify the production Railway variable `PRIVATEID_CALLBACK_URL` equals
      `https://identity.bookwrm.com/privateid/webhook` **before** deploying Stage 0 to
      production (Stage 0 starts honoring this previously ignored variable; see §Compatibility
      in the Stage 0 report).
- [ ] Staging branch chosen; Railway staging service created from it; confirm the production
      service's deploy triggers are untouched.

Provisioning:

- [ ] Staging PostgreSQL 16 provisioned (empty); staging Redis provisioned.
- [ ] Staging environment variables set per §2 (flags unset/off; `OIDC_ISSUER`,
      `OIDC_ALLOWED_ISSUERS`, `CORS_TRUSTED_ORIGINS`, `OIDC_REDIS_NAMESPACE=oidc-staging`).
- [ ] Fresh staging signing key generated and set; confirmed ≠ production key (compare JWKS
      thumbprints).
- [ ] `id-staging.hapiinc.com` CNAME attached; TLS issued and verified (§1).

Certification (synthetic only):

- [ ] Discovery: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
      `jwks_uri` all exactly on `https://id-staging.hapiinc.com`; `grant_types_supported` is
      `["authorization_code"]` (flags off).
- [ ] JWKS served and contains only the staging key.
- [ ] Synthetic tenant/application/client seeded (§8); full code+PKCE round-trip executed with a
      synthetic user; ID token `iss`/`aud`/signature verified against staging JWKS.
- [ ] Negative checks: staging access token rejected by production `/userinfo` (401); staging ID
      token fails verification against production JWKS and against `iss=https://id.hapiinc.com`;
      production token rejected by staging.
- [ ] CORS: staging origins allowed; `https://bookwrm.com` et al. rejected on staging.
- [ ] `/health` readiness green (PostgreSQL + Redis probes).
- [ ] Confirm zero production-credential variables present in the staging service (audit the
      environment against §10.5).

Rollback rehearsal:

- [ ] Detach domain, confirm resolution/cert revocation behavior, re-attach — documented timing.

Post-certification:

- [ ] Record results; staging remains isolated from the production identity registry until the
      separately approved stage that defines that integration.
