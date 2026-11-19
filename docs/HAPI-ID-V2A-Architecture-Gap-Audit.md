# HAPI ID V2 — Current Architecture & Gap Analysis (V2-A)

**Date:** 2026-11-19
**Phase:** V2-A (read-only audit — no code, schema, or configuration changes made)
**Audited commit:** `666dc75` (main)
**Validation:** `npx vitest run` — 510 passed / 124 skipped; the single failing suite is the known
Playwright-Chromium environment-provisioning issue in `tests/FaceSetupCeremony.test.ts`
(browser shell not installed in this container; documented in `docs/Build-Report-2026-11-17.md`).
PostgreSQL integration suites skipped by design (no `*_TEST_DATABASE_URL` configured).

---

## 0. Critical operational context

1. **Production lags main by ~3 months.** Per `docs/hapi-id/recovery/P0E-AUTHENTICATION-CERTIFICATION-BLOCKED.md`,
   `https://identity.bookwrm.com` serves commit `5ece5f0` ("SPRINT-7.75-VERIFY", 2026-08-10). The
   multi-client foundation (`2711ab2`), H6.11 Universal Login, and the hardened security boundary
   (`df5c2f1`) are **not deployed**. Every V2 feature below builds on undeployed code. Bringing
   production to current main (P0E unblock) is a prerequisite for any V2 production gate, and must
   be sequenced before issuer migration work.
2. **Deployment:** Railway project `fulfilling-spirit / production`, single Fastify service,
   PostgreSQL + Redis. Railway env values themselves are not inspectable from this repository;
   the variable *names* consumed are inventoried in §15.

---

## 1. Identity and HAPI subject tables

Source of truth: `src/identity/schema.sql` (applied idempotently at boot by
`ensureIdentitySchema()` in `src/identity/infrastructure/PostgresInfrastructure.ts`).

| Table | Purpose | Notes relevant to V2 |
|---|---|---|
| `identity_subjects` | System-of-record identity. `id` (UUID PK), **immutable `oidc_subject`** (unique) = the OIDC `sub`, `primary_provider` + `primary_provider_subject` (unique pair), `email`, `email_verified`, `display_name`, `status` (`ACTIVE`/`LOCKED`/`DISABLED` in code; TEXT in DB), timestamps, `last_authenticated_at`, `application_id` (creation provenance only). | This is the "HapiIdentity" of the V2 spec. `oidc_subject` is the stable HAPI subject. **One provider pair per subject** — no multi-provider linking table exists. |
| `tenants` | IDaaS customer boundary (H1). Bookwrm = Tenant #1. | |
| `applications` | Relying-party product within a tenant. Carries `application_key`, `allowed_authentication_methods` (default `['HAPI_EMAIL']`), `allowed_identity_providers` (default `[]` — **unused today**), `face_setup_enabled`, `presentation` JSONB. | Per-application method allow-list is the natural activation gate for APPLE/GOOGLE. |
| `oidc_clients` | Client registry (see §2). | |
| `user_authenticators` | Provider authenticators; CHECK-constrained to `provider='privateid'`, `authenticator_type='face'`. Partial unique index: one active face per user. | This is the closest existing analog to `HapiAuthenticationMethod`, but hard-constrained to PrivateID face. |
| `identity_account_links` | Bookwrm-only external-account→subject mapping (`source='bookwrm'` CHECK). Trigger `mirror_bookwrm_account_link` mirrors into the canonical tables. | |
| `application_account_links` / `application_account_link_audit` | Canonical app participation + append-only audit (authority, client_id, request_id, authentication_method, result). | Good template for `HapiAccountLinkAudit`. |
| `identity_claim_provenance` | Per-claim source governance (H3P). | |
| `schema_migrations` | Version rows inserted once per boot (`version` TEXT PK). | See §15 migration-strategy caveat. |
| `authenticator_login_transactions`, `privateid_enrollment_transactions`, `privateid_webhook_diagnostics` | PrivateID face login/enrollment lifecycle. | `privateid_webhook_diagnostics` is marked TEMPORARY (Patch 8.4). |

Auxiliary schemas: `src/email/schema.sql` (`verification_challenges`, `verification_delivery_events`,
`email_verification_audit`), `src/registration/schema.sql` (`registration_evidence`,
`identity_registration_audit`), `src/authentication/email/schema.sql`
(`email_authentication_results` keyed by `token_hash`, `email_authentication_audit`),
`src/authenticators/schema.sql` (`hapi_face_enrollment_bindings`,
`hapi_face_authentication_consents`, `authenticator_enrollment_audit`).

**Finding:** `src/models/IdentitySubject.ts` already declares
`IdentityProvider = "PrivateID" | "Google" | "Apple" | "Passkey" | "Enterprise" | "HAPI_EMAIL"` —
Apple/Google/Passkey are *reserved in the type system* but have **zero implementation**: no
federation code, no external-identity table, and `GET /authorize` **rejects any `idp_hint`**
(`"Provider selection is not enabled"`, `src/oidc/OIDCService.ts:375`).

## 2. OIDC client registry and supported authentication methods

- Persisted in `oidc_clients`: `client_id` (unique), `client_secret` (plaintext TEXT — see gap G-11),
  `redirect_uris TEXT[]`, `scopes TEXT[]`, `grant_types TEXT[]`, `response_types TEXT[]`,
  `token_endpoint_auth_method` CHECK `('client_secret_post','client_secret_basic','none')`,
  `require_pkce` (default true), `status` (`active`/`suspended`).
- Repositories: `PostgresOIDCClientRepository` / `InMemoryOIDCClientRepository`; authority chain
  `resolveRegisteredClient()` (`src/identity/H1ClientAuthority.ts`) requires client → application →
  tenant all active, and `requireApplicationMethod()` enforces the application's
  `allowed_authentication_methods` at authorize *and* token time.
- Authentication methods implemented end-to-end today: **HAPI_EMAIL** (H4 OTP) and
  **PRIVATEID_FACE**. Nothing else.

## 3. Confidential vs public-client validation

- Token endpoint (`src/oidc/OIDCService.ts:578-800`): `client_secret_basic` (RFC 6749 §2.3.1 header
  takes precedence) and `client_secret_post` verified with `constantTimeStringEqual`; method
  `none` skips the secret check and `clientRequiresPkce()` **forces PKCE for every
  `token_endpoint_auth_method=none` client** (`OIDCService.ts:1615`).
- Public-client path is real and tested once
  (`tests/OIDCTokenClientAuthentication.test.ts:271` — "authenticates an explicitly public client
  without a secret and enforces PKCE S256"), but **no public client is registered or seeded**.

## 4. `/authorize`, `/token`, `/userinfo`, discovery, JWKS

All live endpoints are **hand-rolled Fastify handlers at the root path** in
`src/oidc/OIDCService.registerEndpoints()`:

- `GET/POST /authorize` (§5, §G below), `POST /token`, `GET /userinfo`, `GET /jwks`,
  `GET /.well-known/openid-configuration`, plus Universal Login pages
  `GET /login`, `GET|POST /login/email`, `GET|POST /login/email/code`, `POST /login/email/resend`,
  `POST /login/face`.
- Discovery (`getDiscoveryConfiguration()`): `response_types_supported:["code"]`,
  `grant_types_supported:["authorization_code"]`, `code_challenge_methods_supported:["S256"]`,
  `token_endpoint_auth_methods_supported:["client_secret_basic","client_secret_post","none"]`,
  RS256 only. **No `refresh_token` grant, no `revocation_endpoint`, no `end_session_endpoint`.**
- `/userinfo`: opaque Bearer access token looked up in Redis; claims re-resolved live from the
  Identity Registry (Patch 6.1), never from token-time snapshots.
- **Vestigial parallel engine:** the `oidc-provider` npm library is instantiated and mounted at
  `/oidc/*` (`src/oidc/routes.ts`, `src/oidc/provider.ts`) with revocation/introspection "enabled"
  — but nothing routes real traffic to it; the root endpoints are the actual implementation. This
  is exactly the "parallel token engine" the V2 spec warns about. V2 must either adopt it fully or
  (recommended) remove the mount and extend the proven custom engine.

## 5. Authorization-code issuance and exchange

- Codes: 32-byte `base64url` opaque, **60 s TTL**, stored in Redis
  (`RedisOIDCStore.storeAuthorizationCode`), bound to `clientId`, `redirectUri`, `scope`, `nonce`,
  `codeChallenge`, `userId`, `userSub`, `authenticationMethod`, `authenticatedAt`.
- Exchange: serialized via `RedisLockService.withAuthorizationCodeLock`; consumption marks the
  record consumed with a 5 s tombstone (replay rejected). Client-id match, redirect-uri match,
  registered-redirect re-check, application-method re-check, and live email-identity eligibility
  re-check (`primaryProvider==='HAPI_EMAIL' && status==='ACTIVE' && emailVerified && email===primaryProviderSubject`) all enforced.
- **Quirk:** the token endpoint rejects codes with an empty `nonce` (`OIDCService.ts:709`), while
  `GET /authorize` accepts a missing nonce (`query.nonce ?? ""`). Nonce is therefore *de facto
  mandatory*, but a GET request without one fails late (at token exchange) instead of early.

## 6. PKCE S256 enforcement

- `plain` explicitly rejected; only `S256` accepted; challenge format validated
  (`^[A-Za-z0-9_-]{43}$` on the POST handoff path).
- `require_pkce` defaults true in schema and in `clientRequiresPkce()`; method `none` → always on.
- Verifier→challenge check is SHA-256/base64url (`toS256CodeChallenge`). Covered in
  `tests/OIDCPKCETest.test.ts` and the token-auth suite.

## 7. Refresh-token capability — present limitations

**This is the single largest structural gap for native mobile.**

- `POST /token` **issues** a `refresh_token` on every authorization-code exchange
  (`OIDCService.ts:746-785`) and stores it in Redis for **30 days**
  (`REFRESH_TOKEN_TTL_MS = 2_592_000_000`)…
- …but the grant switch rejects everything except `authorization_code`
  (`"Only grant_type=authorization_code is supported"`, `OIDCService.ts:601-607`), and discovery
  advertises only `authorization_code`. **Refresh tokens are issued, stored, and can never be
  redeemed.**
- Storage is keyed by the **plaintext token value** (`oidcRedisKey("refresh_token:"+token)`,
  `RedisOIDCStore.storeRefreshToken`) — no server-side hashing/verifier, no rotation, no token
  family, no reuse detection, no revocation API, no session/device association
  (record = `{userId, clientId, scope, expiresAt}` only).
- Consequence: every token response hands clients a 30-day bearer secret that is dead weight for
  them and pure liability for HAPI.

## 8. Access-token and ID-token lifetimes

- Access token: opaque, **300 s** (`ACCESS_TOKEN_TTL_MS`), Redis record `{sub, clientId, nonce, scope, authenticationMethod, authenticatedAt}`.
- ID token: RS256 JWT, **exp = iat + 300 s**, includes `nonce`, `scope`, live claims, and
  `amr` (`["email"]` or `["face","privateid"]`) + `auth_time` when an authentication method is bound.
- No sender-constraint (no DPoP/mTLS).

## 9. Email OTP registration/authentication

- **H2** verification challenges: hashed codes (`code_hash`), `attempt_count`/`max_attempts`,
  `send_count`, statuses `PENDING/VERIFIED/EXPIRED/LOCKED/CONSUMED`, purposes incl.
  `REGISTRATION`/`AUTHENTICATION`/`RECOVERY`/`EMAIL_CHANGE`.
- **H3** canonical registration: `registration_evidence` (one row per consumed challenge =
  idempotency anchor), `identity_registration_audit`.
- **H4** headless email authentication (`/v1/authentication/email/*`, Basic client auth) ending in
  a single-use, hashed `authentication_result` handle (`email_authentication_results.token_hash`)
  consumed by `POST /authorize` (strict zod schema, `EmailOIDCHandoff.consume` binds it to the
  requesting client).
- **H6.11** interactive Universal Login email flow reuses the same machinery behind the
  interaction store.

## 10. Authentication events and audit tables

Append-only audits: `email_verification_audit`, `email_authentication_audit`,
`identity_registration_audit`, `application_account_link_audit`, `authenticator_enrollment_audit`,
plus `IdentityAudit`/`IdentityClaimAudit` services and a Redis stream OIDC request log
(`XADD oidc:audit MAXLEN ~10000` — request id, client, flow, latency, success, error, user, pkce,
correlation id). No secrets/codes in audit rows (hashes only). Structured
`APPLICATION_AUTHENTICATION` / `APPLICATION_AUTHORIZATION` log events exist for every decision.

## 11. Account-session lifecycle

**There is no persistent HAPI account session.**

- The only browser state is `__Host-hapi_login` — a single-use, 10-minute authorization
  *interaction* handle (`AuthorizationInteractionStore`, SHA-256-keyed in Redis, atomic
  consume-once semantics, per-interaction CSRF token). It is not an SSO session: every
  `/authorize` round-trip requires fresh authentication (OTP or face).
- No session table, no device registry (`/identity/trusted-devices` returns static placeholder
  data via `IdentityService`), no logout/end-session endpoint, no per-device revocation.
- V2 requirements "existing HAPI session detection and secure reuse", "account selection",
  "recent authentication for sensitive linking", and "per-device session visibility and
  revocation" all depend on a session layer that **does not exist yet**.

## 12. Rate limits and abuse protections

- `OIDCRateLimiter` (Redis INCR windows): per-IP 120/min, per-client 300/min, per-user 180/min
  (env-tunable `OIDC_RATE_LIMIT_*`), applied on authorize, token, userinfo, and Universal Login
  mutations.
- Email: per-challenge `max_attempts` + `LOCKED` state, resend `send_count` limits, destination
  hashing; H4 audit event `EMAIL_AUTHENTICATION_RATE_LIMITED`.
- `bodyLimit: 4096` on credential-bearing POSTs; helmet; strict CSP/`X-Frame-Options: DENY` on
  login pages; `__Host-` cookie prefix; CSRF on all interaction mutations; CORS allow-list
  (`src/security/CorsPolicy.ts`).
- Known limitation: the INCR+EXPIRE pattern has the classic unexpired-key edge case if the first
  INCR's EXPIRE fails; acceptable today, worth noting for refresh-endpoint sizing.

## 13. Signing-key lifecycle

`OIDCKeyRotationService`: key ring from `JWT_PRIVATE_KEY` (one or more PEMs) or `OIDC_JWKS_JSON`
(private JWKs); deterministic `kid` from public-key hash; active-kid election coordinated through
Redis with `OIDC_KEY_ROTATION_INTERVAL_SECONDS` (default 3600); non-production generates an
ephemeral key; production **boot guard** refuses to start without configured key material. RS256
only. JWKS endpoint serves the full public ring (supports overlap during rotation).
**Unknown (needs Railway read-only check):** which mechanism production actually uses and whether
the deployed ring matches the recovered service's keys (flagged UNKNOWN in
`docs/recovery/DISCOVERY-SUMMARY.md`).

## 14. Existing Bookwrm relying-party registration

Seeded idempotently at every boot by `ensureBookwrmApplicationSeed()`
(`src/adapters/base44/Base44ApplicationSeed.ts`): Tenant `bookwrm` (fixed UUID in
`WellKnownIdentities.ts`) → Application `bookwrm-base44` (`application_key='BOOKWRM'`,
`allowed_authentication_methods=['HAPI_EMAIL']`, `face_setup_enabled=true`) → one confidential
`oidc_clients` row built from legacy env config via `registerBase44OIDCClient()`
(`Base44OIDCClientAdapter`: client id/secret/redirect URI come from env, not source). Pre-H1
`identity_subjects` rows are backfilled onto this application. Callback URI value lives in Railway
env, not the repository.

## 15. Railway environment, migration strategy, deployment topology

**Environment variables consumed** (from `ConfigurationService`/usage sweep): `NODE_ENV`, `PORT`,
`LOG_LEVEL`, `DATABASE_URL` (+ `IDENTITY_REGISTRY_DRIVER` = `postgres`|`memory`), `REDIS_URL` /
`REDIS_HOST`/`PORT`/`PASSWORD`/`TLS` + `REDIS_ENABLED`, `OIDC_ISSUER` (**default
`https://identity.bookwrm.com`** hard-coded as `OIDCService.DEFAULT_ISSUER`), `JWT_PRIVATE_KEY` /
`OIDC_JWKS_JSON`, `OIDC_KEY_ROTATION_INTERVAL_SECONDS`, `OIDC_RATE_LIMIT_IP/CLIENT/USER`,
`HAPI_PLATFORM_SERVICE_KEY` (service-to-service bearer for `/internal/*` + bridge + admin),
feature flags `OIDC_ENABLED`, `HAPI_UNIVERSAL_LOGIN_ENABLED` (**default false**),
`MOCK_AUTH_ENABLED`, `PRIVATEID_MOCK_MODE`, `CACHE_ENABLED`, `METRICS_ENABLED`, plus PrivateID and
email-provider (Resend) credentials and Base44 client settings.

**Migration strategy:** there is **no numbered-migration framework**. Five idempotent DDL files
(`CREATE TABLE IF NOT EXISTS` + guarded `ALTER`/`DO $$` blocks) are re-applied on every boot, and
`schema_migrations` records a version label once. This is additive-safe but provides no ordering,
no down-migrations, and no per-change audit. V2's additive migrations can follow the same pattern,
but each tranche should add an explicit `schema_migrations` version row and keep every statement
idempotent.

**Topology:** single Fastify process on Railway; Postgres is system of record; Redis holds all
OIDC protocol state (codes, tokens, interactions, rate limits, key-rotation coordination, audit
stream) with an `ioredis-mock` fallback when Redis is disabled (protocol state then being
process-local — single-instance assumption).

---

## 16. Determination: browser-facing authorization endpoint

**The existing `GET /authorize` + Universal Login (H6.11) is a genuine, standards-shaped,
browser-facing authorization front end** — validated client/redirect/scope/response_type/PKCE,
single-use server-side interaction, CSRF, no-store headers, hosted email-OTP and Face pages, code
issuance bound to client+redirect+PKCE. **A new parallel front end is NOT needed.** It is,
however, insufficient for V2 native SSO as-is:

1. Feature-flagged off by default (`HAPI_UNIVERSAL_LOGIN_ENABLED`), and not in the deployed
   production build at all.
2. No persistent HAPI session → no SSO reuse, no account chooser, no `prompt`/`max_age` semantics.
3. No Apple/Google choices; `idp_hint` hard-rejected.
4. No consent step.
5. Nonce late-failure quirk (§5) should be fixed to fail at `/authorize`.
6. No registration entry point for first-time users arriving from a native client (registration is
   a separate H3 service API; Universal Login email flow handles `REGISTRATION` mode via
   `InteractiveEmailAuthentication`, which mitigates this — verified in
   `tests/UniversalLogin.test.ts`).

**The H4 POST `/authorize` handoff is not a native-app flow** — it is a server-mediated,
service-authenticated exchange for the Bookwrm web app. Native clients must use the GET front end
with the system browser.

---

## 17. Gap analysis vs. V2 requirements

| # | V2 requirement | Current state | Gap class |
|---|---|---|---|
| G-1 | Universal identity registry (B) | `identity_subjects` solid, immutable `oidc_subject`; but single `(primary_provider, primary_provider_subject)` pair per subject | **Additive schema**: `external_identities`, `authentication_methods`, `account_link_audit` |
| G-2 | Apple federation (C) | None (type enum placeholder only) | New module |
| G-3 | Google federation (D) | None | New module |
| G-4 | Secure account linking (E) | `IdentityMergeService` (admin-only merge) + Bookwrm service-auth linking exist; no end-user flow, no recent-auth, no provider conflict workflow | New feature on top of session layer |
| G-5 | Native OAuth client registry (F) | Schema + token path support `none`+PKCE today; no public clients registered; no per-platform registrations | Mostly registration + tests |
| G-6 | Browser-facing authorization (G) | Exists (Universal Login) — see §16 caveats | Extend, don't rebuild |
| G-7 | Refresh tokens (H) | Issued but unredeemable; plaintext-keyed; no rotation/family/reuse detection/revocation | **Core build** |
| G-8 | Sessions/devices (H, E, K) | None | **Core build** |
| G-9 | Issuer migration (I) | Single env-driven issuer; hard-coded Bookwrm default; exact-issuer validation everywhere (good) | Plan + config work; no dual-issuer trust exists to misuse |
| G-10 | Passkeys (J) | Type placeholder only | Interface design only (deferred) |
| G-11 | Security ops (K) | Strong audit/rate-limit base; `oidc_clients.client_secret` stored plaintext; refresh tokens plaintext; no revocation endpoint; vestigial `/oidc/*` engine | Hardening items |
| G-12 | Certification suites (L) | 500+ tests, strong negative coverage for existing flows; nothing for federation/refresh/native/issuer | Grows with each tranche |

Additional hardening notes for V2 scope: remove or fence the vestigial `oidc-provider` mount
(§4); hash client secrets at rest (G-11); fix the nonce early-validation quirk (§5); the
TEMPORARY Patch 6.5 redirect-validation log line and Patch 8.4 diagnostics table are still
present and flagged for removal after certification.

---

## 18. Proposed first development tranche (V2-B) — for approval

**Scope: identity registry & client model — additive migrations + isolated tests. No public
feature activation, no production deployment, no credential changes.**

1. **Additive schema (new file, e.g. `src/identity/schema-v2.sql`, applied after existing DDL;
   every statement idempotent; one new `schema_migrations` version row):**
   - `external_identities`: `id`, `identity_subject_id` FK, `provider` CHECK (`APPLE`,`GOOGLE`),
     `provider_issuer`, `provider_subject`, `provider_client_context`, `status`
     (`linked`/`revoked`), `linked_at`/`revoked_at`/`last_authenticated_at`, security metadata;
     `UNIQUE (provider, provider_issuer, provider_subject)` and
     `UNIQUE (identity_subject_id, provider)` (one linked identity per provider per subject).
   - `identity_authentication_methods`: `id`, `identity_subject_id` FK, `method_type` CHECK
     (`HAPI_EMAIL`,`APPLE`,`GOOGLE`,`PASSKEY`), `external_identity_id` nullable FK, state
     (`verified`/`linked`/`revoked`), `last_used_at`; partial unique on active method per type.
     Backfill-view (not data rewrite): existing subjects' `HAPI_EMAIL` methods derived additively;
     **existing `identity_subjects` rows and `oidc_subject` values are never modified.**
   - `identity_link_audit`: append-only — initiating subject, provider, keyed external-identity
     reference, evidence reference (challenge/assertion hash id), correlation id, action, outcome,
     occurred_at. Server-generated ids; no raw tokens (matches existing audit conventions).
2. **Repositories + services (isolated, no route activation):** `ExternalIdentityRepository`
   (Postgres + in-memory), uniqueness/conflict semantics enforced in SQL, atomic link/unlink with
   last-method protection, audit writes in the same transaction.
3. **Native client model groundwork:** seedless registration support for public clients (no new
   env-seeded clients), plus certification tests from the V2 matrix: public client without secret,
   PKCE mandatory, wrong redirect, wrong client, code replay, `token_endpoint_auth_method=none`
   never receives a confidential client's secret path.
4. **Two small correctness fixes tightly coupled to this tranche:** reject missing `nonce` at
   `GET /authorize` (early failure); stop issuing the unredeemable `refresh_token` from `/token`
   **or** gate issuance on client `grant_types` containing `refresh_token` (no registered client
   has it, so behavior for Bookwrm is unchanged) — eliminates the dead 30-day bearer liability
   before the real refresh architecture lands in V2-C.
5. **Tests:** Postgres-gated integration suites following the existing `*.postgres.test.ts`
   pattern + in-memory unit suites; every suite includes rejected/conflict paths (cross-subject
   link conflict, duplicate provider identity, last-method unlink rejection, idempotent retry).

**Explicitly out of tranche:** Apple/Google IdP code (V2-D), refresh rotation/sessions (V2-C),
issuer migration (V2-E), consent/account-management UI, any Railway change, any activation of
`allowed_identity_providers`.

**Pre-tranche operational recommendation (separate approval):** redeploy current `main` to
Railway to close the P0E version gap, and perform the read-only signing-key/environment
verification from the recovery plan — V2 certification against a SPRINT-7.75 production target is
meaningless.
