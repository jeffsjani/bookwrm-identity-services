# HAPI ID V2-B — Build & Certification Report

Date: 2026-11-19
Branch: `main` (local)
Tranche authority: approved HAPI ID V2-B isolated development scope (follows the committed V2-A
audit, `docs/HAPI-ID-V2A-Architecture-Gap-Audit.md`, commit `4b88e10`).

**Scope guarantees honored:** no Railway deployment, no production data migration, no Apple/Google
federation activated, no public linking endpoints exposed, no native production client registered,
no HAPI issuer migration, no existing identity record reassigned, no new production identity
created.

---

## 1. Exact files and migrations created/changed

### Phase 0 — audit preservation

`docs/HAPI-ID-V2A-Architecture-Gap-Audit.md` was already committed as `4b88e10` before any
implementation change. Working tree confirmed; prior-tranche P0 artifacts that were still
uncommitted were preserved in `6490d81` (`tests/P0SecurityGapAudit.synthetic.test.ts`,
`docs/Build-Report-2026-11-17.md`, `docs/recovery/*`).

### Phases 1–2 — federation foundation (commit `01f6398`)

| File | Role |
| --- | --- |
| `src/identity/schema-federation.sql` | **New migration** — additive, idempotent DDL: `external_identities`, `identity_authentication_methods`, `identity_link_audit` + partial unique indexes. |
| `src/identity/infrastructure/PostgresInfrastructure.ts` | Applies the ordered DDL files, records schema version `1.1.0` ("Universal identity federation foundation (V2-B)") exactly once, adds `withPostgresTransaction`. |
| `src/models/ExternalIdentity.ts` | External identity / authentication method / link-audit domain types. |
| `src/identity/ExternalIdentityRepository.ts` | Repository contract + keyed `providerSubjectRef` (SHA-256; raw provider subjects never audited). |
| `src/identity/PostgresExternalIdentityRepository.ts` | Transactional system of record (subject row lock → validate → mutate → audit, all-or-nothing). |
| `src/identity/InMemoryExternalIdentityRepository.ts` | Test-only mirror of the same invariants. |
| `src/identity/IdentityFederationService.ts` | Linking policy layer: link / detect-conflict / unlink / list methods / list audit. **Not wired to any HTTP route.** |
| `package.json` | Build copies `schema-federation.sql` into `dist/`. |
| `tests/IdentityFederation.test.ts`, `tests/IdentityFederation.postgres.test.ts`, `tests/SchemaVersioning.postgres.test.ts` | New/updated tests. |

### Phases 3–4 — public-client certification + nonce/refresh policy (commit `3167f72`)

| File | Role |
| --- | --- |
| `src/oidc/OIDCService.ts` | Nonce fail-fast at `/authorize`; refresh token issued only when the client registration includes the `refresh_token` grant. |
| `tests/NativePublicClientCertification.test.ts` | Phase 3 certification suite (6 tests). |
| `tests/NonceAndRefreshTokenPolicy.test.ts` | Phase 4 policy suite (4 tests). |
| `tests/OIDCServiceMultiTenantFoundation.test.ts` | Two fixture `/authorize` URLs now carry a nonce (their flows could never have completed token exchange without one). |

### Documentation (this commit)

`docs/HAPI-ID-V2B-Build-Certification-Report.md` (this report),
`docs/HAPI-ID-V2B-Refresh-Token-Family-Design.md` (deliverable 6).

## 2. Test results

Environment: Node v24.x, Vitest 4.1.10, disposable PostgreSQL 16 (Docker, fresh databases).
`npx tsc --noEmit` and `npm run build`: clean.

| Run | Result |
| --- | --- |
| Full default suite (`npx vitest run`, no DB env — repo convention) | **60 files passed, 547 tests passed, 0 failed** (119 integration tests skipped by design) |
| Federation integration (`IdentityFederation.postgres.test.ts`, fresh DB) | **9/9 passed** |
| `DATABASE_URL` suites (SchemaVersioning, TenantApplicationFoundation, IdentityRegistry, IdentityClaimProvenance, IdentityFederation; serial, fresh DB) | **27/27 passed** |
| Isolated-schema integration suites (EmailAuthentication, MultiClientFoundation, EmailVerification, P0SecurityGapAudit, Registration, HapiFaceEnrollment, IdentityFederation) | **7 files, 104/104 passed** |

New tests added by V2-B: 13 (federation policy) + 9 (federation PostgreSQL) + 6 (public-client
certification) + 4 (nonce/refresh policy) = **32**. All pre-existing authentication and OIDC tests
pass unchanged except the two fixture URLs noted above.

Known pre-existing harness constraints (verified unchanged with V2-B stashed): the Postgres
integration suites are designed for targeted/serial runs — `SchemaVersioning.postgres` requires an
already-bootstrapped database, and `IdentityRegistry.postgres` leaves subjects that collide with
`TenantApplicationFoundation.postgres` cleanup when both share one database in a single process.
Neither affects production code.

## 3. Transactional linking and uniqueness proof

Database-enforced (not application-trusted) invariants, each proven by a dedicated test in
`tests/IdentityFederation.postgres.test.ts` against real PostgreSQL:

1. **Atomicity** — identity row, authentication-method row and audit row commit in one
   transaction ("links, persists the method, and writes the audit row in the same transaction");
   a conflicted link leaves **no** identity row, **no** method row, only the rejection audit
   ("keeps a failed link fully rolled back").
2. **Exact-identity uniqueness** — partial unique index
   `external_identities_provider_identity_active_key (provider, provider_issuer,
   provider_subject) WHERE status = 'linked'`; raw INSERT of a duplicate fails with `23505`.
3. **Fail-closed concurrency** — two subjects racing for the same provider identity resolve to
   exactly one `linked` + one `conflict`; the loser's rejection is durably audited after its
   transaction rolled back.
4. **Unlink floor** — concurrent unlinks are serialized by the subject row lock and can never
   race a subject to zero usable authentication methods ("never races two concurrent unlinks
   down to zero").
5. **No email-based merging** — the service API cannot express an email; a second subject
   carrying the same verified email links only where explicitly directed (in-memory suite,
   "never links or merges based on a matching email address").
6. **Immutability** — `oidc_subject` / primary provider identifiers verified unchanged across
   link, unlink and attack attempts.

## 4. Public-client certification outcomes (Phase 3)

All against isolated development/test clients; no production client registered.

| Requirement | Outcome |
| --- | --- |
| `token_endpoint_auth_method=none` | ✅ secretless exchange succeeds (new suite + existing `OIDCTokenClientAuthentication`) |
| Authorization Code grant | ✅ only supported grant; others rejected `unsupported_grant_type` |
| PKCE S256 required | ✅ missing challenge rejected at `/authorize`; `plain` rejected; missing verifier rejected at `/token` |
| Exact redirect URI matching | ✅ near-miss variant rejected at `/authorize` and at `/token` (`invalid_grant`) |
| No embedded client secret | ✅ flow completes with no secret anywhere in the request |
| Invalid verifier rejected | ✅ `invalid_grant`, "PKCE validation failed" |
| Authorization-code replay rejected | ✅ second exchange of a consumed code → `invalid_grant` (locked single-use consume) |
| Wrong-client exchange rejected | ✅ `invalid_client`, "client_id does not match code" |
| Code expiration enforced | ✅ 60 s TTL; exchange past expiry → `invalid_grant` |

## 5. Nonce compatibility assessment (Phase 4)

**Audit finding:** the token endpoint has always rejected authorization codes whose stored nonce
is empty (`"nonce is missing on authorization code"`), and every issued ID Token carries the
nonce. The email-authorization schema already required a nonce. Therefore the platform's
*effective* policy has always been "nonce mandatory for every authentication transaction" — but a
client omitting it previously received an authorization code that could never be exchanged.

**Change made:** `/authorize` now rejects missing nonce up front with `invalid_request`
("nonce is required"). This is not a policy change; it surfaces the existing requirement at the
correct protocol step.

**Compatibility:** every client that can currently complete a login already sends a nonce (it
could not obtain tokens otherwise), so no functional client is affected. Strictly per OIDC Core,
nonce is OPTIONAL in the code flow; HAPI ID intentionally exceeds the floor as a replay-protection
policy. Client integration documentation for future native clients must state that `nonce` is
required (AppAuth-style libraries send one by default). Verified: live claim resolution, Universal
Login, email OTP handoff and PrivateID face flows all pass unchanged.

## 6. Refresh-token interim policy

Implemented and tested (see commit `3167f72`): refresh tokens are issued **only** to clients whose
persisted registration includes the `refresh_token` grant. Legacy Bookwrm behavior unchanged;
new registrations receive none; no refresh grant was added; discovery still advertises only
`authorization_code`. Risks and the rotating refresh-token **family** schema + lifecycle proposal
are the separate deliverable `docs/HAPI-ID-V2B-Refresh-Token-Family-Design.md`.

## 7. Railway production-version evidence (read-only, Phase 5)

No Railway CLI/token is available in this environment; evidence comes from Railway's GitHub
deployment records plus live read-only probes of `https://identity.bookwrm.com`.

1. **Deployed commit SHA:** GitHub deployments API (environment `fulfilling-spirit /
   production`) shows the latest deployment at 2026-11-16T16:36:15Z for
   **`666dc7583d81ec79cc0cd5b0ed2e71513a7b8468`** with status **success** (16:37:07Z). That SHA
   **is** current `origin/main`. Corroboration: `/health` uptime (247,329 s at probe time
   2026-11-19T13:19:08Z) back-computes to a boot at ≈2026-11-16T16:37Z — the exact deployment
   success time. The hardcoded `version: "6A.1"` string was **not** used as evidence.
2. **Discovery / grants:** live discovery matches source at `666dc75` — `response_types [code]`,
   `grant_types_supported ["authorization_code"]`, `code_challenge_methods ["S256"]`,
   `token_endpoint_auth_methods ["client_secret_basic","client_secret_post","none"]`, RS256.
3. **Browser-facing authorization flow:** **deployed and enabled.** `GET /login` serves the real
   Universal Login interaction page (the code path returns 404 when
   `HAPI_UNIVERSAL_LOGIN_ENABLED` is off, so the flag is on in production).
4. **Public-client registration:** the capability is deployed (`none` advertised; registration
   validation code is in `666dc75`). Production client IDs live in the persisted registry — the
   dev `base44-web` id is (correctly) unknown in production ("Unknown client").
5. **Refresh behavior vs source:** matches source at `666dc75` — refresh tokens are issued
   unconditionally there; the V2-B interim policy exists only in this undeployed tranche.
6. **Signing keys / environment:** `/health/ready` reports
   `configurationLoaded/redisInitialized/databaseConnected/keysLoaded/providerReady` all true,
   Base44 dependency healthy; `/jwks` serves an RS256 RSA key. No outstanding signing-key or
   environment issue observed.

**Conclusion:** production is **not** behind `origin/main`. The V2-A "~3 months behind / P0E
blocked" finding was resolved by the 2026-11-16 deployments. Production is behind local `main`
only by this V2-B tranche (docs + code intentionally not deployed). A separate controlled
deployment plan (DB compatibility → regression gates → rollback → approval) is required before
V2-B ships; note `ensureIdentitySchema` applies the additive federation DDL on boot, which is
idempotent and additive-only by design.

## 8. Commit SHAs and working-tree status

| Commit | Content |
| --- | --- |
| `4b88e10` | V2-A architecture & gap audit (Phase 0; committed before implementation) |
| `6490d81` | P0 synthetic security suite + recovery docs preservation |
| `01f6398` | Phases 1–2: universal identity federation foundation |
| `3167f72` | Phases 3–4: public-client certification, nonce fail-fast, interim refresh policy |
| (this commit) | V2-B certification report + refresh-token family design |

Working tree: clean after this commit (local `main` ahead of `origin/main` by the commits above;
nothing deployed or pushed as part of this tranche).

## 9. Recommended next implementation tranche (V2-C candidate — requires separate approval)

1. **Controlled deployment of V2-B to Railway** — the additive federation schema and OIDC policy
   changes, behind the plan gates in §7 (database compatibility check, full regression run,
   rollback procedure, explicit approval).
2. **Rotating refresh-token families** — implement
   `docs/HAPI-ID-V2B-Refresh-Token-Family-Design.md` behind a default-off flag with the refresh
   grant handler, reuse detection and RFC 7009 revocation.
3. **Apple sign-in server-side verification (still inactive)** — ID-token verification service
   (issuer/audience/expiry/nonce) feeding `IdentityFederationService.linkExternalIdentity` with
   verified issuer+subject pairs; synthetic-key tests only; no Apple credentials, no routes.
4. **Account-linking HTTP surface design** — authenticated linking/unlinking endpoints consuming
   the Phase 2 service, with step-up re-authentication requirements, exposed only behind a
   default-off flag.

Explicitly out of scope without new approval: V2-C execution, production deployment, provider
credentials, issuer migration, federation activation, native production client registration.
