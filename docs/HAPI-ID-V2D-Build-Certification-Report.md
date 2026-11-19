# HAPI ID V2-D — Build & Certification Report

## Apple/Google Federation & Universal Account Linking

Date: 2026-11-19
Branch: `feature/hapi-id-v2d` (branched from V2-C `d55480d`; local only, never pushed)
Status: **Development-complete, isolated. Nothing is deployed, migrated, or activated.**

---

## 1. Phase 0 — V2-C preservation audit (all checks passed)

1. **Commits intact**: `2e3a6a4`, `ddfda81`, `cbf91d0`, `d55480d` present; working tree clean
   before branching.
2. **No deploy-branch exposure**: `d55480d` is not an ancestor of `origin/main` or ANY remote
   branch; `feature/hapi-id-v2c` exists locally only. Nothing was pushed by V2-D either.
3. **Test-count reconciliation (empirical)**: V2-B baseline `547 passed / 119 skipped`. V2-C added
   67 tests, of which 48 run in the default (no-DB) configuration and 19 are PostgreSQL-gated:
   547 + 48 = **595 passed** and 119 + 19 = **138 skipped** — re-verified by running the suite at
   `d55480d` before any V2-D change (`64 files / 595 passed / 138 skipped`). The three reported
   numbers are mutually consistent; total test count is 547 + 67 = 614 runnable-anywhere tests.
4. **Session/refresh security review**: no unresolved concerns found. Verified: secrets stored
   only as SHA-256 hashes (unique-indexed, fail-closed); fixation protection revokes the presented
   pre-auth token before establishment; double-submit CSRF compared in constant time; idle windows
   capped by absolute ceilings; refresh reuse revokes the entire family; `__Host-` cookies.
5. **Schema additivity**: `schema-sessions.sql`, `schema-refresh.sql`, `schema-federation.sql`
   contain only `CREATE TABLE/INDEX IF NOT EXISTS` — no `ALTER`, no row rewrites — and all V2-C
   behavior remains behind default-off flags.

## 2. Deliverable 1-2 — Branch, commits, implementation files

Commits on `feature/hapi-id-v2d` (full head SHA reported with the delivery message):

| Commit | Content |
| --- | --- |
| `a0a6be1` | Phases 1-2: federation core (Google verifier, Apple client secret, transactions, authorization service, identity resolution, `markAuthenticated`) |
| `50fcd12` | Phases 3-4: Universal Login federation + authenticated account-linking API + flags |
| `40a6d8b` | Phase 6: 53 new security tests |
| (this commit) | Phase 5 design + this report |

**New files**

- `src/identity/federation/FederatedIdentityTypes.ts` — shared `VerifiedFederatedIdentity` +
  verifier interface.
- `src/identity/federation/GoogleIdentityTokenVerifier.ts` — server-only Google id_token
  verification (JWKS RS256, both exact issuer forms canonicalized to one identity key, registered
  audience, required nonce, expiry; unverified emails suppressed entirely).
- `src/identity/federation/AppleClientSecretService.ts` — per-exchange ES256 client-secret JWT
  from `APPLE_TEAM_ID`/`APPLE_SERVICES_ID`/`APPLE_KEY_ID`/`APPLE_CLIENT_SECRET_KEY`; key material
  never logged, persisted, or echoed.
- `src/identity/federation/FederationTransactionStore.ts` — Redis-backed single-use login/link
  transactions; 32-byte random state and nonce; keys are SHA-256 digests; 5-minute TTL.
- `src/identity/federation/FederatedAuthorizationService.ts` — authorization-URL construction
  (exact registered redirect URI, Apple `form_post`), server-side code exchange
  (injectable exchanger; HTTP impl used only under live configuration), callback handling that
  consumes state FIRST, typed denial/error mapping, full id_token verification bound to the
  transaction nonce. Errors never carry codes, secrets, or provider bodies.
- `src/identity/federation/FederatedIdentityResolutionService.ts` — the only bridge from verified
  provider identity to HAPI identity: linked-login resolution, safe first-time registration
  (always a NEW subject), `/token` link-liveness check. Email never participates in any lookup.
- `src/routes/accountAuthenticationMethods.ts` — the V2-C Phase 4 API (see §4).
- `docs/HAPI-ID-V2D-Native-Client-Readiness.md` — Phase 5 design.

**Modified files**

- `src/oidc/OIDCService.ts` — federated Universal Login routes + callbacks, "Continue as"
  session continuation, EXTERNAL_OIDC capability mapping, federated `/token` eligibility
  (revocation fail-closed), honest `amr`/`auth_time` (`["apple","fed"]`, `["google","fed"]`),
  optional fixation-safe session establishment at login completion.
- `src/oidc/UniversalLoginPages.ts` — Continue with Apple/Google buttons, explicit
  account-choice page, Continue-as rendering (all invisible while flags are off; flag-off HTML is
  byte-identical).
- `src/oidc/AuthorizationInteractionStore.ts` — server-written `federation` pending state.
- `src/identity/{ExternalIdentityRepository, InMemory…, Postgres…}` — `markAuthenticated`
  (metadata-only; never mutates linking state).
- `src/identity/IdentityFederationService.ts` — exact-triple lookup + markAuthenticated
  passthroughs.
- `src/models/OIDCAuthorizationCode.ts`, `src/authentication/AuthenticationProvider.ts` —
  `APPLE`/`GOOGLE` authentication-method values.
- `src/config/FeatureFlagService.ts`, `src/config/ConfigurationService.ts` — new default-off
  flags + credential configuration readers (undefined until EVERY value is present).
- `src/server.ts` — registers the (flag-gated) account-linking API.

**Migrations: none.** V2-D reuses the V2-B/V2-C schema unchanged; no new tables, no `ALTER`, no
production migration exists or is required for this tranche.

**New default-off feature flags**

| Flag | Default | Controls |
| --- | --- | --- |
| `HAPI_APPLE_FEDERATION_ENABLED` | OFF | Apple buttons, launch route, Apple callback |
| `HAPI_GOOGLE_FEDERATION_ENABLED` | OFF | Google buttons, launch route, Google callback |
| `HAPI_ACCOUNT_LINKING_API_ENABLED` | OFF | the whole `/account/authentication-methods` surface |

With all V2-D flags off the platform is byte-identical to V2-C (asserted by the unchanged 595
pre-existing tests plus explicit flag-off tests).

## 3. Deliverable 3 — Apple & Google federation certification

All certification is synthetic (generated JWKS, synthetic codes, injected exchanger); **no live
Apple or Google endpoint, credential, or identity is involved anywhere**, and the HTTP exchanger
is reachable only under explicit production configuration that does not exist.

| Requirement | Outcome |
| --- | --- |
| HAPI-hosted initiation | ✅ chooser → POST launch → 303 to provider with exact registered values |
| Cryptographically random state and nonce | ✅ 32-byte server-generated per transaction; browser never chooses either |
| Strict redirect validation | ✅ provider `redirect_uri` is fixed server config; RP redirect URIs exact-match as before |
| Server-side code exchange | ✅ injectable exchanger; code replay/injection fails closed (`code_exchange_failed`) |
| Apple client-secret JWT | ✅ ES256, `iss`=team, `sub`=services id, `aud`=appleid.apple.com, kid header, 5-min TTL, 6-month cap, no leakage |
| JWKS signature verification | ✅ RS256 only; rogue-key tokens rejected |
| Exact issuer/audience | ✅ Apple exact; Google both documented forms, canonicalized; everything else `wrong_issuer`/`wrong_audience` |
| Expiry + nonce validation | ✅ expired rejected; nonce REQUIRED and constant-time compared against the transaction |
| Stable subject extraction | ✅ `sub` only; missing subject rejected |
| Private relay handling | ✅ flagged via claim and domain; relay addresses displayable but never identity keys |
| Verified-email handling (Google) | ✅ unverified email never surfaced at all |
| Explicit linking | ✅ account-linking API only (§4); login NEVER links to an existing subject |
| Safe first-time registration | ✅ explicit user choice → brand-new subject + atomic link; registration race → conflict, fail closed |
| Revocation/failure handling | ✅ denial/error → recovery chooser; unlink/revocation between code issuance and `/token` → `invalid_grant`; locked subjects refused |
| Single authoritative registry | ✅ both providers resolve exclusively through `identity_subjects` + `external_identities` |
| No email-based merging | ✅ a Google identity with an email equal to an existing HAPI account still requires explicit choice and produces a NEW subject |

## 4. Deliverable 4 — Account-linking API & login UX results

API (`/account/authentication-methods`, flag-gated, implements the certified V2-C design 1:1):

| Design requirement | Result |
| --- | --- |
| List methods (incl. derived HAPI_EMAIL, `canUnlink`, recent-auth context) | ✅ |
| Initiate linking (single-use nonce transaction bound to subject + session) | ✅ |
| Complete via server-verified provider id_token + transaction nonce | ✅ |
| Recent authentication (600 s) → 428 `step_up_required` | ✅ on start/complete/unlink |
| Explicit confirmation | ✅ linking only ever happens via the two-step start/complete ceremony |
| Already-linked detection | ✅ 409 `provider_already_linked` |
| Cross-account conflicts | ✅ 409 `provider_identity_in_use`, owner never revealed |
| Last-method protection | ✅ 409 `last_method` (repository-enforced, audited) |
| Atomic transactions + append-only audit | ✅ V2-B repository contract (PostgreSQL single-transaction link/unlink + audit row) |
| CSRF + rate limits | ✅ `X-HAPI-CSRF` double-submit on every mutation; per-IP/per-subject limits |
| Browser-supplied issuer/subject never trusted | ✅ only `identityToken` is accepted as evidence; asserted-identity bodies are rejected outright |
| Untrusted/stale sessions blocked | ✅ unknown cookie → 401; revoked/expired session → 401 `stale_session`; transactions die with their session |
| Unlink hygiene | ✅ sessions established via the unlinked provider are revoked, cascading to their refresh-token families |

Universal Login (Phase 4): Continue with Email / Apple / Google (capability- and flag-gated),
existing-session detection with "Continue as …", returning-user resolution through the identity
registry, explicit account-choice page, recovery back to the chooser on provider
denial/failure, and the Bookwrm email/OTP flow untouched (its entire pre-existing suite passes
unchanged). Authentication-method management is served by the §4 API; a dedicated management UI
remains for a UI tranche.

All methods produce a HAPI-issued OIDC assertion for the same HAPI subject once securely linked
(verified end-to-end in tests: Apple login, Google registration, email, and session continuation
all mint codes for `identity_subjects.oidc_subject` with honest `amr`).

## 5. Deliverable 5 — Native-client readiness

See `docs/HAPI-ID-V2D-Native-Client-Readiness.md`. Key result: the existing `/authorize` and
`/token` already satisfy every native requirement (public client, PKCE S256 enforced, replay and
cross-client rejection, exact redirect URIs, nonce fail-fast, native refresh lifetimes), re-run
green on this branch. No production native client registered.

## 6. Deliverable 6 — Full regression results

Environment: Node v24, Vitest 4.1.10, default (no-DB) configuration.

| Run | Result |
| --- | --- |
| V2-C baseline re-verification (at `d55480d`, before changes) | 64 files / **595 passed** / 138 skipped / 0 failed |
| Full suite with V2-D (all flags default-off) | 69 files / **648 passed** / 138 skipped / **0 failed** |
| New V2-D tests | **53** (11 Google verifier, 4 Apple client secret, 11 federation round-trip, 13 federated Universal Login, 14 account-linking API) |
| `npx tsc --noEmit` | clean |
| `npm run build` (production) | clean; federation sources emitted to `dist/` |
| V2-B native public-client suite | 6/6 re-verified |

Every pre-existing V2-B and V2-C test passes unchanged. The PostgreSQL-gated suites (138) are
environment-gated exactly as in V2-C and unchanged by V2-D (no schema or repository-contract
changes besides the additive `markAuthenticated`, which the shared in-memory/PG contract tests
exercise through the login path).

## 7. Deliverable 7 — Threat model & remaining gaps

**Mitigated by design (tested):**

- Forged/replayed provider callbacks → single-use state consumed before any other processing.
- Callback injection (valid token from another transaction) → nonce binding fails verification.
- Authorization-code replay/theft at the provider exchange → server-side exchange fails closed.
- Provider-token forgery (wrong key/issuer/audience/expiry/subject) → verifier matrix.
- Email-based account takeover → email is display metadata everywhere; no lookup uses it.
- Cross-account link grafting → DB-unique active triple; owner never disclosed on conflict.
- Login CSRF on linking → session + double-submit CSRF + subject/session-bound transactions.
- Session fixation → establishment revokes any presented session token first.
- Stale-session abuse of linking → resolveSession fails closed; 401 `stale_session`.
- Secret/token leakage → only hashes persisted/audited; typed errors; detail-free exchange and
  verification failures; Apple key never echoed.
- Post-issuance revocation → federated authorization codes re-check link liveness at `/token`.

**Remaining gaps (explicitly out of V2-D, for the activation tranche):**

1. **Login CSRF at the provider callback** is mitigated by single-use state but, like all
   upstream-IdP flows, final defense rests on the RP's own `state` (present and enforced by the
   RP contract). The Google GET callback could additionally require the interaction cookie;
   Apple's cross-site `form_post` structurally cannot.
2. **Apple server-to-server revocation notifications** (and Google Cross-Account Protection /
   RISC) are not consumed; revocation currently takes effect at unlink or `/token` re-check, not
   push-initiated. Requires live credentials — activation-tranche work.
3. **First-login race orphan**: if first-time registration loses the linking race, the freshly
   minted subject row remains (unusable, never authenticated). Harmless but worth a sweeper.
4. **Account-linking rate limits** reuse the shared OIDC limiter buckets; a dedicated tighter
   bucket for `link/complete` is recommended before activation.
5. **No management UI** for authentication methods yet (API-only).
6. Apple `user` payload (first-login name) is ignored by design; display-name capture can be
   added later without protocol changes.

## 8. Deliverable 8 — Required provider configuration (for the activation tranche)

**Apple Developer (Sign in with Apple):**

1. App ID (Elite+ iOS bundle) with Sign in with Apple capability.
2. **Services ID** (e.g. `com.hapiinc.id`) → becomes `APPLE_SERVICES_ID` (OAuth `client_id`).
3. Sign in with Apple **Key** (ES256) → `APPLE_KEY_ID` + downloaded `.p8` → `APPLE_CLIENT_SECRET_KEY`.
4. `APPLE_TEAM_ID` (developer team).
5. Registered return URL: `https://id.hapiinc.com/federation/apple/callback` (exact) → `APPLE_REDIRECT_URI`.
6. Domain verification for the issuer host; later: server-to-server notification endpoint.

**Google Cloud (OAuth consent + credentials):**

1. OAuth consent screen (production, external), scopes `openid email profile`.
2. Web application OAuth client → `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.
3. Authorized redirect URI: `https://id.hapiinc.com/federation/google/callback` (exact) → `GOOGLE_REDIRECT_URI`.
4. Later: RISC/Cross-Account Protection subscription.

All five Apple values and all three Google values must be present or the provider simply does not
exist at runtime (partial configuration can never launch a live authorization). Secrets belong in
Railway environment configuration, never in the repository.

## 9. Deliverable 9 — Controlled production deployment plan (NOT executed)

1. **Stage 0 (inert ship)**: merge V2-D with all flags off → production behavior byte-identical;
   schema already additive and bootstrapped.
2. **Stage 1 (staging activation)**: staging issuer + staging Apple Services ID/Google client;
   enable `HAPI_GOOGLE_FEDERATION_ENABLED` (Google first: simpler callback), run the §3 matrix
   live; then Apple.
3. **Stage 2 (linking)**: enable `HAPI_PERSISTENT_SESSIONS_ENABLED` + `HAPI_ACCOUNT_LINKING_API_ENABLED`
   in staging; exercise link/unlink/step-up with real provider round-trips.
4. **Stage 3 (production canary)**: enable Google federation for an internal-tester Application
   only (capability `EXTERNAL_OIDC` is per-application, giving a natural canary boundary); monitor
   `identity_link_audit`, `APPLICATION_AUTHENTICATION` events, and error rates; then Apple.
5. **Stage 4**: account-linking API in production; last: native-client registration per the
   Phase 5 design.
6. **Rollback** at every stage = flip the flag off (no migration, no data rewrite; linked
   identities simply become dormant rows).
7. Issuer cutover to `id.hapiinc.com` remains a separate approved tranche and precedes provider
   registration going live (provider redirect URIs are issuer-anchored).

## 10. Deliverable 10 — Recommended V2-E scope

1. Issuer cutover plan execution (`identity.bookwrm.com` → `id.hapiinc.com`) with dual-issuer
   transition support.
2. Live provider activation per §9 (staging first), including Apple server-to-server revocation
   notifications and Google RISC consumption.
3. Authentication-method management + device/session management UI on the V2-D API.
4. Native client registration + device-lab certification (Phase 5 checklist) and production
   refresh-grant activation for the native profile.
5. Dedicated rate-limit buckets and audit dashboards for the linking surface; orphan-subject
   sweeper (§7.3).
6. PASSKEY method groundwork (schema already reserves the method type).

## 11. Release-restriction compliance

| Restriction | Status |
| --- | --- |
| No Railway deployment | ✅ nothing pushed; branch is local-only |
| No production DB migration | ✅ no new schema at all |
| No live Apple/Google authorization | ✅ no credentials exist; HTTP exchanger unreachable without them; flags off |
| No issuer cutover | ✅ untouched |
| No production refresh-grant activation | ✅ flag untouched (off) |
| No automatic identity merging | ✅ structurally impossible (no email lookups; explicit choice required) |
| No PrivateID activation | ✅ untouched |
| No push to deploying branches | ✅ verified `git branch -r --contains` empty for all V2-D commits |
