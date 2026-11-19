# HAPI ID V2-D — Apple/Google Federation & Universal Account Linking Build Report

Date: 2026-11-19
Repository: bookwrm-identity-services
Branch: `feature/hapi-id-v2d` (local only, never pushed)
Head: `21892b4bb7e72adfd0b24885fc4e1e27369e5231`
Status: **Development-complete, isolated. Nothing is deployed, migrated, or activated.**

Companion documents:

- [HAPI-ID-V2D-Build-Certification-Report.md](./HAPI-ID-V2D-Build-Certification-Report.md) —
  full certification evidence, threat model, and activation plan.
- [HAPI-ID-V2D-Native-Client-Readiness.md](./HAPI-ID-V2D-Native-Client-Readiness.md) — Phase 5
  native-client design.
- [HAPI-ID-V2C-Account-Linking-API-Design.md](./HAPI-ID-V2C-Account-Linking-API-Design.md) — the
  API contract implemented 1:1 in this tranche.

## Executive Summary

HAPI ID V2-D delivers server-only Sign in with Apple and Google federation through Universal
Login, plus the authenticated universal account-linking API certified in V2-C. All new behavior
is behind default-off feature flags; with flags off the platform is byte-identical to V2-C.

Completed outcomes:

- Apple and Google upstream federation core: id_token verification, Apple ES256 client-secret
  minting, single-use Redis-backed state/nonce transactions, server-side code exchange, and
  strict typed error handling with no secret or provider-body leakage.
- Federated identity resolution as the single bridge from verified provider identity to HAPI
  identity: linked-login resolution, safe first-time registration (always a NEW subject, never
  email-based merging), and `/token` link-liveness re-checks.
- Universal Login federation UX: Continue with Apple/Google, existing-session "Continue as …",
  explicit account-choice page, and recovery back to the chooser on provider denial/failure. The
  Bookwrm email/OTP flow is untouched.
- Authenticated account-linking API (`/account/authentication-methods`): list / link-start /
  link-complete / unlink with 600 s step-up, double-submit CSRF, last-method protection,
  cross-account conflict refusal (owner never revealed), and unlink session/refresh cascade.
- Native-client readiness certified against the existing `/authorize` + `/token` surface
  (public client, PKCE S256, exact redirect URIs, replay and cross-client rejection).
- 53 new security tests; all pre-existing V2-B/V2-C tests pass unchanged.

Validation outcomes (Node v24, Vitest 4.1.10, default no-DB configuration):

- V2-C baseline re-verification at `d55480d`: 64 files / 595 passed / 138 skipped / 0 failed
- Full suite with V2-D (flags default-off): 69 files / **648 passed** / 138 skipped / **0 failed**
- `npx tsc --noEmit`: clean
- `npm run build` (production): clean
- V2-B native public-client suite: 6/6 re-verified

## Commits

| Commit | Content |
| --- | --- |
| `a0a6be1` | Phases 1-2: federation core (Google verifier, Apple client secret, transactions, authorization service, identity resolution, `markAuthenticated`) |
| `50fcd12` | Phases 3-4: Universal Login federation + authenticated account-linking API + flags |
| `40a6d8b` | Phase 6: 53 new security tests |
| `21892b4` | Phase 5 design + build & certification report |

## Implementation Delivered

New modules (all under `src/identity/federation/` unless noted):

- `FederatedIdentityTypes.ts` — shared `VerifiedFederatedIdentity` + verifier interface.
- `GoogleIdentityTokenVerifier.ts` — JWKS RS256 verification, canonicalized issuer forms,
  registered audience, required nonce, expiry; unverified emails suppressed entirely.
- `AppleClientSecretService.ts` — per-exchange ES256 client-secret JWT; key material never
  logged, persisted, or echoed.
- `FederationTransactionStore.ts` — single-use login/link transactions; 32-byte random state and
  nonce; SHA-256-digest keys; 5-minute TTL.
- `FederatedAuthorizationService.ts` — authorization-URL construction, server-side code exchange
  (injectable exchanger; HTTP impl reachable only under live configuration), state consumed
  first, nonce-bound id_token verification.
- `FederatedIdentityResolutionService.ts` — the only provider-identity → HAPI-identity bridge;
  email never participates in any lookup.
- `src/routes/accountAuthenticationMethods.ts` — the account-linking API.

Modified: `src/oidc/OIDCService.ts`, `src/oidc/UniversalLoginPages.ts`,
`src/oidc/AuthorizationInteractionStore.ts`, external-identity repositories
(`markAuthenticated`, metadata-only), `src/identity/IdentityFederationService.ts`,
`src/models/OIDCAuthorizationCode.ts`, `src/authentication/AuthenticationProvider.ts`,
`src/config/FeatureFlagService.ts`, `src/config/ConfigurationService.ts`, `src/server.ts`.

Migrations: **none** — V2-D reuses the V2-B/V2-C schema unchanged.

## Feature Flags (all default OFF)

| Flag | Controls |
| --- | --- |
| `HAPI_APPLE_FEDERATION_ENABLED` | Apple buttons, launch route, Apple callback |
| `HAPI_GOOGLE_FEDERATION_ENABLED` | Google buttons, launch route, Google callback |
| `HAPI_ACCOUNT_LINKING_API_ENABLED` | the whole `/account/authentication-methods` surface |

Provider credentials (`APPLE_TEAM_ID`/`APPLE_SERVICES_ID`/`APPLE_KEY_ID`/
`APPLE_CLIENT_SECRET_KEY`/`APPLE_REDIRECT_URI`, `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`/
`GOOGLE_REDIRECT_URI`) must ALL be present or the provider does not exist at runtime.

## Test Delivery

53 new tests, all synthetic (generated JWKS, synthetic codes, injected exchanger — no live Apple
or Google endpoint, credential, or identity anywhere):

| Suite | Tests |
| --- | --- |
| Google id_token verifier matrix | 11 |
| Apple client-secret service | 4 |
| Federated authorization round-trip | 11 |
| Federated Universal Login | 13 |
| Account-linking API | 14 |

## Release-Restriction Compliance

- No Railway deployment; no push to any deploying branch (verified: no remote contains any
  V2-D commit).
- No production DB migration (no new schema at all).
- No live Apple/Google authorization (no credentials exist; flags off).
- No issuer change; no production refresh-grant activation; no PrivateID activation.
- No automatic identity merging — structurally impossible (no email lookups; explicit user
  choice always required).

## Next Steps (recommended V2-E scope)

1. Issuer cutover execution (`identity.bookwrm.com` → `id.hapiinc.com`) with dual-issuer support.
2. Staged live provider activation (Google first, staging first) per the certification report §9,
   including Apple server-to-server revocation notifications and Google RISC.
3. Authentication-method + session management UI on the V2-D API.
4. Native client registration and device-lab certification; production refresh-grant activation
   for the native profile.
5. Dedicated linking rate-limit buckets, audit dashboards, orphan-subject sweeper.
