# HAPI ID V2-E Stage 5A — Registration and Application Identity Foundation

**Status: CORE REGISTRATION CERTIFIED; APPLICATION OWNERSHIP LINKING AND LIVE PROVIDER ACCEPTANCE REMAIN OPEN.**

Date: 2026-11-22  
Branch: `feature/hapi-id-v2e-stage1`  
Baseline: `92caf54ae0236ec3314da160c7cd17cd3b16f5f6`  
Staging issuer: `https://id-staging.hapiinc.com`  
Planned production issuer: `https://id.hapiinc.com`

No runtime authentication code, configuration, staging identity, passkey, deployment, or production
resource was changed. This certification adds tests only.

## 1. BUILT / PARTIAL / MISSING inventory

| Area | Status | Evidence and boundary |
| --- | --- | --- |
| Email registration and return | **BUILT** | H2 verified OTP → H3 atomic registration/evidence/audit → original OIDC interaction. Existing HAPI_EMAIL accounts use H4 and retain their `oidc_subject`. |
| Google registration and return | **PARTIAL** | Verified exact provider identity; unknown users explicitly choose creation or email sign-in. Matching email never merges. First-time concurrency is now exercised against PostgreSQL, but subject creation and external binding are separate transactions. |
| Apple registration and return | **PARTIAL** | Same explicit choice and exact-identity binding. Added a first-time Apple test for returning-subject continuity and no same-email merge. As with Google, subject creation and external binding are separate transactions. |
| Passkey enrollment and authentication | **BUILT** | Post-authentication enrollment is bound to the canonical subject; credential authentication resolves that subject and its existing OIDC `sub`. PostgreSQL/Redis/Chromium tests cover enrollment, login, revocation, and failure paths. |
| Stable HAPI subject | **BUILT** | `identity_subjects.oidc_subject` is the canonical OIDC subject. Email, provider, and passkey paths resolve to their linked subject; email changes do not define identity. |
| Provider linking and recovery | **PARTIAL** | Apple/Google account-method APIs require an authenticated HAPI session, CSRF, and recent authentication. No general self-service recovery exists when every enrolled method is lost; email/provider recovery still depends on access to a linked method. |
| Application account mapping | **PARTIAL** | `application_account_links` has per-application associations, two-way uniqueness, audit, idempotent retry, and conflict rejection. A legacy internal Bookwrm route exists. There is no wired reusable Bookwrm/Elite+ linking ceremony that independently proves application-account ownership and captures explicit consent. |
| OIDC RP foundation | **BUILT** | Discovery, registered clients, authorization code, PKCE S256, exact redirects, state/nonce, signed ID tokens, stable `sub`, and UserInfo consistency have automated coverage. |
| Bookwrm / Elite+ client integrations | **PARTIAL** | Bookwrm/Base44 has a confidential OIDC client adapter and registered callback shape, but no Base44-hosted live flow was certified here. Elite+ web/native client registrations and app-side acceptance are not present in this repository. |

## 2. Existing functionality reused

- H2/H3/H4 email verification, registration, returning authentication, audit, and OIDC handoff.
- Apple/Google authorization-code exchange and token verification; exact `(provider, issuer, subject)`
  bindings; explicit first-time account choice; no email-based merge.
- Existing IdentitySubject registry and stable `oidc_subject`; no parallel HAPI identity table added.
- Post-authentication passkey enrollment, per-subject credential storage, authentication, and revocation.
- H1 Tenant/Application/OIDC-client authority and the existing generic application-account link
  tables/repository.
- Existing OIDC discovery, code + PKCE, ID-token, UserInfo, redirect, and replay protections.

H3 email registration is transactional across identity creation, verification consumption, evidence,
provenance, and audit. Federated first-time registration is not: `registerFirstTime` resolves or
creates the subject before writing the external-identity binding. A failed binding write can leave
an unusable subject without that binding; this race/orphan limitation was already recorded in the
V2-D certification. A retry of the same provider identity reuses the subject, but this is not
equivalent to the requested all-or-nothing transaction and remains a Stage 5A gap.

## 3. Application account mapping design and gap

The canonical association is `(application_id, external_account_id) → identity_subject_id`.
Database uniqueness prevents both one application account being claimed by two HAPI subjects and
one HAPI subject being silently assigned multiple accounts within the same application. Audit
records retain the application, authority, client, request, authentication method, and result.
Associations do not copy roles, subscriptions, permissions, or historical data.

The PostgreSQL repository checks that the subject, tenant, application, and client are active; the
database constraints arbitrate concurrent claims. The existing Bookwrm internal route instead uses
a shared service credential plus a Bookwrm user-id header and a supplied HAPI `oidcSubject`. That is
not, by itself, a reusable application-specific user-ownership proof or explicit-consent ceremony.
No equivalent Elite+ route/integration is wired. Do not treat matching email as proof or use this
partial surface to migrate accounts.

## 4. Minimum OIDC application contract

Each application and environment needs its own registered client and exact redirect URI. Relying
parties must use issuer discovery, Authorization Code + PKCE S256, validate state and nonce, validate
the signed ID token's issuer/audience/signature/expiry, and key identity only by the stable HAPI
`sub`. UserInfo `sub` must match the ID token. Map that subject to the application's existing user
only after application-approved ownership proof and explicit consent where required; do not copy
application roles or entitlements from HAPI. Provider cancellation and expired/replayed flows must
return to a safe retry path without creating an account. Logout/recovery must revoke only the
appropriate application/HAPI sessions and enrolled authenticator; persistent sessions and refresh
grants remain separately gated.

### Base44 / Bookwrm web

This repository contains the Base44 confidential-client adapter and SSO callback URIs. It does not
contain the hosted Base44 application configuration or establish that Base44's hosted-auth flow
can directly consume HAPI tokens or perform the required server-side code exchange, PKCE, state,
nonce, and token validation. No direct native token handoff is assumed. The actual hosted Bookwrm
web flow remains an external acceptance item.

### Elite+ web and native

There is no Elite+ web client or web application integration in this repository. The native
readiness documents describe public clients and system-browser authorization with PKCE S256, but
the Elite+ iOS/Android clients, redirect ownership (Universal/App Links), registrations, and
device-level acceptance are not present here. A Base44/Capacitor WebView must not be treated as
support for direct native token handoff.

## 5. Recovery posture

- A lost passkey is recoverable through another already-linked method; no self-service path can
  recover an account when no usable method remains.
- Lost email access blocks Email OTP; a linked Apple, Google, or passkey method can still
  authenticate and support an approved method change.
- Lost Apple/Google access similarly requires another linked method or provider-side recovery.
- Sensitive Apple/Google method changes require a live HAPI session, CSRF, and recent
  authentication; adding further passkeys requires fresh subject-bound authority.
- Administrative recovery exists for legacy PrivateID authenticator continuity, not as a general
  end-user recovery system.
- SMS OTP remains disabled. Persistent sessions and refresh grants remain default-off and are not
  approved by this work.

## 6. Tests and build

All provider tokens and identities in these tests are synthetic.

| Validation | Result |
| --- | --- |
| `npm run build` | PASS |
| Full default suite, `npx vitest run --hookTimeout=30000` | **74 files passed, 14 skipped; 766 passed, 194 skipped; 0 failed** |
| Focused registration/federation/OIDC/linking suites | **115 passed** |
| Disposable PostgreSQL 16 registration, email, federation, multi-client, and tenant/application suites | **57 passed** |
| Disposable Redis 7 + PostgreSQL + Chromium passkey/Universal Login suites | **94 passed** |
| Worktree after validation | No generated build changes |

The first unadjusted full-suite run hit the Chromium suite's 10-second `beforeAll` timeout under
parallel load. That suite passed alone with a 30-second hook timeout, and the complete rerun above
passed with the same timeout allowance. The default run skips database/Redis-gated suites; the
reported integration runs used disposable loopback-only containers and did not connect to staging
or production.

The three new tests certify Apple first-time creation/returning continuity, concurrent federated
registration under PostgreSQL uniqueness, and rollback of H3 email identity/evidence/challenge/audit
writes when a final audit write fails. They do not certify federated subject-plus-binding rollback.
No runtime behavior changed.

## 7. Live acceptance outstanding

- Live first-time and returning Apple and Google browser flows using separately approved provider
  tenants and staging credentials.
- Live cancellation, replay, and provider-link recovery acceptance.
- Bookwrm/Base44 hosted-web compatibility and its account-ownership/consent proof.
- Elite+ web/native client registration and application-specific linking proof; device/browser
  acceptance remains outstanding.
- User recovery when the only email, Apple/Google account, or passkey is lost.
- Operator confirmation of staging PostgreSQL/Redis isolation before staging deployment.

Prior live email/OIDC and passkey evidence is documented in the existing Stage 3/Stage 4 reports
and in the user-provided certified baseline; it was not re-executed in this work.

## 8. Delivery and recommendation

No runtime feature was missing from the tested email/Apple/Google registration paths, so those
flows were not rewritten. Development changes are limited to focused certification tests and this
report. No staging release branch update, deploy, Railway change, production provisioning, or
Bookwrm/Elite+ application change is authorized or performed.

**GO for continued development-branch certification. NO-GO for staging deployment** until federated
subject-plus-binding creation is atomic or otherwise safely recoverable, the application
ownership-proof/consent contract is agreed and wired, and live Apple/Google staging acceptance and
operator resource-isolation checks are complete.
