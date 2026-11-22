# HAPI ID V2-E Stage 5A — Registration and Application Identity Foundation

**Status: FEDERATED REGISTRATION IS ATOMIC; HAPI-SIDE APPLICATION-LINK CONTRACT IS IMPLEMENTED BUT NOT PRODUCTION-ENABLED.**

Date: 2026-11-22  
Branch: `feature/hapi-id-v2e-stage1`  
Baseline: `92caf54ae0236ec3314da160c7cd17cd3b16f5f6`  
Staging issuer: `https://id-staging.hapiinc.com`  
Planned production issuer: `https://id.hapiinc.com`

This follow-up closes the PostgreSQL federated-registration atomicity gap and adds a fail-closed
HAPI application-linking contract with a test verifier. It does not configure a trusted production
proof verifier or change staging/production resources, application clients, or identity data.

## 1. BUILT / PARTIAL / MISSING inventory

| Area | Status | Evidence and boundary |
| --- | --- | --- |
| Email registration and return | **BUILT** | H2 verified OTP → H3 atomic registration/evidence/audit → original OIDC interaction. Existing HAPI_EMAIL accounts use H4 and retain their `oidc_subject`. |
| Google registration and return | **BUILT** | Verified exact provider identity; unknown users explicitly choose creation or email sign-in. Matching email never merges. Subject creation, provider binding, and link audit now share one PostgreSQL transaction with unique constraints resolving races. |
| Apple registration and return | **BUILT** | Same explicit choice and exact-identity binding. PostgreSQL subject creation, provider binding, and audit are atomic; retry returns the prior subject. Matching email never merges. |
| Passkey enrollment and authentication | **BUILT** | Post-authentication enrollment is bound to the canonical subject; credential authentication resolves that subject and its existing OIDC `sub`. PostgreSQL/Redis/Chromium tests cover enrollment, login, revocation, and failure paths. |
| Stable HAPI subject | **BUILT** | `identity_subjects.oidc_subject` is the canonical OIDC subject. Email, provider, and passkey paths resolve to their linked subject; email changes do not define identity. |
| Provider linking and recovery | **PARTIAL** | Apple/Google account-method APIs require an authenticated HAPI session, CSRF, and recent authentication. No general self-service recovery exists when every enrolled method is lost; email/provider recovery still depends on access to a linked method. |
| Application account mapping | **PARTIAL** | Added authenticated HAPI-session start/complete endpoints and a short-lived, session/subject/application/client-bound Redis transaction. Completion accepts only an injected application-proof verifier's claims and rechecks active tenant/application/client authority before the existing audited association write. Production proof verification is deliberately not configured; the legacy Bookwrm continuity route remains and must be migrated or disabled before enabling this surface. |
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

H3 email registration remains transactional across identity creation, verification consumption,
evidence, provenance, and audit. Federated registration now creates/resolves the subject and links
the exact `(provider, issuer, subject)` binding through transaction-scoped instances of the existing
`IdentityRegistry`, `IdentityFederationService`, and PostgreSQL repositories. A returned binding
conflict aborts the transaction; a database binding/audit failure rolls back the subject. The unique
primary-provider and external-identity constraints serialize concurrent first registrations.
Repeated or retried requests return the same HAPI subject and binding. Verified email remains
contact metadata only and is never part of identity resolution.

## 3. Application account mapping design and gap

The canonical association remains `(application_id, external_account_id) → identity_subject_id`.
Database uniqueness prevents one application account being claimed by multiple HAPI subjects and
one HAPI subject being assigned multiple accounts within one application. The existing
`PostgresApplicationAccountLinks` repository writes the association and audit in one statement and
checks the active HAPI subject, tenant, application, and client both before and during insertion.
Associations do not copy roles, subscriptions, permissions, or historical data.

The HAPI contract is behind the existing default-off `HAPI_ACCOUNT_LINKING_API_ENABLED` surface:

1. `POST /account/application-links/start` requires a live HAPI session, CSRF, recent
   authentication, explicit `consent: true`, and an active registered application/client. The
   response contains a random transaction ID, nonce, fixed HAPI audience, and expiry.
2. The app proves ownership of its existing account and returns an app-signed proof through its
   own authenticated flow. HAPI never accepts an external account ID from the browser request.
3. `POST /account/application-links/complete` requires the same HAPI subject and session. The
   verifier must validate a signing key trusted specifically for the expected application/client.
   HAPI then checks application/client, audience, transaction ID, nonce, proof ID, issue/expiry
   bounds (maximum two minutes), and single-use Redis claims before reconciling the exact verified
   account ID.
4. The association audit records the approved HAPI subject, application account, authority,
   registered client, transaction ID, authentication method, and result. Conflicts fail closed.
   Redis atomically consumes the proof and transaction after persistence succeeds, so a transient
   database failure can be retried with the same proof; terminal association conflicts consume it.

The production server does not inject a proof verifier, so these routes return unavailable even if
the shared account-linking flag is enabled. The test verifier is synthetic and is not a trusted
production proof mechanism.

The legacy `POST /internal/identity/account-link` endpoint accepts the HAPI service credential,
`x-bookwrm-user-id`, and a caller-supplied HAPI `oidcSubject`; it has no HAPI user session, step-up,
linking consent, or short-lived ownership proof. It can therefore bypass the new ceremony. The
repository contains its handler and tests but no Bookwrm caller implementation, so external
production consumers could not be established here. The server now does not register this route
when the issuer is exactly `https://id-staging.hapiinc.com`; non-staging behavior is unchanged to
avoid breaking an unverified production dependency. The legacy route remains a production
integration risk until Bookwrm migrates or its consumers are verified and the route is retired.
No Elite+ proof issuer or integration is present.

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
| Full default suite, `npx vitest run --hookTimeout=30000` | **74 files passed, 16 skipped; 774 passed, 202 skipped; 0 failed** |
| Focused registration/federation/linking and authentication regressions | **113 passed** |
| Disposable PostgreSQL registration, email, registry, federation, and multi-client suites | **62 passed** |
| HAPI_STAGING-shaped PostgreSQL + Redis link acceptance | **1 passed** |
| Redis proof reservation/replay integration | **2 passed** |
| PostgreSQL/Redis/Chromium passkey and Universal Login suites | **94 passed in the prior Stage 5A baseline; not rerun in this follow-up** |
| `git diff --check` | PASS |

The default run skips database/Redis-gated suites. The follow-up PostgreSQL and Redis runs use
disposable loopback-only containers and do not connect to staging or production. The controlled
acceptance fixture seeds an isolated `HAPI_STAGING` application/`staging-web` client and random
HAPI subjects; its in-test proof adapter is synthetic, default-skipped without explicit test URLs,
and is not imported by runtime code. It certifies the HAPI protocol and persistence, not ownership
of a real Bookwrm or Elite+ account.

The follow-up tests certify Apple/Google first-time and repeated registration, concurrent subject
creation, provider-binding rollback, explicit application-link consent, transaction/subject/app
binding, proof expiry and replay rejection, association conflicts, and audit rollback. The
synthetic ownership verifier tests do not certify a production Bookwrm/Elite+ signing-key trust
relationship. Passkey browser integration results above are from the prior certified baseline,
while the current full default suite includes the available passkey regression tests.

## 7. Live acceptance outstanding

- Live first-time and returning Apple and Google browser flows using separately approved provider
  tenants and staging credentials.
- Live cancellation, replay, and provider-link recovery acceptance.
- Live staging acceptance with separately approved test identities and staging-owned PostgreSQL/
  Redis was not performed; no such credentials or identity approvals were supplied.
- Bookwrm/Base44 hosted-web compatibility and server-side ownership-proof/consent issuance.
- Elite+ web/native client registration and application-specific ownership-proof issuance;
  device/browser acceptance remains outstanding.
- Production consumer inventory and migration/retirement of the legacy Bookwrm link endpoint.
- User recovery when the only email, Apple/Google account, or passkey is lost.
- Operator confirmation of staging PostgreSQL/Redis isolation before staging deployment.

Prior live email/OIDC and passkey evidence is documented in the existing Stage 3/Stage 4 reports
and in the user-provided certified baseline; it was not re-executed in this work.

## 8. Delivery and recommendation

Existing email, Apple, Google, and passkey behavior was preserved. Federated registration reuses the
existing schema; no migration or runtime variable was added. On the exact staging issuer, the
legacy service-key link route is not registered, and the new HAPI linking API remains default-off
and has no production verifier. Non-staging legacy behavior is unchanged. No release-branch update,
deployment, Railway change, production provisioning, or staging/production identity change was
performed.

**GO for a staging-only deployment with application linking disabled**, provided operators verify
the exact staging issuer and leave `HAPI_ACCOUNT_LINKING_API_ENABLED` unset or false. This is not
approval to enable linking. **NO-GO for production application-linking integration** until each
application implements trusted ownership-proof issuance, HAPI configures app-specific key trust,
and the legacy Bookwrm consumer path is verified and retired.

## 9. Stage 5A follow-up delivery

The follow-up implementation adds:

- PostgreSQL transaction-scoped subject and external-identity repositories for first-time Apple and
  Google registration; conflicts and failed provider-binding writes leave no orphan subject.
- An application-link ceremony using the existing HAPI session/CSRF/recent-authentication guard,
  existing `application_account_links` persistence/audit, a short-TTL Redis transaction, and a
  verifier interface that has no production implementation configured.
- The legacy Bookwrm link route is omitted only on the exact staging issuer; non-staging
  compatibility is retained until its external consumers are established.
- Synthetic unit/integration adapters for application ownership proofs; these certify HAPI claim
  binding and replay handling, not a Bookwrm/Elite+ production signature/key trust relationship.

For both Bookwrm and Elite+, the app must authenticate the user to the existing account, show
explicit consent, and issue a signed app/client-specific assertion containing the stable account ID,
HAPI audience `urn:hapi:application-account-link:complete`, transaction ID, nonce, unique `jti`,
and `iat`/`exp` no more than 120 seconds apart. HAPI must validate signature and app-specific
issuer/key trust before accepting it. Linking stores an association only; it must not replace app
user IDs or move roles, subscriptions, permissions, or historical data. Each app must verify its
historical data remains attached to the same existing account after linking. No live signing key,
trust source, or real account proof is configured by this change.
