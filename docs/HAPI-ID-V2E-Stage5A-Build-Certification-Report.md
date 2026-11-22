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
production proof mechanism. The existing internal Bookwrm continuity endpoint still uses a
service credential, principal header, and supplied HAPI subject; it does not meet the new
short-lived proof contract and remains a rollout blocker until Bookwrm migrates or operators
disable that legacy path. No Elite+ proof issuer or integration is present.

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
| Full default suite, `npx vitest run --hookTimeout=30000` | **74 files passed, 15 skipped; 772 passed, 201 skipped; 0 failed** |
| Focused registration/federation/linking and authentication regressions | **106 passed** |
| Disposable PostgreSQL 16 registration, email, registry, federation, and multi-client suites | **62 passed** |
| Account-link API plus disposable Redis 7 ceremony suite | **23 passed** |
| PostgreSQL/Redis/Chromium passkey and Universal Login suites | **94 passed in the prior Stage 5A baseline; not rerun in this follow-up** |
| `git diff --check` | PASS |

The default run skips database/Redis-gated suites. The follow-up PostgreSQL and Redis integration
runs used disposable loopback-only containers and did not connect to staging or production. The
Redis test uses unique proof IDs so replay protection is exercised without stale test data causing
cross-run failures.

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
- Bookwrm/Base44 hosted-web compatibility and its account-ownership/consent proof.
- Elite+ web/native client registration and application-specific linking proof; device/browser
  acceptance remains outstanding.
- User recovery when the only email, Apple/Google account, or passkey is lost.
- Operator confirmation of staging PostgreSQL/Redis isolation before staging deployment.

Prior live email/OIDC and passkey evidence is documented in the existing Stage 3/Stage 4 reports
and in the user-provided certified baseline; it was not re-executed in this work.

## 8. Delivery and recommendation

Existing email, Apple, Google, and passkey login behavior was preserved. Runtime changes are limited
to atomic federated registration and the new fail-closed HAPI application-link contract; no
application-side integration was made. No staging release branch update, deploy, Railway change,
production provisioning, or staging/production identity change was performed.

**NO-GO for staging deployment** until the application trust/key-verification mechanism is agreed
and implemented by each app, the legacy Bookwrm route is migrated or disabled, the app-side consent
and ownership proof flows are accepted for Bookwrm and Elite+, live Apple/Google staging acceptance
is complete, and operators confirm staging resource isolation.

## 9. Stage 5A follow-up delivery

The follow-up implementation adds:

- PostgreSQL transaction-scoped subject and external-identity repositories for first-time Apple and
  Google registration; conflicts and failed provider-binding writes leave no orphan subject.
- An application-link ceremony using the existing HAPI session/CSRF/recent-authentication guard,
  existing `application_account_links` persistence/audit, a short-TTL Redis transaction, and a
  verifier interface that has no production implementation configured.
- Synthetic unit/integration adapters for application ownership proofs; these certify HAPI claim
  binding and replay handling, not a Bookwrm/Elite+ production signature/key trust relationship.

Application-side contract requirement: after independently authenticating the user to the existing
Bookwrm or Elite+ account, the app must issue a signed, app-specific ownership assertion containing
its stable account ID, registered application/client, HAPI audience
`urn:hapi:application-account-link:complete`, HAPI transaction ID and nonce, a unique `jti`, and
`iat`/`exp` with at most a 120-second lifetime. The app must protect the signing key and bind it to
that application/client in HAPI's approved verifier configuration. HAPI's verifier must validate
signature, issuer/key trust, audience, client and claim types, then normalize timestamps to
milliseconds for the current verifier interface. The app must present clear user consent before
starting the HAPI ceremony. No key source, signing algorithm, or production trust is assumed here.
