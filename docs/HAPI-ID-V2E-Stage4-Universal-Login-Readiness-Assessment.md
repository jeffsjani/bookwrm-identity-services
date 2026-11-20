# HAPI ID V2-E Stage 4 — Universal Login Readiness Assessment

**Status: IMPLEMENTATION READY; STAGING ACTIVATION AND CROSS-CLIENT ACCEPTANCE REMAIN.**

This assessment follows the SIMPLE FIRST principle. It reuses the existing H4 email engine, H6
Universal Login interaction, H1 client authority, H2 email verification, H3 registration and H5
session primitives where applicable. It does not propose new OTP or OIDC engines.

## 1. What is already implemented and working

### 1.1 Complete email and identity path

- Email entry, OTP delivery, OTP verification and resend
- H4 proof verification and single-use authentication-result handoff
- H2 email verification and H3 atomic registration
- Returning-user lookup through the existing HAPI_EMAIL identity registry
- Shared new/returning email journey with internal branch classification only
- Existing OIDC authorization interaction state, state echo, nonce, scopes and redirect binding
- Authorization-code issuance, PKCE S256 and signed ID-token claim handoff
- Staging JWKS validation and UserInfo in the browser console
- Secure, short-lived `__Host-hapi_login` Universal Login interaction cookie
- CSRF validation, rate limiting, replay protection and generic failure presentation
- Existing staging console with independent HTTP Basic protection
- Staging-only callback registration guarded by issuer and database/client validation

The implementation is covered by focused in-memory and PostgreSQL suites, including:

- New-email registration through H2 and H3
- Existing-email authentication
- The ordinary authorization-code and token exchange
- PKCE and nonce claims
- Replay and replay-safe interaction handling
- The Bookwrm zero-choice email journey
- Resend and submit-once behavior
- Generic pages that do not disclose account existence

The live browser console then demonstrated the positive staging path for `jeff@hapiinc.com`.

### 1.2 Application presentation

- Bookwrm has a client-specific H6.11 zero-choice screen and step-one/step-two email experience.
- Other clients use the existing neutral HAPI presentation.
- The server restricts the Bookwrm presentation to an exact client allowlist and static copy.
- Face, Apple, Google and refresh features are capability-gated and can remain disabled.

## 2. Minimum missing work for production-quality Universal Login

No OTP or OIDC engine rebuild is required. The minimum missing items are operational and acceptance
quality, not architectural:

1. Complete the live negative acceptance matrix: wrong verifier, code replay, proof replay,
   garbage bearer, cross-JWKS and expired/consumed interaction behavior.
2. Obtain datastore-scoping evidence for staging PostgreSQL and Redis before enabling a broader
   or persistent staged session experience.
3. Certify at least one first-time registration and one returning-user login for the real staged
   OAuth client behavior.
4. Exercise the exact callback/return behavior for each application that will use Universal Login.
5. Verify staging email, identity and session data are isolated from production and retained only
   as approved by operations.
6. Decide and document persistent-session and refresh grant activation separately. These are not
   required for the minimum Universal Login email/authorization-code journey.
7. Validate operational log, alert and rollback behavior before rollout.

## 3. Minimum code changes

**No new runtime code is required to begin the Stage 4 staging activation if the existing branch is
deployed and enabled only through staging configuration.**

The exact recommended build is:

> **Stage 4A — Staging Universal Login activation and acceptance harness use**, using the existing
> H4/H6 implementation and the existing staging console, with no engine changes.

The build should contain only narrowly scoped follow-ups discovered by acceptance testing:

- Any small copy or accessibility defect found in the real browser journey
- Any missing telemetry field needed to distinguish failed, registration and authentication paths
  without recording email, OTP, token or proof values
- Any staging or application-capability guard needed by live evidence

Do not add SMS, Apple, Google, native mobile, persistent-session or refresh-grant behavior in this
build. Do not add an admin console or repeated architecture framework.

## 4. Minimum UI improvements

The existing UI is close enough to accept. Minimum improvements, only if validation identifies a
defect, are:

- Preserve clear mobile sizing for the email field and six-character OTP input
- Keep the two-step Bookwrm/neutral HAPI progress copy visible without exposing registration
  versus authentication state
- Preserve a visible, client-safe return/start-again path for expired or unavailable interactions
- Retain accessible labels, error announcement, submit-once behavior and script-disabled forms
- Keep the generic failure copy and no account-enumeration differences

Bookwrm already has the best-established client theme. Elite+ and future companion applications
should use the existing generic HAPI page unless they have a reviewed, allowlisted client presentation.
Adding per-application branding does not require a new login engine.

## 5. Security and session functionality to reuse

Reuse, rather than duplicate:

- H1 client authority and application allowed-method checks
- The existing authorization interaction store with TTL and one-time consumption
- `__Host-hapi_login` short-lived, Secure, HttpOnly, SameSite=Lax interaction cookie
- CSRF matching and mutation-route rate limits
- OIDC state, nonce, redirect URI, scope and PKCE S256 binding
- H4 proof TTL and single-use authentication-result handoff
- H2/H3 registration evidence and identity collision protections
- Staging-only console Basic authentication and host/session guards
- Existing ID-token signing/JWKS validation and UserInfo
- Existing `Cache-Control: no-store`, referrer and CSP headers
- Safe diagnostic events that omit email, OTP, secrets and tokens
- Existing session establishment behind `HAPI_PERSISTENT_SESSIONS_ENABLED`, if later activated

Persistent sessions and refresh grants remain separately gated by `HAPI_PERSISTENT_SESSIONS_ENABLED`
and `HAPI_REFRESH_GRANT_ENABLED`; they should not block basic authorization-code Universal Login.

## 6. Bookwrm, Elite+ and companion application fit

### Bookwrm

The existing `bookwrm-base44-production` client has a specific server allowlist and H6.11 zero-choice
screen. It is already prepared for both a known and unknown email. Bookwrm's callback and OAuth
state must be exercised against the staged service, but no new OAuth client or engine is needed.

### Elite+

No Elite+ client registration or integration can be assumed from this repository. Elite+ should use
an existing registered companion OAuth client or proceed through the normal H1 registration process
before Universal Login activation. The HAPI email journey is client-generic after H1 authority and
allowed-method validation.

### Future companions

A future application should add only:

- An approved OAuth client profile
- An exact callback URI
- An allowed HAPI_EMAIL application method
- A neutral or separately certified presentation policy
- A client-specific acceptance test for state, PKCE, redirect and UserInfo

It should not add a separate login, OTP or identity service.

## 7. Small staged implementation and acceptance plan

### Stage 4A — staging activation

1. Keep the code revision unchanged unless a real acceptance defect requires a small patch.
2. Enable only `HAPI_EMAIL_AUTHENTICATION_ENABLED=true` and
   `HAPI_UNIVERSAL_LOGIN_ENABLED=true` in the existing staging backend.
3. Keep the staging console disabled after certification by default.
4. Keep Apple, Google, refresh and persistent sessions disabled.
5. Run the existing Stage 3 harness and live browser console for the positive path.

**Acceptance:** observed live pass for first-time registration and returning-user authentication;
exact staging issuer; PKCE; nonce; state; signing key/JWKS; ID-token claims; UserInfo; registered
redirect/callback.

### Stage 4B — security acceptance

Run the existing automated harness plus live staging probes for replay and verifier rejection.

**Acceptance:** no secret, token or OTP appears in logs or browser page; result and code replay are
rejected; wrong verifier and garbage bearer are rejected; cross-JWKS validation fails.

### Stage 4C — application acceptance

Exercise Bookwrm first. For Elite+ or future companions, use the existing client integration surface
and exact registered callback without creating new OAuth clients in this build.

**Acceptance:** application starts `/authorize`, receives the same OIDC code/state/PKCE contract,
exchanges it successfully and receives matching identity claims; cancellation and expiration return
cleanly to a usable application state.

### Stage 4D — operational rollback and rollout decision

Document the staging evidence and operator rollback. Do not enable production flags or production
Bookwrm during this stage.

**Acceptance:** one-command/three-variable rollback is rehearsed; no callback, key or identity data
is removed; production health and discovery remain unchanged.

## 8. Minimum rollback

```text
STAGING_TEST_CONSOLE_ENABLED=false
HAPI_UNIVERSAL_LOGIN_ENABLED=false
HAPI_EMAIL_AUTHENTICATION_ENABLED=false
```

The console may remain deployed. Keep:

- existing staging OAuth clients
- registered staging console callback
- staging signing keys
- staging identity data
- staging PostgreSQL and Redis isolation

No Railway variables should be changed as part of documentation or source-only build work.

## 9. Release blockers

### Closed for Stage 3 positive certification

- Live browser authorization and state: PASS
- Live browser code exchange with PKCE S256: PASS
- Live signed ID-token/issuer/audience/nonce/expiration: PASS
- Live UserInfo mailbox match: PASS
- Live OTP delivery and acceptance: PASS

### Current Stage 4 blockers or gates

- Live negative acceptance matrix not complete
- Staging Redis/PostgreSQL and identity isolation evidence remains required before broader activation
- Production Universal Login activation is not approved
- Elite+ or companion callback readiness cannot be certified until its application/client integration
  is identified and separately approved
- Persistent sessions and refresh grants remain not certified and out of scope
- Production client-secret handling remains a separate hardening item; source currently records
  plaintext-at-rest OAuth client credentials as an open production-hardening requirement

No source code defect is currently identified that requires rebuilding Universal Login.
