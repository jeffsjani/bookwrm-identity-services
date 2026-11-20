# HAPI ID V2-E Stage 3 — Live Authentication Certification

**Status: LIVE POSITIVE CERTIFICATION CLOSED — browser console scope passed.**

This report records the observed live browser certification. It does not convert automated tests or
operator procedures that were not executed live into live PASS results.

- Certification date: 2026-11-20
- Staging issuer: `https://id-staging.hapiinc.com`
- Railway project: `charismatic-charm`
- Staging backend: `hapi-id-staging-backend`
- Deployed source revision: `6c83fb9`
- Resend sender: `auth-staging.hapiinc.com`
- Controlled test identity: `jeff@hapiinc.com`

## 1. Live browser console PASS results

The browser-based staging test console was enabled and executed for the controlled test mailbox.
The console reported PASS for all four checks listed below:

| # | Live browser-console check | Result |
| --- | --- | --- |
| 1 | Authorization and state | **PASS** |
| 2 | Authorization code exchange with PKCE S256 | **PASS** |
| 3 | Signed ID token, issuer, audience, nonce and expiration | **PASS** |
| 4 | UserInfo matched the test mailbox | **PASS** |

The successful path used successful email OTP authentication followed by the ordinary OIDC
authorization-code flow. This verifies the reuse of the existing H4 email-authentication engine and
HAPI Universal Login handoff in the deployed staging revision.

## 2. Signing-key and OIDC claim verification

The live browser console verifies the ID token server-side against the staging origin's local JWKS,
then verifies issuer, audience, nonce and expiration. It does not expose the ID token or signing
key material to the browser.

The existing live staging posture had a new, staging-only RSA signing-key set and no production key
reuse. The browser PASS proves the deployed token was signed and validated against the staging
signing-key/JWKS path; it also proves the configured issuer and requested claims matched the
browser's authorized flow.

## 3. Email delivery verification

- The approved staging Resend sender is `auth-staging.hapiinc.com`.
- A live email OTP was delivered to the controlled mailbox `jeff@hapiinc.com`.
- The live OTP was accepted by the deployed Universal Login email flow.
- The same flow completed identity authentication and returned an authorization code to the
  registered console callback.

## 4. Existing implementation evidenced by the live test

The live browser test used the existing deployed implementation rather than a new OTP or OIDC engine:

- H4 email authentication start and verification
- H6 Universal Login email interaction and secure interaction cookie
- Existing OIDC authorization-code exchange
- PKCE S256
- Staging JWKS-backed ID-token validation
- Staging UserInfo
- First-time registration behavior, when a mailbox has no eligible subject
- Returning-user authentication behavior, where an eligible HAPI_EMAIL subject already exists

The test identity remained unchanged except for the normal authentication/registration behavior
approved for the staging environment.

## 5. Browser-console certification limitations

The browser console is a positive, operator-visible certification surface, not a substitute for the
complete automated Phase D matrix.

The following live browser checks were **not** added to the live positive report:

- Wrong-code or wrong-verifier rejection
- Authorization-code replay rejection
- Email proof/`authentication_result` replay rejection
- Garbage or expired bearer rejection at UserInfo
- Cross-JWKS rejection against the production issuer
- Replay, CSRF, rate-limit and expired-interaction negative test execution in the live browser
- Concurrent or high-load behavior
- Persistent-session or refresh-token behavior
- Apple, Google, SMS or passkey federation
- Native mobile authorization
- Production issuer or production Bookwrm behavior

Automated tests may cover these areas, but they are not claimed here as observed live PASS results.

## 6. Features not yet certified

The following remain incomplete or outside this certification:

- Full live negative acceptance matrix
- Persistent-session activation and refresh grants
- Apple/Google federation
- SMS OTP
- Native mobile login
- General production Universal Login rollout
- Production identity migration or data changes
- A production cutover or production Bookwrm configuration change
- Production-scale performance or reliability certification
- Edge/proxy log-policy certification outside application logging

## 7. Certification conclusion

**Stage 3 live positive email/OIDC authentication certification is complete for the deployed
revision and browser-console scope.**

The observed four PASS results establish that the staging browser flow, email OTP, PKCE authorization
code exchange, staging signing-key claim validation and UserInfo mailbox matching work together.
Negative tests, session features and future authentication methods remain separately gated.

## 8. Stage 3 to Stage 4 rollback posture

The browser console may remain deployed but disabled by default.

Minimum rollback, applied only through the authorized staging deployment configuration:

```text
STAGING_TEST_CONSOLE_ENABLED=false
HAPI_UNIVERSAL_LOGIN_ENABLED=false
HAPI_EMAIL_AUTHENTICATION_ENABLED=false
```

Preserve all of the following:

- Existing staging OAuth clients
- Registered staging console callback
- Staging signing keys
- Staging identity data
- Existing staging PostgreSQL and Redis data
- Existing Resend staging sender configuration

Do not remove the console callback, signing keys or identities merely to stop the test. No Railway
configuration change was made for this report.
