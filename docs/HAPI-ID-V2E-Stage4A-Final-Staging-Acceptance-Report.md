# HAPI ID V2-E Stage 4A — Final Staging Acceptance Report

**Status: STAGING AUTOMATED ACCEPTANCE PASSED; LIVE FIRST-TIME AND LIVE NEGATIVE COMPLETION REMAIN.**

Certification date: 2026-11-20

Published predecessor documentation: `4a58da836e5e876aa4bcd37a069f41ed8aba11e6`

## 1. Scope

This report closes the existing Stage 4A automated pass and separates it from behaviors that still
require a live, operator-approved browser test or direct staging-resource confirmation.

No code was changed, no Railway variable was changed, no OTP was sent, no deployment was made and
no production configuration was changed.

## 2. Automated acceptance evidence

A focused rerun of the existing Universal Login, staging console, PKCE, UserInfo and page suites
produced:

- **5 test files passed**
- **90 tests passed**
- **0 tests failed**
- **1 PostgreSQL-gated test file skipped**
- **24 PostgreSQL-gated tests skipped** because their isolated database environment is not active

Existing suites cover:

- First-time registration through H2/H3
- Returning-user authentication
- OTP resend and interaction replay
- Authorization-code replay
- PKCE verifier mismatch
- Invalid redirect URI rejection
- ID-token issuer, audience, nonce and subject claims
- UserInfo subject and email claims
- Generic-page and secret-redaction behavior

The automated suite is the evidence for negative-security behavior. It is not a live email-OTP
delivery or live Railway-resource certification.

## 3. Live browser evidence already passed

The Stage 3 live browser console previously reported PASS for:

| Live check | Result |
| --- | --- |
| Authorization and state | PASS |
| Authorization-code exchange with PKCE S256 | PASS |
| Signed ID-token issuer, audience, nonce and expiration | PASS |
| UserInfo matching `jeff@hapiinc.com` | PASS |

A live OTP was delivered and accepted for the controlled test mailbox. The browser console did not
expose negative-security controls and did not claim them as live passes.

## 4. Live staging acceptance checklist

| Behavior | Automated evidence | Live browser evidence | Remaining status |
| --- | --- | --- | --- |
| First-time registration by email OTP | PASS | Not live-confirmed for a fresh mailbox | Outstanding |
| Returning-user email authentication | PASS | Live positive Stage 3 mailbox round-trip PASS | Certificate scope complete; live returning-user rerun not separately identified |
| Incorrect OTP rejection | Existing suite coverage | Not live-confirmed | Outstanding or operator live test |
| Expired OTP rejection | Existing expiry coverage | Not live-confirmed | Outstanding or operator live test |
| OTP replay rejection | Existing replay coverage | Not live-confirmed | Automated sufficient unless operator requires live evidence |
| Authorization-code replay | PASS | Not live-confirmed | Automated sufficient unless operator requires live evidence |
| PKCE verifier mismatch | PASS | Not live-confirmed | Automated sufficient unless operator requires live evidence |
| Invalid redirect URI | PASS | Staging Stage 2 exact redirect test PASS | Live staging negative coverage already documented |
| ID-token issuer/audience/nonce/expiration | PASS | PASS | Live browser PASS |
| Correct UserInfo subject | PASS | PASS | Live browser PASS |

There is no requirement to modify the browser console for negative controls. Incorrect, expired and
replayed OTP behavior should remain covered by existing negative suites unless a live operator result
is separately required.

## 5. Staging isolation result

### Confirmed

- Staging issuer: `https://id-staging.hapiinc.com`
- Railway staging project: `charismatic-charm`
- Staging signing-key kid: `rsa-1-OXX7VucDdDJvBUEB`
- Production signing-key kid: `rsa-1-DOCW-KVBmBo4vKFr`
- The live staging and production JWKS are disjoint.
- Existing staging seed evidence defines only `staging-web` and `staging-native` clients and refuses
  databases containing an unrelated production OIDC client.
- Existing Stage 2 evidence documents distinct staging and production PostgreSQL/Redis hosts and
  the staging Redis namespace.
- Existing production preflight evidence reports production discovery and JWKS unchanged.

### Not directly confirmed in this workspace session

The Railway CLI is not installed in this environment, so this session could not inspect service
attachments or resource ownership directly. Therefore the following should remain an operator
confirmation before broader activation:

- PostgreSQL attached to the `charismatic-charm` staging backend is not shared with Bookwrm production.
- Redis attached to that staging backend is not shared with production.
- No production identity rows or production OAuth client records are present in staging.

This is a narrow operator/resource check. It is not a reason to repeat the earlier Stage 1–3
infrastructure audits.

## 6. Explicit remaining untested areas

- Live first-time registration for a fresh controlled mailbox
- Live incorrect OTP rejection
- Live expired OTP rejection
- Live OTP replay in the browser
- Live authorization-code replay in the browser
- Live PKCE mismatch in the browser
- Direct confirmation of PostgreSQL and Redis exclusive attachment to `charismatic-charm`
- Direct confirmation that production identity and client records are absent from staging
- Persistent sessions and refresh grants
- Apple and Google federation
- SMS OTP
- Native mobile login
- Production-facing Universal Login activation

Automated evidence exists for several of these negative cases. It is not claimed as live evidence.

## 7. Actual production-facing blockers

No genuine Universal Login implementation defect was found.

Current blockers for production-facing Universal Login preparation are:

1. The live first-time registration and live negative OTP matrix remain outstanding.
2. Direct Railway PostgreSQL/Redis exclusive-attachment confirmation remains operator-visible.
3. Production identity and OAuth-client isolation confirmation remains operator-visible.
4. Persistent sessions and refresh grants are separately gated and outside Stage 4A.
5. Production activation, production Bookwrm callback acceptance and production client-secret
   hardening remain separate approvals or workstreams.

## 8. Recommendation

**CONDITIONAL GO: Stage 4A staging acceptance may continue using the existing console and suites.**

**NO-GO: Production-facing Universal Login activation.**

The existing implementation already demonstrated live positive email/OIDC behavior and passed 90
focused automated acceptance tests. It is ready for a small final operator staging pass limited to
fresh registration, live OTP negatives and direct resource-isolation confirmation. No additional
service or framework is needed.
