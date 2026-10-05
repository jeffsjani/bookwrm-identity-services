# HAPI ID H4 - Passwordless Email Authentication

Controlled production release: deploy with H4 disabled, verify schema and certified
identity regressions, and stop before activation. H4 is opt-in and does not change
the existing PrivateID GET `/authorize` flow or add any product UI.

## Architecture and policy

`EmailAuthenticationService` delegates every OTP operation to the existing
`EmailVerificationService`. H2 owns normalization, cryptographic generation,
challenge-bound HMAC, expiry, attempts/lockout, resend/rotation, destination
budgets, Resend delivery, telemetry, webhooks, and verification audits.
The dedicated purpose is `AUTHENTICATION`.

After email proof, `PostgresEmailAuthenticationRepository` resolves **only an
existing** canonical `IdentitySubject` keyed by `HAPI_EMAIL` and the normalized
verified destination. It requires ACTIVE status, `emailVerified=true`, an email
matching that provider key, and the same application as the trusted H1 context.
HAPI's existing global provider/email uniqueness is not broadened into
cross-application authentication. A subject registered under another application
is not automatically usable here.

H4 never calls registration, `resolveOrCreate`, or subject creation. The only
subject mutation is `last_authenticated_at` on successful authentication.
No provenance is inferred, overwritten, or fabricated.

Matching email on a different-provider identity is **not** sufficient to add an
authenticator. Cross-provider authentication/linking is deferred to H5: it needs
an authenticated linking ceremony, governed ownership evidence, explicit policy,
and auditable binding. No account linking or face enrollment is added in H4.

## Trusted-client APIs

All routes require Basic authentication with an active confidential persisted H1
client. Tenant/application are derived from its active application and tenant;
body-supplied context and product-specific headers are not used.
Never distribute client secrets to a public browser.
Request objects are strict and responses have `Cache-Control: no-store`.

| Route | Request | Success |
| --- | --- | --- |
| POST `/v1/authentication/email/start` | `{ "email": "person@example.com" }` | 200 `{ challengeId, expiresIn, resendAfter }` |
| POST `/v1/authentication/email/resend` | `{ "challengeId": "<UUID>" }` | Same H2 challenge and response shape |
| POST `/v1/authentication/email/verify` | `{ "challengeId": "<UUID>", "code": "<privately entered code>" }` | 200 `{ authenticated: true, subject, authenticationResult, expiresIn: 60, authenticationMethod: "HAPI_EMAIL", authenticatedAt, assurance: "email_otp" }` |

`subject` is the existing stable `oidcSubject`, never the internal database ID.
Wrong-code/expired/locked/rate-limit errors retain H2 semantics. Wrong context or
purpose is rejected before resend/verification can mutate another flow's evidence.

## Enumeration resistance

Start performs **no identity lookup**. Existing and unknown email both receive an
actual H2 challenge and the same generic email, HTTP status, response fields,
UUID length, TTL, cooldown, provider-failure handling, and rate-limit policy.
There is no dummy success fallback and no identity-dependent timing branch.
Delivery acceptance is not ownership proof.

Only after successful email proof does H4 distinguish internal eligibility.
Unknown, inactive, unverified, different-provider, and other-application identities
all produce public HTTP 401 `{ "error": "AUTHENTICATION_FAILED" }`.
Their verified challenge is consumed, but no result or identity is created.
Internal audit records distinguish `NO_ELIGIBLE_IDENTITY` from
`IDENTITY_NOT_ELIGIBLE`; these are not returned publicly.

## Single-use result and OIDC seam

The result is a cryptographically random 256-bit opaque capability, not an access
token, a new user, or a second session model. Only its SHA-256 digest is stored.
It expires 60 seconds after issuance and is bound to the exact authenticated client,
tenant, application, verified challenge, and canonical identity.
Never log the raw result or put it in a URL, source code, or persistent browser storage.

Exchange it server-to-server using the same H1 client's Basic credentials:

```json
{
  "client_id": "<same authenticated H1 client>",
  "redirect_uri": "<exact registered redirect URI>",
  "response_type": "code",
  "scope": "openid email",
  "nonce": "<nonempty transaction nonce>",
  "state": "<relying-party transaction state>",
  "code_challenge": "<43-character S256 challenge>",
  "code_challenge_method": "S256",
  "authentication_result": "<short-lived result from H4 verify>"
}
```

POST this strict JSON object to `/authorize`. The endpoint validates the existing
client, redirect, grant, response type, and allowed scopes, requires `openid`,
nonce, and S256, and reauthenticates the active H1 context. It returns
`{ "redirectUri": "<registered callback with authorization code and state>" }`
rather than exposing the result in a GET URL or invoking another provider.
The relying party must validate/bind state, nonce and PKCE to the originating
browser transaction before establishing its session. H4 does not build that UI.

Result consumption locks its PostgreSQL row, rechecks canonical identity
eligibility and the original verified email, and has exactly one winner across
processes. Consuming an ineligible result burns it. Wrong client/context attempts
cannot burn a still-valid result.

The principal implements existing `AuthenticatedUser` internally, plus
`authenticationMethod=HAPI_EMAIL`, an authentication timestamp, and
`assurance=email_otp`. Existing `issueAuthorizationRedirect` creates the existing
60-second Redis-backed authorization code. `/token` uses the existing client
authentication and PKCE validation to issue the existing token types; `/userinfo`
uses the canonical registry. H4 ID tokens additionally carry `amr: ["email"]` and
`auth_time`. No high-assurance or biometric assurance is claimed.
H4 also rechecks ACTIVE/verified HAPI_EMAIL eligibility at token issuance.
H4 resolves persisted clients directly by client ID for this handoff/token path;
the legacy client-list resolution used by face GET `/authorize` is unchanged.

PostgreSQL atomically combines verified-evidence consumption, eligibility
resolution, result issuance, success audit, and `last_authenticated_at`.
H2's self-contained `consume()` cannot span result creation in that same
transaction, so H4 uses the shared persisted challenge inside its own transaction,
as H3 does. H2 OTP verification remains its existing separate transaction.
Concurrent OTP verification, evidence consumption/result creation, and capability
handoff each have one winner.
Expiry is rechecked after acquiring the canonical identity lock, so lock contention
cannot turn expired evidence or an expired result into a fresh authentication.

There is intentionally no successful verification replay or idempotent artifact
minting. Wrong-code attempts follow H2 policy, but a successful OTP cannot
establish fresh artifacts indefinitely. If a verified-to-result transition fails,
or a consumed result's Redis authorization-code write fails, fail closed and
start a new authentication ceremony; do not retry issuance from old proof or use
registration as recovery. This avoids pretending PostgreSQL and Redis are one
distributed transaction.

## Audits and privacy

The separate durable `email_authentication_audit` contains:

- `EMAIL_AUTHENTICATION_STARTED`
- `EMAIL_AUTHENTICATION_VERIFIED`
- `EMAIL_AUTHENTICATION_SUCCEEDED`
- `EMAIL_AUTHENTICATION_FAILED`
- `EMAIL_AUTHENTICATION_RATE_LIMITED`

Rows contain context, challenge reference, fixed internal outcome, and timestamp:
no OTP, plaintext email, raw result, or client secret. H2's delivery and verification
audits remain unchanged. Unexpected failures are explicitly logged with a
sanitized event and return 503, not success-shaped defaults.

## Activation and migration

Set `HAPI_EMAIL_AUTHENTICATION_ENABLED=true` only for an explicitly approved
validation/release. Default/unset/false leaves H4 routes unavailable (POST
`/authorize` returns 404). Invalid flag values or missing H2 configuration fail
startup. Existing H2 Resend, sender, verification-secret, PostgreSQL and OIDC/Redis
settings are reused; no new secret or delivery system is introduced.
No environment variable has been changed by this implementation.

The build packages `src/authentication/email/schema.sql` into `dist`.
It adds `email_authentication_results` and `email_authentication_audit`.
When H2 is configured, these additive tables are prepared at startup even with H4
disabled; route registration and OIDC handoff remain gated by explicit activation.
This permits migration verification before any authentication traffic is enabled.
The H2 schema expands the named purpose CHECK constraint atomically and
idempotently, preserving all old purposes and rows. It needs an ALTER TABLE lock;
schedule approved rollout appropriately. Do not change other challenge constraints.
No identity, registration, linking, authenticator, or provenance table shape changes.
Disabling H4 rolls back activation without deleting durable audits or evidence.
Expired capability rows are inert; retention/deletion, if later required by policy,
must be explicitly configured without deleting verification/audit evidence.

## Validation

Use local, dedicated PostgreSQL test databases, never production:

```sh
npm run build
npx vitest run
HAPI_AUTHENTICATION_TEST_DATABASE_URL='<isolated test database>' \
  npx vitest run tests/EmailAuthentication.postgres.test.ts
```

H4's PostgreSQL tests use unique per-run schemas and remove only their own schema.
They cover canonical resolution, unknown/ineligible/cross-provider outcomes,
unchanged identity/downstream counts, context/purpose/client isolation, replay,
concurrent verify/result issuance/handoff, expiry, changed eligibility/email,
atomic rollback, legacy purpose migration, and real OIDC code/token/userinfo flow.
Unit/HTTP tests cover H2 reuse, attempts, resend/rotation, shared budgets, strict
request schemas, confidential authority and opt-in configuration. Architecture
tests forbid downstream product, face, registration, account-link and credential
model dependencies in H4 core.

Run existing H1 PostgreSQL foundation tests on a separate clean database from
provenance fixtures: its legacy backfill can otherwise scope other suites' leftover
subjects to its application and cause an unrelated teardown FK failure. No H1
implementation or test behavior has been changed to mask this.

Local validation completed:

- `npm run build`: passed, including packaging the H4 SQL.
- Full `npx vitest run` with isolated H2/H3/H4 PostgreSQL URLs: **300 passed,
  18 skipped** across 54 files; the skipped DATABASE_URL-gated H1/registry/schema/
  provenance tests also passed separately.
- H4-specific coverage: **35 passing tests**, including **20 real-PostgreSQL
  tests** and the canonical-subject OIDC token/userinfo handoff.
- All PostgreSQL coverage: **53 tests passed** across isolated configurations.
- `git diff --check`: passed. No production network calls, push or deploy.

Remaining release prerequisite: approved production activation and live email /
OIDC validation. Cross-provider linking, browser UI and session UX are explicitly
out of scope. This implementation does not push, deploy, or perform production
requests as part of the automated test suite.

## Controlled release checkpoints

Commit only H4 implementation, tests, configuration and related documentation.
Use the normal GitHub-linked Railway deployment and match its commit to
local `main` and `origin/main`. Keep `HAPI_EMAIL_AUTHENTICATION_ENABLED` false or
unset throughout this release.

Before activation, verify both authentication tables and the expanded purpose
constraint directly in PostgreSQL. Compare pre/post row counts and fingerprints
for all IdentitySubjects, provenance, verification challenges, registration
evidence/audit, authenticators, account links and face transaction tables.
The certified H3 subject and its two HAPI_EMAIL provenance rows must be unchanged.
H4 email routes and POST `/authorize` must reject requests while disabled.
Use non-mutating H2/H3 validation probes and OIDC discovery/JWKS/client-validation
checks; do not send an authentication email or launch a face ceremony.
Readiness uses the service's existing dependency checks; no readiness behavior
is changed by H4.

Stop after deployment verification and report whether activation is ready.
Enabling H4 and live authentication require the separate approved activation step.
