# H5: attach Face to an existing HAPI identity

## Existing enrollment analysis

The legacy `PrivateIDEnrollmentService.startEnrollment()` records its principal's
`userId` in `privateid_enrollment_transactions`. Its completion does **not** derive
the canonical subject from that stored authority: it calls
`IdentityRegistry.resolveOrCreate({ provider: "PrivateID", providerSubject: puid })`.
Supplying a HAPI `oidcSubject` or internal ID to that start method therefore cannot
safely attach Face to an existing HAPI_EMAIL subject.

H5 adds a distinct, explicit attachment seam. It reuses:

- `PrivateIDClient.createEnrollmentSession()` and the existing certified Face ceremony
  (the provider request remains `VERIFY` with a Face requirement);
- `privateid_enrollment_transactions` and its repository;
- `user_authenticators`, its repository and its existing uniqueness constraints;
- the shared-secret-authenticated `/privateid/webhook`;
- `AuthenticatorLoginResolver` and the existing authorization-code/PKCE/OIDC machinery.

The new completion never calls the legacy identity-creating completion.
Legacy enrollment stays available for compatibility; it is not HAPI attachment
authority. Cross-provider account consolidation and legacy product repair are not H5.

## Authority and policy

`POST /v1/authenticators/privateid/enroll` accepts an existing opaque **H4 access
token** in `Authorization: Bearer <access_token>`, and an empty body `{}` (or no body).
It does not accept an ID token, the short-lived H4 authentication result, a client
secret, email, subject ID, `oidcSubject`, PUID, tenant/application ID, or a product
user header as authority. Extra body fields return 400.

The existing server-side Redis access-token record now retains the original
authentication method and timestamp, not mutable email claims. H5 requires:

- unexpired token, `openid` scope, method `HAPI_EMAIL`;
- finite, nonfuture authentication timestamp **no older than five minutes**;
- an existing ACTIVE HAPI_EMAIL subject, verified email equal to its provider key;
- the subject's current application matching the token's persisted confidential
  H1 client, and both application and tenant active.

The five-minute freshness policy was explicitly approved. The database rechecks
freshness after canonical subject lock acquisition. Access tokens minted before
this metadata extension fail closed; obtain a fresh H4 login first.
Face-authenticated tokens cannot authorize enrollment: email step-up is required.

Authority is derived from the server-side token's stable `sub` and current H1 rows.
Only the server resolves the internal subject ID. Reservation and publication
revalidate authority; new attachment completion revalidates subject and tenant/application/client
binding under locks. Ceremony expiry is at most five minutes, capped by provider
expiry. The recent-email requirement authorizes the ceremony's start; the bound,
short-lived ceremony is its completion authority.

## Public API

New ceremony, HTTP 200:

```json
{
  "enrolled": false,
  "enrollmentId": "<opaque provider transaction reference>",
  "launchUrl": "<provider Face ceremony URL>",
  "expiresAt": "<ISO timestamp>"
}
```

Already active, HTTP 200, without another provider call:

```json
{ "enrolled": true, "alreadyEnrolled": true }
```

No internal identity UUID, email, PUID, token, or client credential is returned.
The launch URL is necessary to run the provider ceremony; treat it as sensitive.
Responses use `Cache-Control: no-store`.

Errors: 401 missing/expired/insufficient recent email authority; 403 ineligible
canonical identity or H1 context; 400 unexpected input; 409 existing pending
ceremony or authenticator ownership conflict; 502 invalid/unavailable provider session.
Provider failures return sanitized `PROVIDER_SESSION_FAILED` errors, not raw upstream
response bodies; database failures surface as server errors. A reserved provider
failure is audited. The H5 provider request has a ten-second
abort deadline. Failed/expired reservations permit a new authorized ceremony.
No password or new OTP/session-identity system is introduced.

## Completion, correlation, conflicts

Only the existing **authenticated provider webhook** may attach a PUID. H5 requires
the exact random `transactionID` issued for enrollment. Session ID is optional for
the provider's transaction-only contract; when supplied, it must match the durable
provider-session binding. There is no identifier guessing, current-session fallback,
transaction-ID-as-PUID fallback, browser-supplied PUID authority, or email lookup.

H5 dispatch occurs before legacy webhook diagnostics, identity resolution and
enrollment. It never persists the webhook body or biometric data. HAPI sessions
are explicitly marked so unbound callbacks cannot enter legacy completion.
When H5 dispatch is installed, explicit unknown/mismatched identifiers no longer
fall back to the process's current legacy session. Valid legacy/OIDC correlation
and APIs remain intact.

`GET /privateid/callback` recognizes durable H5 bindings and reports their persisted
enrollment status; it cannot attach Face or issue a login code. Browser success
parameters are not provider evidence. The shared provider callback may run before
the webhook and return `pending`; inspect again after provider completion. No UI
integration is included.

Database completion locks the canonical subject and enrollment transaction in a
consistent order, then serializes absent-row PUID claims with a transaction-scoped
advisory lock. Existing unique `(provider, provider_subject)` and partial unique
active-Face-per-user constraints remain the final defense against concurrent
legacy writers. Expiry is rechecked after lock waits and before final completion.
Authenticator creation, binding, transaction completion and audit commit atomically.
An audit failure rolls back the entire attachment.

- Same completed ceremony/PUID/same active subject: idempotent success.
- Subject already has active Face: start returns already enrolled.
- Existing active same-subject PUID during completion: reuse, never duplicate.
- PUID owned by another subject, including a legacy PrivateID canonical identity:
  conflict; never move, merge, or change the existing owner.
- Revoked PUID: conflict, even for the same subject; no implicit reactivation.
- Different active Face during a pending ceremony: conflict.
- Concurrent starts: one ceremony; other starts return `ENROLLMENT_IN_PROGRESS`.
- Concurrent same-ceremony completion: one authenticator, idempotent followers.
- Concurrent cross-subject same-PUID completion: one winner, one conflict.

## Canonical identity and authentication continuity

The authenticator's `user_id` is the **existing `IdentitySubject.id` rendered as text**,
not a product identifier and not `oidcSubject`. H5 never inserts or updates an
IdentitySubject, registration evidence, or claim provenance. Primary provider stays
HAPI_EMAIL; email, verification state, identity IDs and HAPI_EMAIL provenance remain
unchanged. No `IdentityAccountLink` or product membership is required.

Face login already resolves `PUID → UserAuthenticator → IdentitySubject` using
`AuthenticatorLoginResolver`, without email lookup or identity creation. A successful
Face OIDC webhook now carries `PRIVATEID_FACE` and its authentication timestamp;
the callback preserves that timestamp instead of refreshing it. Existing ID-token
issuance emits `amr: ["face", "privateid"]` and `auth_time` for that method.
H4 remains `amr: ["email"]` with its original H4 authentication timestamp.
Both methods use the same stable canonical `sub`, code/token store and `/userinfo`.
This supports email **or** Face authentication conceptually; full recovery, removal,
replacement, UI and cross-provider identity consolidation are outside this scope.

## Audit and isolation

`authenticator_enrollment_audit` contains tenant/application/client, canonical
subject/enrollment references, provider, timestamp and sanitized outcome:

- `AUTHENTICATOR_ENROLLMENT_STARTED`
- `AUTHENTICATOR_ENROLLED`
- `AUTHENTICATOR_ALREADY_ACTIVE`
- `AUTHENTICATOR_ENROLLMENT_CONFLICT`
- `AUTHENTICATOR_ENROLLMENT_FAILED`

No biometric payload, PUID, OTP, launch URL, access token or raw secret is written
to this audit. Invalid unauthenticated API requests are rejected with sanitized
route logs; they have no trusted subject to attach an enrollment audit to.

Core has no Base44, Bookwrm user-ID, account-link, C5.1/C5.2 claim-governance or
registration dependency. A transitive runtime import test enforces this isolation.
The existing legacy product adapters remain outside H5.

## Additive migration and activation

`src/authenticators/schema.sql` adds:

- `hapi_face_enrollment_bindings`: foreign-key-bound enrollment authority, provider
  session correlation and completed authenticator reference;
- `authenticator_enrollment_audit`: durable lifecycle events.

It does not rewrite existing identity, authenticator, enrollment, provenance or
registration rows. SQL is packaged by `npm run build` and idempotently prepared at
startup on the PostgreSQL driver, even while H5 is disabled. Callbacks still recognize
H5 bindings while disabled and reject new completion with 503; they cannot fall
through to legacy identity creation. Memory-only tests keep H5 unavailable.

`HAPI_FACE_ENROLLMENT_ENABLED=false` is the default. Enabling requires PostgreSQL
and `HAPI_EMAIL_AUTHENTICATION_ENABLED=true`. No production code, variables, schema,
identity, commit, push or deployment has been changed during H5 development.
Production activation, real provider delivery/correlation and live Face ceremony
validation remain approval-gated. Do not use the H3/H4-certified production identity
until that approval.

## Validation

```bash
npm run build
npx vitest run

# Isolated schema-per-run PostgreSQL tests, against a fixture database only:
HAPI_FACE_ENROLLMENT_TEST_DATABASE_URL=<local-test-url> \
  npx vitest run tests/HapiFaceEnrollment*.test.ts
```

For complete database regression also configure `HAPI_EMAIL_TEST_DATABASE_URL`,
`HAPI_REGISTRATION_TEST_DATABASE_URL`, and `HAPI_AUTHENTICATION_TEST_DATABASE_URL`.
Run the four existing `DATABASE_URL` suites separately. The H1 foundation fixture
requires its own clean database because its legacy backfill/teardown conflicts
with other registry fixture subjects when they share a database.

H5 tests cover real H3 registration fixtures, unchanged canonical identity and
provenance/evidence, recent token authority, strict APIs, active/suspended scope,
PUID conflicts, revocation policy, PostgreSQL races and lock-wait expiry, durable
restart correlation, audit atomicity, disabled additive migration, authenticated
webhooks, and full H4-email → H5-attachment → Face-OIDC → H4-email continuity.
They assert no Base44 call, identity creation, registration call, account link
or raw webhook diagnostics in the H5 path.

Local validation results:

- `npm run build`: PASS, including packaged SQL equality.
- H5 focused tests: **52 PASS**, including **29 PostgreSQL**.
- Full suite with H2/H3/H4/H5 isolated PostgreSQL URLs: **352 PASS**,
  with the 18 `DATABASE_URL`-gated tests skipped in this invocation.
- Those 18 gated tests, run separately against fixture databases: **18 PASS**
  (H1 foundation: 3; registry/provenance/schema: 15).
- Combined distinct regression coverage: **370 PASS**; no unresolved skipped suite.
