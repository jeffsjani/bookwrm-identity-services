# HAPI ID H2: Email Verification

H2 establishes verified email evidence only. It never reads, creates, resolves, merges, or updates an IdentitySubject. No existing identity/login/registration/invitation flows are changed. H2 is opt-in and has not been deployed.

## Schema and lifecycle

`src/email/schema.sql` adds `verification_challenges`, `verification_delivery_events`, and `email_verification_audit`. The challenge stores every requested H2 field as a first-class column. Application is nullable; tenant is required. There is no foreign key to IdentitySubject. The migration is idempotent and runs when H2 is explicitly enabled. The build packages this SQL separately from H1's unchanged schema.

Lifecycle: `PENDING -> VERIFIED -> CONSUMED`, or `PENDING -> EXPIRED / LOCKED`. Unconsumed verified evidence also becomes EXPIRED when consumption is attempted after expiration. Expiration is checked on operations, not by a background sweeper. Resend stays on the same pending challenge, rotates the OTP, renews expiration, and does not reset failed attempts. Verified evidence must be consumed before its challenge expiration.

## Normalization and OTP security

`normalizeEmail` trims surrounding whitespace, validates an unquoted ASCII local part and DNS domain (including IDN-to-ASCII conversion), and lowercases the domain. Local-part casing, dots, and plus-addressing are preserved. Quoted local parts, address literals, and SMTPUTF8 local parts are intentionally unsupported. There are no mailbox-provider transformations.

OTPs use Node's cryptographic `randomInt`, including leading zeros. Only challenge-bound HMAC-SHA-256 hashes are stored. A separate HMAC domain hashes destinations for rate limiting and privacy-conscious telemetry. Comparisons use `timingSafeEqual`. OTP hashes are cleared on verification, expiration, and lock. Codes exist transiently only in delivery requests; the in-memory test provider deliberately captures them for assertions.

The verification secret must be high-entropy, at least 32 bytes, stable across replicas/restarts, and distinct from client/provider/webhook credentials. Changing it invalidates outstanding codes and changes rate-limit destination hashes. Coordinate rotation rather than replacing it during an active challenge window.

## Policy

All configurable values live in `VerificationPolicy`, with positive integer validation:

| Optional Railway variable | Default |
| --- | --- |
| `HAPI_EMAIL_OTP_LENGTH` | 6 (supported range 6-9) |
| `HAPI_EMAIL_EXPIRATION_SECONDS` | 600 |
| `HAPI_EMAIL_MAX_ATTEMPTS` | 5 |
| `HAPI_EMAIL_RESEND_COOLDOWN_SECONDS` | 60 |
| `HAPI_EMAIL_MAX_SENDS_PER_CHALLENGE` | 5 |
| `HAPI_EMAIL_MAX_SENDS_PER_DESTINATION_HOUR` | 10 |
| `HAPI_EMAIL_MAX_SENDS_PER_DESTINATION_DAY` | 30 |
| `HAPI_EMAIL_PROVIDER_TIMEOUT_MS` | 10000 |

Destination limits are rolling hourly/daily windows, scoped to tenant plus normalized destination and shared across applications. Send reservations, including failed/timed-out requests, count against limits. PostgreSQL transactions take a tenant/destination advisory lock before reading/updating challenges and send history. Verify/resend/consume use the same lock across replicas. External delivery happens after commit with a deadline and AbortSignal; provider errors are sanitized. A timeout can have an uncertain delivery outcome, but can never establish ownership.

## APIs and trusted authority

All three APIs require HTTP Basic authentication using a persisted, confidential H1 OIDC client's ID and secret. Public clients (`tokenEndpointAuthMethod=none`), suspended applications, and suspended tenants are rejected. Tenant/application context is resolved from H1 repositories, never from browser-supplied tenant headers or IDs. Optional `applicationId` must match the authenticated client's application. Other body fields, including `tenantId`, are rejected.

These are server-to-server endpoints. Do not place client secrets in browsers. A public-browser client authorization mechanism is not part of H2.

* `POST /v1/identity/email/start`: `{ "email": "person@example.com", "purpose": "REGISTRATION", "applicationId": "optional UUID" }` returns `{ "challengeId": "UUID", "expiresIn": 600, "resendAfter": 60 }`.
* `POST /v1/identity/email/resend`: `{ "challengeId": "UUID" }` returns the same shape. Cooldown and limits return 429. Concurrent eligible resends have one winner.
* `POST /v1/identity/email/verify`: `{ "challengeId": "UUID", "code": "123456" }` returns `{ "verified": true, "verificationId": "UUID" }`. Optional `purpose` asserts the expected purpose. Invalid codes consume attempts; exhausted challenges lock. Concurrent verification has one winner.

Purposes are `REGISTRATION`, `INVITATION`, `RECOVERY`, `EMAIL_CHANGE`, and (H4) `AUTHENTICATION`. Responses have `Cache-Control: no-store`. Start never consults the identity registry and has identical response shape/status for registered and unknown emails. Provider failure/timeout returns generic 503. Request parsing errors, provider payloads, OTPs, OTP hashes, and credentials are never logged by H2.

H4 reuses this service through dedicated authentication routes. The generic H2 verify route
still establishes evidence only, including for `AUTHENTICATION`; it does not issue an authenticated
principal or authentication result. Use the H4 verify route for that journey.
H2 and H4 share the trusted H1 Basic-auth helper without changing H2 authorization semantics.
The idempotent H4 purpose migration expands only `verification_challenges_purpose_check` in one
transaction; it preserves existing purposes, challenge data, and lifecycle rules.

## H3 consumption preparation

The server-side `consume(context, verificationId, email, purpose)` operation requires matching tenant, application, normalized email, purpose, challenge, verified status, and unexpired evidence. It atomically changes `VERIFIED` to `CONSUMED`. Reuse is rejected; concurrent consumers have one winner. There is no public consumption route and no IdentitySubject operation. `verificationId` is only a lookup identifier, not an unrestricted bearer credential. H3 will need to compose consumption and subject creation within its own transaction/idempotency boundary; H2 does not implement that later workflow.

## Providers, telemetry, and audit

Core imports only `EmailDeliveryProvider`; Resend API calls/configuration live in `src/adapters/email/resend` and composition. Tests use `InMemoryEmailDeliveryProvider`. Resend requests use a per-send idempotency key, fixed API endpoint, configured sender, and the generic plain-text HAPI ID template. Generic registration content does not mention any relying application.

Append-only delivery events distinguish challenge creation, send requested, provider accepted (with provider message ID), delivered, deferred, bounced, complained, suppressed, user verified, provider failed, and timeout. They describe operations, not ownership. Only OTP verification changes the challenge to VERIFIED.

Durable audit events: `EMAIL_VERIFICATION_STARTED`, `EMAIL_VERIFICATION_SENT`, `EMAIL_VERIFICATION_RESENT`, `EMAIL_VERIFICATION_FAILED`, `EMAIL_VERIFICATION_VERIFIED`, `EMAIL_VERIFICATION_EXPIRED`, `EMAIL_VERIFICATION_LOCKED`, and `EMAIL_VERIFICATION_RATE_LIMITED`. Events contain IDs, destination HMAC, and timestamps, not plaintext email, OTP, or codeHash. Rejected start rate-limit audits carry a request/challenge UUID without creating a challenge.

## Required Railway variables

* `HAPI_EMAIL_PROVIDER=resend` (leave unset to preserve H1-only behavior).
* `RESEND_API_KEY`: a secret key authorized to send with the verified domain.
* `HAPI_EMAIL_FROM=HAPI ID <verify@id.hapiinc.com>`.
* `HAPI_EMAIL_VERIFICATION_SECRET`: independent high-entropy secret of at least 32 bytes.
* `RESEND_WEBHOOK_SECRET`: the Resend endpoint's `whsec_...` signing secret, required for webhook activation but not outbound sends. Before it is configured, the unchanged webhook route returns 503 `WEBHOOK_NOT_CONFIGURED` and accepts no telemetry.
* `DATABASE_URL`: durable PostgreSQL with the deployed H1 Tenant/Application schema.
* `IDENTITY_REGISTRY_DRIVER=postgres`: retain the production H1 persistence setting.

No real credentials are stored in source or documentation. All replicas must use the same verification secret and policy.

## Required Resend configuration

Verify `id.hapiinc.com` in Resend and publish its required DNS records; authorize `verify@id.hapiinc.com` as sender. Set the sender display name to HAPI ID. Create an HTTPS webhook endpoint at `<HAPI_ID_ORIGIN>/v1/identity/email/webhooks/resend` and configure relevant events: `email.delivered`, `email.delivery_delayed`, `email.bounced`, `email.complained`, `email.suppressed`, and `email.failed` as available in the provider dashboard. Copy that endpoint's signing secret to `RESEND_WEBHOOK_SECRET`.

The adapter verifies the exact raw body using the official Svix signature mechanism (`svix-id`, `svix-timestamp`, `svix-signature`) before JSON parsing. Missing, stale, or altered signatures fail. Signed event IDs deduplicate retries. Unknown provider message IDs return 503 so events arriving before acceptance persistence are retried; unsupported signed event types are acknowledged without state changes. Provider-specific names do not enter Core.

## Validation

`npx vitest run tests/EmailVerification.test.ts` covers normalization, policy, hashing, lifecycle, limits, client authority, isolation, error/log privacy, providers, webhook signatures/replay, and a transitive Core architecture check. Identity repository spies and unchanged subject snapshots explicitly enforce the H2/H3 boundary.

`HAPI_EMAIL_TEST_DATABASE_URL=<disposable PostgreSQL URL> npx vitest run tests/EmailVerification.postgres.test.ts` exercises real schema migration and independent service/repository instances for verification/resend/consume concurrency, rate limits, rollback, audit persistence, no subject mutation, and webhook deduplication. Use a disposable database: the suite bootstraps the H1 schema and removes its test records afterward. These tests skip without that dedicated variable.

Required release gates are `npm run build` and `npx vitest run`. Live Resend sender/DNS/API/webhook delivery remains an operator-run provider integration check. No automatic deployment or push is performed.

### Verified results

* `npm run build`: passed, including packaged H1 and H2 SQL.
* Focused H2 suites: 43 passed (37 behavioral/security/architecture tests and 6 actual PostgreSQL tests).
* Full `npx vitest run`, with the dedicated H2 test database: 43 files passed, 3 database-gated files skipped; 231 tests passed, 9 skipped.
* Those 9 existing H1/PostgreSQL tests were also run on isolated disposable databases: all passed. In total, all 240 distinct tests were exercised successfully.
* Existing PostgreSQL test prerequisites matter: SchemaVersioning expects the H1 schema to be provisioned before running; sharing a database across H1 suites can leave IdentitySubjects that TenantApplicationFoundation backfills and then fails to remove before deleting their application in teardown. A grouped shared-database run reproduced that teardown failure. The H1-only suite passed on a fresh database; no existing code or tests were changed to conceal it.
* Runtime dependency audit reports pre-existing Axios (high), Fastify (moderate), and fast-uri (moderate) advisories. No advisory was reported for the new Svix dependency. Unrelated dependency remediation remains outside H2 and should precede a production rollout.

### Provider integration handoff

No H2 implementation blocker remains for provider integration. Railway variables, sender-domain DNS verification, HTTPS webhook registration, and a live send/verify/webhook smoke test still require operator configuration. No live provider credentials were supplied or used; provider acceptance and signed webhook tests used synthetic responses/secrets. No code was pushed or deployed.

### Controlled release preparation (2026-10-04)

Webhook activation is independent of outbound email: `RESEND_WEBHOOK_SECRET` may be absent at startup, and the fixed webhook route fails closed with 503 until its signing secret is configured. A configured webhook still requires raw-body signature verification. `RESEND_API_KEY` remains required when enabling the Resend provider; never deploy an enabled provider without it.

Release validation after a clean `npm ci`: build passed, focused H2 tests passed 43/43 including 6/6 isolated PostgreSQL tests, and full regression passed 231 tests with the same 9 existing database-gated skips. No count differences from the approved implementation report.

Production `DATABASE_URL` was already present. The explicit PostgreSQL driver matches the existing production default. The provider selector, sender, and a newly generated 48-byte verification secret were staged only for `bookwrm-identity-services` with automatic redeploys suppressed; no secret value was printed or stored in source. The Resend API key and webhook signing secret remain operator-supplied.

The H2 migration is additive CREATE TABLE/INDEX only and has no existing identity/authenticator/link/session mutations or backfills. Existing identity, OIDC, PrivateID, C5.1, C5.2, and application-specific sources were left unchanged. Production migration/deployment remains gated on provider configuration; current production readiness was checked without invoking any email endpoint. A GitHub-linked production service must not be pushed while the enabled provider lacks its API key.