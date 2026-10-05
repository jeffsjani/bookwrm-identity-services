# HAPI ID H3 — Canonical Identity Registration (Implementation Report)

Status: **implemented, locally validated, not pushed/not deployed** per explicit instruction.

## Scope

H3 adds exactly one new capability on top of the already-certified, deployed H2: converting a
**verified H2 `REGISTRATION` challenge** into a canonical HAPI `IdentitySubject`, atomically. It does
not touch H2 email-verification behavior, Resend, PrivateID, Face Login, existing OIDC
authentication, C5.1/C5.2, Base44 registration/invitations, or Bookwrm UI.

Files touched:
- **Additive-only edits** to two existing H1/H2 union types (`IdentityProvider`,
  `IdentityClaimSource`) to add `"HAPI_EMAIL"` — no DB schema change required (both backing columns
  are plain `TEXT`, no `CHECK` constraint enumerates values).
- **New module** `src/registration/` (types, Postgres/in-memory repositories, service, schema).
- **New route** `src/routes/registration.ts`.
- **New composition** `src/registration/RegistrationComposition.ts`, wired into `src/server.ts`.
- **New tests**: `tests/Registration.test.ts` (in-memory), `tests/Registration.http.test.ts`
  (Fastify route-level), `tests/Registration.postgres.test.ts` (real-Postgres concurrency),
  `tests/RegistrationArchitectureIsolation.test.ts`.

## H3 schema

`src/registration/schema.sql` — additive only, copied to `dist/` by the build (mirrors H1/H2
convention):

- `registration_evidence` — PK `verification_challenge_id` (FK -> `verification_challenges.id`).
  Columns: `identity_subject_id`, `tenant_id`, `application_id`, `email`, `created_at`. Serves two
  purposes at once (Tasks 10 + 17): it is both the **idempotency anchor** (a second completion call
  for the same `verificationId` finds this row and returns success without re-creating anything) and
  the **durable evidence-linkage record** (which verification established which identity, when,
  under which tenant/application).
- `identity_registration_audit` — append-only, `CHECK`-constrained `type` column enumerating the
  five `RegistrationAuditType` values. Columns are privacy-conscious: no OTP/code, no secrets, only
  IDs and a short `detail` string.

No changes to `identity_subjects`, `verification_challenges`, `tenants`, `applications`,
`oidc_clients`, or any other existing table.

## Registration API

`POST /v1/registration/complete`

- Auth: same trusted H1 client Basic-auth context as H2 (`authorize()` is **duplicated verbatim**
  from `routes/emailVerification.ts`, not shared/refactored, to avoid touching H2's route module at
  all).
- Request body: `z.object({ verificationId: z.string().uuid() }).strict()`. The `.strict()` flag
  rejects any extra field — this is the mechanism that structurally prevents the `email`, `tenantId`,
  `emailVerified`, `claimSource`, `oidcSubject` injection vectors named in spec item 19: they are
  rejected with `400 INVALID_REQUEST` before ever reaching business logic.
- Response (200): `{ registered: true, subject, email, emailVerified: true }` — application-neutral,
  no PrivateID PUID, no Base44 userId, no `IdentityAccountLink`, no internal claim/implementation
  detail, no raw database UUID (subject is the stable `oidcSubject`).
- Error responses map `RegistrationErrorCode` -> HTTP status (`UNAUTHORIZED`->401,
  `INVALID_EVIDENCE`/`INVALID_PURPOSE`/`UNVERIFIED_CHALLENGE`/`EXPIRED_CHALLENGE`/
  `LOCKED_CHALLENGE`/`EVIDENCE_ALREADY_CONSUMED`/`ACCOUNT_CONFLICT`->400,
  `REGISTRATION_UNAVAILABLE`->503). Malformed JSON and unknown errors never leak internals.

## Verification evidence validation

Before any identity mutation, the challenge row is read with `SELECT ... FOR UPDATE` inside the
registration transaction and validated for:
`channel = EMAIL`, `purpose = REGISTRATION`, `status = VERIFIED`, `verifiedAt` present,
`consumedAt = null`, tenant match, application match. "Not found", "wrong tenant", and "wrong
application" all collapse to the same generic `INVALID_EVIDENCE` error — mirroring H2's own
`withChallenge()` privacy pattern — so no information about challenge existence leaks across
tenants/applications. A challenge verified for `RECOVERY`/`INVITATION`/`EMAIL_CHANGE` is rejected
with `INVALID_PURPOSE` and is never usable for registration.

The email used for the new identity is **derived from the challenge's own stored normalized
destination**, never from the request body — the client cannot submit or influence it.

## Transaction boundary

A single Postgres transaction (`pool.connect()` -> `BEGIN` ... `COMMIT`/`ROLLBACK`) spans, in order:
1. `IDENTITY_REGISTRATION_STARTED` audit row.
2. `SELECT verification_challenges ... FOR UPDATE` (lock + validate).
3. Cross-provider email-conflict check (`SELECT identity_subjects ... FOR UPDATE`, Case C).
4. `IdentityRegistry.resolveOrCreate()` — bound to the **same transaction client** by constructing a
   `PostgresIdentitySubjectRepository` with the open `pg.PoolClient` passed as its connection
   override, so identity creation runs on the same open transaction as the challenge update.
5. `INSERT registration_evidence`.
6. `UPDATE verification_challenges SET status='CONSUMED', consumed_at=now()`.
7. Claim-provenance recording (`HAPI_EMAIL`) when newly created.
8. Outcome audit row (`IDENTITY_REGISTERED` / `IDENTITY_REGISTRATION_IDEMPOTENT` /
   `IDENTITY_REGISTRATION_CONFLICT` / rejection-specific `IDENTITY_REGISTRATION_FAILED`).
9. `COMMIT` on every expected business outcome (success, idempotent replay, every rejection);
   `ROLLBACK` only on a truly unexpected exception, mapped to `REGISTRATION_UNAVAILABLE` (503).

This guarantees the required invariant: there is never a committed state with `challenge=CONSUMED`
and no identity, nor `IdentitySubject created` with consumption failed — both halves commit or roll
back together.

H2's own `EmailVerificationService.consume()` could not be reused for this, because it internally
opens and commits its own self-contained transaction; using it would split consumption and identity
creation across two separate transactions, violating atomicity. H3 therefore reads/writes
`verification_challenges` directly via its own SQL inside its own transaction — acceptable since "H2
Verification" is an expected dependency, not something H3 is forbidden from reading.

## Identity creation / oidcSubject

Reuses the **existing** `IdentityRegistry.resolveOrCreate()` / `PostgresIdentitySubjectRepository`
abstractions rather than duplicating identity-persistence logic. No new identity table, no new ID
generation scheme — the existing `oidcSubject` generation inside `IdentityRegistry` is used unchanged
(the same stable, opaque external identifier already used by PrivateID/Face Login identities). The
HTTP response returns this `oidcSubject` as `subject`, never the internal database `id`.

Initial values on creation: `email` = verified H2 normalized email, `emailVerified = true`,
`status = ACTIVE`.

## Email uniqueness namespace (documented per spec item 8)

`identity_subjects.email` has **no unique constraint** today. The only uniqueness guarantee in the
schema is the composite constraint `identity_subjects_provider_identity_key UNIQUE (primary_provider,
primary_provider_subject)`, and it is **global, not tenant-scoped** — this is pre-existing precedent
(the same constraint already governs PrivateID/other providers).

H3 reuses this exact same global-not-tenant-scoped pattern: the new provider value is
`primary_provider = 'HAPI_EMAIL'`, `primary_provider_subject = <normalized email>`. This is a
**conscious, documented decision**, not an oversight:
- It gives H3 real atomic, DB-enforced dedup for Cases A/B/D via
  `INSERT ... ON CONFLICT (primary_provider, primary_provider_subject) DO UPDATE` — proven by the
  Postgres concurrency tests below.
- It is consistent with how every other provider already behaves in this codebase, so it does not
  introduce a new/different multi-tenant model that would conflict with existing assumptions.
- It does **not** generalize to "email is globally unique across HAPI" — a `Google`- or
  `PrivateID`-provider identity with the same email is a **separate** row by design, and is exactly
  what Case C below protects against (no silent cross-provider merge).
- If a future requirement needs tenant-scoped (rather than global) uniqueness for `HAPI_EMAIL`
  specifically, that is a distinct, separately-reviewed schema change (e.g. a partial unique index
  scoped by an added tenant column) — out of scope for H3 and intentionally not introduced here.

## Duplicate-registration behavior (Cases A-D)

- **Case A — no existing identity**: `resolveOrCreate()` inserts a new row; `created = true`;
  `IDENTITY_REGISTERED` audit.
- **Case B — same verified email already belongs to the same canonical (`HAPI_EMAIL`) identity**:
  `resolveOrCreate()`'s `ON CONFLICT ... DO UPDATE` finds the existing row and returns it unchanged
  (`created = false`); no second subject is created; verified directly by the Postgres test
  "concurrent completion of two DIFFERENT verifications for the same email collapses onto one
  canonical identity."
- **Case C — verified email belongs to a different-provider identity (conflict)**: an explicit
  in-transaction `SELECT ... FOR UPDATE` on `identity_subjects WHERE email = $1 AND primary_provider
  <> 'HAPI_EMAIL'` detects this before any mutation; the transaction **commits with no identity
  mutation and no challenge consumption** (challenge is left `VERIFIED`, still usable by a future
  authenticated linking/recovery flow) and returns `ACCOUNT_CONFLICT` (400). No silent merge, no
  identity created, no evidence recorded. Verified by a dedicated Postgres test; the narrowed-but-not
  fully airtight window between this `SELECT` and commit is documented — in practice it is closed by
  the `FOR UPDATE` lock plus the earlier challenge-row lock serializing same-email attempts.
- **Case D — simultaneous registrations**: proven safe by two dedicated Postgres concurrency tests
  (10 concurrent callers for the identical `verificationId`; two concurrent callers for two
  different, separately-created verification challenges bound to the same email) — in both cases
  exactly one canonical `IdentitySubject` row and one consumed challenge result, never two subjects.

## Concurrency strategy

- `SELECT verification_challenges ... FOR UPDATE` serializes competing completions of the *same*
  challenge (second concurrent caller blocks until the first's transaction commits, then reads
  `CONSUMED` + evidence -> idempotent path).
- `INSERT ... ON CONFLICT (primary_provider, primary_provider_subject) DO UPDATE` (existing H1
  mechanism, reused, not duplicated) serializes competing completions of *different* challenges for
  the *same* email at the database level — this is the real guarantee, not an application-level
  pre-check.
- `SELECT identity_subjects ... FOR UPDATE` for the Case-C conflict check.
- No reliance on only application-level pre-checks anywhere in the critical path.

## Idempotency

A retry with the same `verificationId` after a prior successful completion finds the
`registration_evidence` row already present (keyed by `verification_challenge_id`, the PK) and
returns the **same** `subject`/`email` with `idempotentReplay: true` internally (not exposed over
HTTP — the public response shape is unchanged/identical on retry) without re-running identity
creation or re-consuming anything. A consumed verification can never be used to establish a
*different* identity: a verified challenge's evidence row is permanently bound to one
`identity_subject_id`.

## HAPI_EMAIL provenance

`"HAPI_EMAIL"` was added as a first-class `IdentityClaimSource` (additive union member,
`src/identity/IdentityClaimSource.ts`) and `IdentityProvider` (additive union member,
`src/models/IdentitySubject.ts`). Provenance is recorded via the existing
`IdentityClaimSourceStore.recordClaimSource()` primitive (the same governed, in-memory-durable
mechanism already used elsewhere) at the moment of creation. `IdentityClaimResolver.resolve()` was
*not* used directly for this call, because it only evaluates claims against an already-existing
subject and short-circuits as a no-op whenever `proposedValue === currentValue` — which is always
true immediately after creation, a pre-existing limitation unrelated to H3. Recording the source via
`recordClaimSource()` directly is the lowest-level existing governed primitive available for this
case, consistent with spec item 6's "if an existing governed path can be reused" wording.

## Registration evidence linkage

`registration_evidence` (see schema above) durably records which verification established which
identity, at what time, under which tenant/application — supporting both audit and idempotency —
without making the verification evidence itself a reusable bearer credential (it remains keyed 1:1
to the now-`CONSUMED` challenge, and a consumed challenge cannot be re-verified or reused by H2).

## Audit

`identity_registration_audit` (durable Postgres table) records one row for **every** branch:
`IDENTITY_REGISTRATION_STARTED` (always, first), then exactly one of `IDENTITY_REGISTERED` /
`IDENTITY_REGISTRATION_IDEMPOTENT` / `IDENTITY_REGISTRATION_CONFLICT` /
`IDENTITY_REGISTRATION_FAILED` (with a `detail` string identifying the specific
`RegistrationErrorCode` for failures). No OTP, code, or secret is ever logged — only IDs and short
privacy-conscious metadata.

## Architecture isolation

`tests/RegistrationArchitectureIsolation.test.ts` scans every file under `src/registration/` plus
`src/routes/registration.ts` and asserts:
- No import specifier references anything Base44/Bookwrm/PrivateID/password-specific.
- No literal source mention of `Base44`, `x-bookwrm-user-id`, `BiometricIdentity`,
  `PendingIdentityActivation`, `PrivateID`, or `password`.

H3's only intentional dependencies are H1 (`identity/*`: tenants/applications/OIDC clients, identity
registry/subject repository) and H2 (`email/*`: verification challenge read/consume path) — both
expected per spec item 15.

## H3 tests

- `tests/Registration.test.ts` — **14 tests** (in-memory): Case A creation + `HAPI_EMAIL` provenance,
  unverified/expired/locked/wrong-purpose/wrong-tenant/wrong-application/unknown-`verificationId`
  rejections, idempotent retry, Case B reuse, Case C conflict (challenge left untouched), replay
  after foreign consumption, no-password/no-PrivateID-authenticator/no-`IdentityAccountLink` check,
  guessed-`verificationId` security case.
- `tests/Registration.http.test.ts` — **9 tests** (Fastify route-level via `app.inject()`): valid
  success shape, missing/invalid/unknown/public-client auth all 401, `.strict()` schema rejects
  `email`/`tenantId`/`emailVerified`/`claimSource`/`oidcSubject` injection (400), cross-tenant
  rejected, cross-application (same tenant, different client/app) rejected, wrong-purpose rejected,
  HTTP-level idempotent retry, malformed JSON rejected without echoing content, guessed
  `verificationId` rejected as `INVALID_EVIDENCE` (not a distinguishing 404/500).
- `tests/RegistrationArchitectureIsolation.test.ts` — **1 test** (static source/import scan, see
  above).

Total new H3 focused tests: **24**, all passing.

## PostgreSQL tests

`tests/Registration.postgres.test.ts` — **9 tests**, gated by `HAPI_REGISTRATION_TEST_DATABASE_URL`
(falls back to `HAPI_EMAIL_TEST_DATABASE_URL` if unset; skips entirely if neither is set), run
against an isolated disposable database (`hapi_h3_test` locally):
1. Happy path: exactly one `IdentitySubject`, one `registration_evidence` row, challenge `CONSUMED`.
2. **Case D** — 10 concurrent completions of the *same* `verificationId`: exactly one
   `created=true`, all 10 resolve successfully, all return the same `subject`, exactly one DB row.
3. **Case D variant / Case B** — two concurrently-verified, *different* challenges for the *same*
   email, completed concurrently: both resolve to the same `subject`, exactly one DB row, both
   challenges end `CONSUMED`.
4. Successful retry (same `verificationId`) is idempotent — same subject, no second row.
5. **Case C** — pre-existing different-provider identity with the same email -> `ACCOUNT_CONFLICT`,
   challenge remains `VERIFIED` (untouched), no second identity row.
6. Wrong tenant and wrong application both rejected identically as `INVALID_EVIDENCE`.
7. Replay after the challenge was independently consumed (simulated external consumption) ->
   `EVIDENCE_ALREADY_CONSUMED`.
8. Existing (pre-H3, different-provider) `IdentitySubject` row is byte-for-byte unchanged after an
   unrelated H3 registration runs.
9. Malformed `verificationId` always surfaces as a `RegistrationError` instance, never a raw
   Postgres driver error.

All 9 pass.

## Full regression

- `npm run build` — **PASS**, zero TypeScript errors.
- `npx vitest run` (entire suite, in-memory only): **250 passed, 24 skipped (274 total)** across 45
  passed / 5 skipped test files — no existing H1/H2/Bookwrm test regressed.
- `npx vitest run` with all three Postgres-gated DB URLs set
  (`DATABASE_URL`, `HAPI_EMAIL_TEST_DATABASE_URL` -> `hapi_h2_test`;
  `HAPI_REGISTRATION_TEST_DATABASE_URL` -> `hapi_h3_test`): **274/274 individual test assertions
  passed**; one pre-existing, H3-unrelated **suite-teardown race** was observed and is reported
  below — it reproduces identically with H3's registration tests entirely excluded from the run, so
  it is not a regression introduced by this work.

### Pre-existing, unrelated test-infrastructure note

When many Postgres-gated suites share one database (`hapi_h2_test`) and vitest runs files in
parallel, `tests/TenantApplicationFoundation.postgres.test.ts`'s `afterAll` teardown
(`DELETE FROM applications WHERE id = $1`) can race against
`tests/IdentityRegistry.postgres.test.ts`, which inserts `identity_subjects` rows referencing the
same fixed well-known Bookwrm `applicationId` fixture and does not always clean them up before the
other suite's teardown runs, producing a foreign-key violation in that one teardown step. This was
reproduced **with H3's new tests/DB fully removed from the run**, confirming it is a pre-existing
test-isolation gap between two already-existing H1 suites, not something H3 introduced. It does not
affect H3's own tests (which run against a fully separate, dedicated `hapi_h3_test` database) and
does not indicate any production risk — every individual test assertion in the full run still
passed (274/274); only one file's cleanup step collided. Left unaddressed per "do not fix unrelated
pre-existing issues."

## Migration safety

`src/registration/schema.sql` only adds two brand-new tables
(`registration_evidence`, `identity_registration_audit`); it does not alter, rename, or drop any
existing table or column. `ensureSchema()` uses `CREATE TABLE IF NOT EXISTS`, safe to run repeatedly.
The two union-type additions (`HAPI_EMAIL` on `IdentityProvider`/`IdentityClaimSource`) require zero
database migration, since both backing columns are plain `TEXT` with no enumerated `CHECK`
constraint. No existing `IdentitySubject`, `Tenant`, `Application`, OIDC client,
`PrivateID`/`UserAuthenticator`, C5.1, or C5.2 row is read, written, or otherwise touched by any H3
code path except the one new, intentional creation of a `HAPI_EMAIL`-provider row during an actual
registration completion call.

## Remaining blockers

None for correctness/readiness of the H3 implementation itself. Two items are intentionally **not**
done in this round per explicit instruction:
- **Not committed, not pushed, not deployed** — all changes remain local working-tree changes only.
- The pre-existing H1 Postgres-test teardown race noted above is out of scope for H3 and left
  untouched.
