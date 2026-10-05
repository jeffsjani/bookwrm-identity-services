# HAPI ID H3P — Durable Identity Claim Provenance

## Summary

H3.1's architecture review identified one concrete production blocker: `IdentityClaimSourceStore`
recorded which source (`HAPI_EMAIL`, `BOOKWRM`, `PRIVATE_ID`, ...) currently owns each
`IdentitySubject` claim (`email`, `emailVerified`, `displayName`) purely in process-local `Map`s,
with a comment explicitly describing this as "durable for process lifetime" — i.e. not durable at
all across a Railway restart/redeploy or a second service instance.

H3P replaces that in-memory store with a PostgreSQL-backed, repository-style abstraction, wires it
atomically into H3's existing registration transaction, and leaves every other H3/H2 behavior,
schema, and governance rule untouched. This is an identity-core infrastructure correction, not a
registration redesign.

**Nothing in this release has been committed, pushed, or deployed.**

## 1. Schema (additive only)

New table in `src/identity/schema.sql` (the shared identity-core schema, ensured by
`ensureIdentitySchema()` — not a registration-specific table):

```sql
CREATE TABLE IF NOT EXISTS identity_claim_provenance (
    identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
    claim_name TEXT NOT NULL,
    source TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (identity_subject_id, claim_name)
);
```

Kept deliberately minimal per the spec: no `verified_at`, `source_subject`, or `metadata JSONB` —
none of those were needed to close the blocker, and adding them now would have built a generalized
evidence system the spec explicitly said not to build. `identity_subject_id` is the **immutable**
internal `identity_subjects.id`, never `oidcSubject` or a mutable provider subject.

No existing table (`identity_subjects`, `oidc_subject`, `primary_provider`,
`primary_provider_subject`, `user_authenticators`, `identity_account_links`, `tenants`,
`applications`, `oidc_clients`, `verification_challenges`) was altered or dropped.

## 2. Durable store abstraction

`src/identity/IdentityClaimSourceStore.ts` is now an interface (`getClaimSources`,
`getClaimUpdatedAt`, `recordClaimSource`, all async, all keyed by `identitySubjectId`), with two
implementations:

- `src/identity/InMemoryIdentityClaimSourceStore.ts` — same two-`Map` logic as before, for
  deterministic unit tests and the in-memory driver (`IDENTITY_REGISTRY_DRIVER=memory`).
- `src/identity/PostgresIdentityClaimSourceStore.ts` — production implementation. Constructor
  accepts an **optional** `client?: PostgresClient` override (same convention as
  `PostgresIdentitySubjectRepository`): when omitted it uses the shared `getPostgresPool()`
  singleton; when supplied with a transaction-scoped `pg.PoolClient`, every read/write goes through
  that same open transaction.

`IdentityClaimResolver` now takes an injected store (`defaultClaimSourceStore()` selects
in-memory vs. Postgres the same way `IdentityRegistry`/`AuthenticatorLoginResolver` already do, via
`configuration.getIdentityRegistryDriver()`), awaits its calls, and looks the subject up first so it
can key the store by the immutable `subject.id` instead of `oidcSubject`. Its public
`resolve(oidcSubject, source, suggested)` signature, and its delegation to the untouched
`IdentityClaimPolicy.evaluateClaim()` governance logic, are unchanged. Both existing callers
(`IdentityMergeService`, and `IdentityAccountLinkService` — the C5.1 `BOOKWRM` path) use the shared
singleton and required **zero code changes**.

## 3. Atomic H3 integration (critical requirement)

`PostgresRegistrationRepository.complete()` previously called the old free-function
`recordClaimSource(subject.oidcSubject, ...)` for `email`/`emailVerified` on creation — a plain
in-process call that did **not** participate in the surrounding `BEGIN`/`COMMIT`/`ROLLBACK` boundary
that already covered the challenge lock, conflict check, `resolveOrCreate`, registration-evidence
insert, and challenge consumption. That gap is now closed:

```ts
const claimSources = new PostgresIdentityClaimSourceStore(client as unknown as PostgresClient);
await claimSources.recordClaimSource(subject.id, "email", "HAPI_EMAIL", verifiedAt);
await claimSources.recordClaimSource(subject.id, "emailVerified", "HAPI_EMAIL", verifiedAt);
```

`client` here is the **same** `pg.PoolClient` already used for every other statement in the
transaction — no second connection, no second transaction. Verified directly:

- Happy path (`tests/Registration.postgres.test.ts`): after a successful registration,
  `identity_claim_provenance` has exactly the two expected rows, and a **brand-new**
  `PostgresIdentityClaimSourceStore` instance (simulated restart) reads them back identically.
- Rollback path (`tests/Registration.postgres.test.ts`, Case C conflict test): when registration is
  rejected with `ACCOUNT_CONFLICT` and rolled back, no `HAPI_EMAIL` provenance row exists for the
  pre-existing conflicting subject.

`InMemoryRegistrationRepository` received the equivalent update using
`InMemoryIdentityClaimSourceStore`, keyed by `subject.id`, for parity in unit tests.

## 4. Historical provenance policy (no fabrication)

Existing subjects created before this release have no row in `identity_claim_provenance`.
`getClaimSources()`/`getClaimUpdatedAt()` return `{}` (all fields `undefined`) for them — the store
never infers or backfills a source. This is verified explicitly
(`tests/IdentityClaimProvenance.postgres.test.ts`, "reports genuinely unrecorded historical
provenance as undefined, never fabricated"). `IdentityClaimPolicy.evaluateClaim()` already treats
`currentSource === undefined` as "no current value recorded" and accepts the first future proposer
— this is pre-existing, correct, unchanged behavior, not something H3P needed to fix.

## 5. C5.1 / BOOKWRM path

`IdentityAccountLinkService.ts` calls `identityClaimResolver.resolve(subject.oidcSubject, "BOOKWRM",
...)` and required no code change. Because the resolver now durably persists through
`PostgresIdentityClaimSourceStore`, any **future** C5.1 claim update automatically becomes durable.
No historical `BOOKWRM` provenance was fabricated for existing records. Verified directly with a
dedicated test writing/reading a `BOOKWRM` source through a fresh store instance.

## 6. Update / concurrency semantics

`recordClaimSource()` is an `INSERT ... ON CONFLICT (identity_subject_id, claim_name) DO UPDATE SET
source = $3, updated_at = $4` — the latest authorized write always wins, `updated_at` always
reflects it, and concurrent writers are serialized by PostgreSQL itself (verified with 10 concurrent
writes resolving to one deterministic row). No process-local locking/race protection is used.

## 7. Tests

**Focused (in-memory, always run), 283 total project tests pass; H3P didn't change that count in
the in-memory run (`InMemoryIdentityClaimSourceStore` is a drop-in behavioral match for the old
Maps) but added 9 new Postgres-gated tests (skipped without `DATABASE_URL`).**

`tests/IdentityClaimProvenance.postgres.test.ts` — **9 tests**, gated by `DATABASE_URL`:
1. Write/read roundtrip.
2. Restart persistence (fresh store instance, same DB).
3. Multi-instance read (two independent store instances, same DB).
4. Same-source idempotency (recording the same claim/source twice is a no-op).
5. Authorized later source overwrites source and `updatedAt`.
6. 10 concurrent writes to the same claim resolve deterministically to one row.
7. Unrecorded historical provenance reports as `undefined`, never fabricated.
8. BOOKWRM (C5.1) provenance persists durably across a fresh store instance.
9. Recording provenance never mutates the `IdentitySubject` row itself.

`tests/Registration.postgres.test.ts` — extended two existing tests in place (same 9 test count):
happy path now also asserts the two `identity_claim_provenance` rows exist and are readable from a
brand-new store instance; the Case C conflict test now also asserts no `HAPI_EMAIL` provenance row
was left behind after rollback.

`tests/RegistrationArchitectureIsolation.test.ts` re-verified passing (registration repository files
were edited; zero Base44/Bookwrm/PrivateID dependencies introduced).

## 8. Full regression

- `npm run build` — **PASS**.
- `npx vitest run` (in-memory) — **250 passed, 24 skipped (274 total pre-existing) + 9 new Postgres
  tests reported skipped = 283 total, 250 run**. No regressions.
- `npx vitest run` with `DATABASE_URL`/`HAPI_EMAIL_TEST_DATABASE_URL` → `hapi_h2_test` and
  `HAPI_REGISTRATION_TEST_DATABASE_URL` → `hapi_h3_test` (fresh, isolated local databases) —
  **283/283 individual test assertions passed** across 51 test files.
- The previously-documented H1 shared-DB teardown race (`TenantApplicationFoundation.postgres.test.ts`'s
  `afterAll` occasionally failing to delete a Bookwrm `applications` row still referenced by a
  leftover `identity_subjects` row from a different suite sharing `hapi_h2_test`) was reproduced
  **independently, with H3/H3P files fully excluded from the run** — confirming it is not an H3P
  regression. It is a test-isolation artifact of multiple suites sharing one database, not a
  provenance defect.

## 9. Migration safety

The only schema change is the new, additive `identity_claim_provenance` table. No column was added,
altered, or dropped on `identity_subjects`, `oidc_subject`, `primary_provider`,
`primary_provider_subject`, `user_authenticators`, `identity_account_links`, `tenants`,
`applications`, `oidc_clients`, or `verification_challenges`. No existing identity row is rewritten
merely by deploying H3P — confirmed with a dedicated regression test that writes provenance for a
freshly created subject and reloads the same subject afterward, asserting every structural field
(`id`, `oidcSubject`, `primaryProvider`, `primaryProviderSubject`, `displayName`) is unchanged.

## 10. Remaining blockers

None identified. H3's one outstanding production blocker (process-local claim provenance) is
resolved.
