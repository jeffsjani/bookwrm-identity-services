# Identity Platform Operations Manual

Bookwrm Identity Services (Railway) — Identity Registry, OIDC Provider, PrivateID integration.

## 1. Deployment

- Runtime: Node.js, TypeScript compiled via `tsc` (`npm run build` → `dist/`). Start with `npm start` (`node dist/server.js`) or `npm run dev` (tsx watch) locally.
- Required environment variables (see `src/config/ConfigurationService.ts` for full validation):
  - `DATABASE_URL` — PostgreSQL connection string for the Identity Registry system of record.
  - `IDENTITY_REGISTRY_DRIVER` — `postgres` in every real environment. Only set to `memory` for local/CI tests without a database.
  - `REDIS_URL` (or `REDIS_HOST`/`REDIS_PORT`) — transient OIDC state only (codes, tokens, correlation, rate limits). Never the identity system of record.
  - `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` (or `OIDC_JWKS_JSON`) — OIDC signing keys.
  - `PRIVATEID_*` — PrivateID API credentials, redirect/callback URLs, webhook shared secret.
  - `BASE44_BASE_URL`, `IDENTITY_API_PATH`, `BOOKWRM_IDENTITY_API_KEY` — legacy Bookwrm-facing routes only (`routes/identity.ts`); not used by the OIDC login path since Phase 3.
- On boot, the process must be able to reach both Postgres and Redis; `GET /health/ready` and `GET /identity/admin/health` gate readiness.
- The `identity_subjects` schema (`src/identity/schema.sql`) is applied idempotently via `ensureIdentitySchema()` on first Postgres repository use — no separate migration step is required for this table today.

## 2. Backup

- The Identity Registry (`identity_subjects` table) is the only durable state that must be backed up. Redis holds nothing durable by design (Task 4/RC1-K).
- Use standard PostgreSQL backup tooling (`pg_dump`/managed provider snapshots) against the `identity_subjects` table and its containing database.
- Recommended cadence: continuous WAL archiving or provider-managed point-in-time recovery, since this table is written on every login.

## 3. Restore

- Restore the PostgreSQL database/table from backup using standard `pg_restore`/provider restore tooling.
- After restore, no application-side reconciliation is required: `oidc_subject` and `(primary_provider, primary_provider_subject)` uniqueness constraints are self-consistent within the restored snapshot.
- Redis does not need to be restored — it will simply start empty (in-flight OIDC authorization codes/sessions at the time of failure are lost, which only forces affected users to re-authenticate; no identity data is at risk).

## 4. Migration

- Schema changes to `identity_subjects` should be applied as additive, backward-compatible `ALTER TABLE` statements executed before deploying code that depends on new columns (expand/contract pattern). There is currently no migration framework in this repository — changes go through `src/identity/schema.sql` plus a manual, reviewed DDL step against the target database.
- Application-level migration (e.g., moving users from a prior identity model) is **not** a bulk operation: per RC1 Task J, identities migrate naturally on first successful login through `IdentityRegistry.resolveOrCreate()`.

## 5. Failover

- **Postgres unavailable**: `IdentityRegistry.resolveOrCreate()`/lookups fail closed (throw); OIDC logins fail with a clean error rather than silently degrading to an inconsistent state. Verified in [Phase5ProductionHardening.test.ts](../tests/Phase5ProductionHardening.test.ts) (Task 5 chaos tests) that partial/corrupted state is never left behind.
- **Redis unavailable**: only affects transient OIDC state (authorization codes, rate limiting, correlation). The Identity Registry itself has no Redis dependency — a full Redis outage does not corrupt or lose any `IdentitySubject` data, only forces in-flight logins to restart.
- **PrivateID unavailable**: no new authentications can start, but already-persisted `IdentitySubject` rows are entirely unaffected (Identity Registry has no runtime dependency on PrivateID after a subject exists).
- Real Postgres cluster restart was verified directly in this sandbox: a subject created before `pg_ctlcluster restart` resolved correctly, unchanged, afterward.

## 6. Recovery (identity, not disaster)

- Implemented in [IdentityRecoveryService.ts](../src/identity/IdentityRecoveryService.ts): when PrivateID issues a new `privateIdUserId` for someone who already has an `IdentitySubject` (e.g. biometric re-enrollment), an administrator calls `POST /identity/admin/subject/:id/recover` with `{ newPrivateIdUserId, adminApproved: true, reason }`.
- This re-points `primary_provider_subject` on the **existing** `oidcSubject` — it never mints a new subject and never happens automatically. Every recovery is audited (`RECOVERY` event in `IdentityAudit`).
- A recovery request targeting a `newPrivateIdUserId` already linked to a different subject is rejected (409) to prevent identity takeover.

## 7. Merge

- Implemented in [IdentityMergeService.ts](../src/identity/IdentityMergeService.ts): `POST /identity/admin/merge` with `{ survivorOidcSubject, loserOidcSubject, reason }`.
- Claims from the loser are reconciled onto the survivor via `IdentityClaimResolver` as an administrative (`MANUAL`) source, so they always take effect per existing claim policy rules. The loser is marked `DISABLED` (never deleted). Both sides get an immutable `MERGE` audit entry.
- **Known limitation**: the schema models one `primaryProvider`/`primaryProviderSubject` per subject, so the loser's authenticator identity is not re-attached to the survivor as a *second* authenticator — that requires a future multi-authenticator table.

## 8. Monitoring

- `GET /identity/admin/health` — Registry, Redis, PostgreSQL, OIDC, JWKS, PrivateID, Correlation store size, PendingIdentity stats, with latency in ms for Registry/Redis/PostgreSQL. Returns `503` if any component is `unhealthy`.
- `GET /metrics` (Prometheus format, shared registry across OIDC and Identity metrics) — see [IdentityMetrics.ts](../src/identity/infrastructure/IdentityMetrics.ts) for the full counter list: `identity_new_identities_total`, `identity_returning_logins_total`, `identity_failed_linking_total`, `identity_email_verification_failures_total`, `identity_claim_updates_total{claim,decision}`, `identity_authenticator_adds_total`, `identity_authenticator_failures_total`, `identity_oidc_logins_total`, `identity_oidc_failures_total`.
- `GET /identity/admin/subjects`, `/identity/admin/subject/:id`, `/identity/admin/subject/:id/audit` — read-only inspection for support/on-call use.

## 9. Troubleshooting

| Symptom | Likely cause | Where to look |
|---|---|---|
| Login succeeds but user gets a different `sub` each time | `resolveOrCreate` is creating duplicate rows for the same person | Check `(primary_provider, primary_provider_subject)` uniqueness in `identity_subjects`; verify the same `privateIdUserId` is being sent by PrivateID each time |
| `POST /privateid/webhook` returns `FAILURE` with an identity error | Unverified email from PrivateID (RC1-F) | `PendingIdentity` stage will show `blocked`; check `identity_email_verification_failures_total` metric |
| `GET /identity/admin/subject/:id` returns 404 for a real subject | Malformed `oidcSubject` (must be UUID) | Fixed in Phase 5 — malformed IDs return 404, not 500; confirm the ID being queried is correct |
| `/identity/admin/health` reports `postgresql: not_configured` | `IDENTITY_REGISTRY_DRIVER` is not `postgres` | Check environment configuration; this should never be `memory` outside tests |
| Claim update silently ignored | `IdentityClaimPolicy` rejected a conflicting/duplicate proposal (by design) | Check `identity_claim_updates_total{decision="reject"}` and `GET /identity/admin/subject/:id/audit` for the `reason` |
| High latency under load | Lock contention on a single `(primary_provider, primary_provider_subject)` row during concurrent logins for the same identity | See Phase 5 load test results below; contention is expected and bounded by Postgres row-level locking, not application code |

### Measured load test results (this environment, single local Postgres instance, worst case — all requests targeting the same identity)

| Concurrency | Total duration | Result |
|---|---|---|
| 100 | ~205ms | 1 subject created, no duplicates |
| 500 | ~805ms | 1 subject created, no duplicates |
| 1000 | ~1419ms | 1 subject created, no duplicates |

These numbers are from a single-node local Postgres instance in this sandbox, not a production-sized deployment — re-run [Phase5ProductionHardening.test.ts](../tests/Phase5ProductionHardening.test.ts) against the real target environment before relying on these figures for capacity planning.
