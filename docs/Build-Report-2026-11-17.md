# Build Report — 2026-11-17 (Latest Build)

Date: 2026-11-17  
Repository: bookwrm-identity-services  
Branch: main  
Commit: 666dc75 — "docs: P0E Authentication Certification Report — Blocked on Production Upgrade"

## Executive Summary

The latest build of the Bookwrm Identity Services / HAPI ID codebase compiles cleanly and the full automated test suite passes with no failures.

Validation outcomes:

- Build (`npm run build`): pass
- Test suite (`npx vitest run`): pass — 0 failures

## Toolchain

| Tool | Version |
| --- | --- |
| Node.js | v24.22.2 |
| TypeScript (tsc) | 7.0.2 |
| Vitest | 4.1.10 |

## Build

`npm run build` runs `tsc` and copies the five SQL schema files (`identity`, `email`, `registration`, `authentication/email`, `authenticators`) into `dist/`.

- Result: pass, exit code 0, no compiler diagnostics.
- `dist/` output and all schema copies produced successfully.

## Test Suite

Command: `npx vitest run`

| Metric | Result |
| --- | --- |
| Test files | 57 passed, 9 skipped (66 total) |
| Tests | 524 passed, 110 skipped (634 total) |
| Failures | 0 |
| Duration | ~53s |

### Skipped suites

All skipped suites are PostgreSQL integration tests gated with `describe.skipIf(!databaseUrl)` on per-domain environment variables (for example `HAPI_EMAIL_TEST_DATABASE_URL`). No live test database was configured in this environment, so they skipped by design:

- tests/EmailVerification.postgres.test.ts
- tests/EmailAuthentication.postgres.test.ts
- tests/Registration.postgres.test.ts
- tests/IdentityRegistry.postgres.test.ts
- tests/IdentityClaimProvenance.postgres.test.ts
- tests/HapiFaceEnrollment.postgres.test.ts
- tests/SchemaVersioning.postgres.test.ts
- tests/TenantApplicationFoundation.postgres.test.ts
- tests/MultiClientFoundation.postgres.test.ts
- tests/P0SecurityGapAudit.synthetic.test.ts (currently untracked in git)

### Browser-based tests

The H5.4 "real Chromium form/CSP navigation contract" suite in tests/FaceSetupCeremony.test.ts initially failed because the Playwright Chromium headless shell and its OS libraries were not installed in this environment. After running:

```
npx playwright install chromium
sudo npx playwright install-deps chromium
```

the suite passes fully: 98/98 tests in FaceSetupCeremony.test.ts, including the previously environment-skipped browser tests. This was an environment provisioning issue, not a code defect.

## Working Tree State

Untracked files present at build time (not included in commit 666dc75):

- `docs/recovery/`
- `tests/P0SecurityGapAudit.synthetic.test.ts`

## Conclusion

- The codebase at commit 666dc75 builds and validates cleanly.
- All runnable unit and contract tests pass; skips are limited to database-gated integration suites that require a provisioned PostgreSQL test database.
- Environments running the full suite should pre-install Playwright Chromium and its OS dependencies to exercise the H5.4 browser navigation contract tests.
