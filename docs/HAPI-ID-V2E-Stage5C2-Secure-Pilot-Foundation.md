# HAPI ID Stage 5C.2 Secure Production Pilot Foundation

Status: prepared for operator review. No production database, identity, OAuth client, secret, callback or Railway setting was changed.

## Client-secret security

Pilot provisioning stores the confidential client secret as a `scrypt$...` salted hash using scrypt N=16384, r=8, p=1 and 32-byte derived keys. Verification uses Node timing-safe byte comparison. Existing plaintext credentials remain accepted unchanged and are not rewritten during normal seeding. Other client creation and rotation paths are not automatically migrated to scrypt. Missing, malformed and wrong secrets fail closed.

The production baseline compares plaintext secrets directly, or compares SHA-256 digests of the supplied and stored plaintext in H1/registration; it does not identify a stored SHA-256 digest as a hash of the credential. Those stored values remain plaintext-compatible. A legacy plaintext secret beginning `scrypt$` is ambiguous and will be interpreted as a hash; inventory and rotate such secrets before release. A separate hash migration is unnecessary: the existing `client_secret TEXT NOT NULL` column is additive-compatible.

The token endpoint now requires the registered authentication method on authorization-code and enabled refresh grants. A Basic request may include a matching body `client_id`, but not a body secret; conflicting IDs, malformed or unsupported Authorization headers, duplicate credentials, and secrets on public clients fail closed. Existing clients using a different method than their registration must be corrected before deployment. Bookwrm's default registration is `client_secret_post`, unless explicitly configured otherwise; actual production registrations and observed request methods require separate operator verification.

The pilot allowlist is inactive when neither pilot setting is present. When configured, it limits only the specified application; other applications retain their prior behavior. Partial production settings fail startup. Before provisioning or enabling the dedicated pilot, the operator must configure both settings for its exact application ID and approved addresses; otherwise the pilot is not restricted.

## Operator-controlled provisioning

Use:

```sh
node scripts/provision-production-pilot.mjs \
  --application-id <explicitly-approved-UUID> \
  --redirect-uri <exact-approved-HTTPS-callback>
```

This defaults to a plan-only output and makes no database changes. Execution requires `--execute`, `DATABASE_URL`, `HAPI_PILOT_PROVISIONING_ACKNOWLEDGED=true`, `HAPI_PILOT_ALLOWLIST_CONFIRMED=true`, `HAPI_PILOT_PROVISIONING_TARGET=https://id.hapiinc.com`, `OIDC_ISSUER=https://id.hapiinc.com`, approved `HAPI_PILOT_PROVISIONING_DATABASE_HOST`, `HAPI_PILOT_PROVISIONING_DATABASE_PORT`, `HAPI_PILOT_PROVISIONING_DATABASE_NAME` and `HAPI_PILOT_PROVISIONING_DATABASE_SCHEMA`, and TLS (`sslmode=require` or `sslmode=verify-full`). URL host, explicit port and database must match the approved values; the connected database and current schema are checked before mutation. URL parameters that could override the target, duplicate parameters, and ambient `PGOPTIONS` are refused. Prefer `verify-full` with a trusted CA and independently verify the target: these checks are operator attestations, not proof of database identity.

### Credential handoff (future authorized operation only)

The certification service reads `HAPI_CERTIFICATION_CLIENT_SECRET`; its deployed value and a matching vault version have not been verified here. The script cannot recover the secret from the service or from a database hash. An authorized operator must establish whether the same secret is retained in an approved vault and whether it is exactly 64 base64url characters, without displaying its value. The script accepts only that format on non-interactive stdin, optionally followed by one newline. A secure vault-to-stdin pipe is possible, but no vault integration is supplied or verified here. Before use, the operator must verify the vault tool, shell, process supervisor, database and log settings do not echo, trace, persist, or log the value. Do not pass it in command arguments or an environment variable to the provisioning process. Do not use shell tracing, interactive echo, or saved output.

If the existing secret is retrievable in that format through an approved non-logging channel, retain the certification service's existing configuration and stream the same vault version directly into the script in a separately authorized session. The script hashes it with a fresh salt and writes only the scrypt hash to HAPI's client row; the certification service retains the matching plaintext as a protected service secret. Restrict database and log access, including SQL parameter logging.

If the existing secret is unavailable, has the wrong format, or the handoff cannot be assured non-logging, do not attempt to recover it from the hash. In a separately approved coordinated rotation, generate 48 cryptographically random bytes and store their 64-character base64url encoding as a new version in the approved vault. During a controlled window, stream that version to initial provisioning and securely set the same version as the certification service secret. Keep the pilot inactive until both sides are confirmed. If a client row already exists with a different secret, the script refuses to change it; a separately reviewed rotation mechanism and rollback procedure are required before proceeding.

On failure, keep the pilot disabled. A transaction error should roll back, but a lost connection around commit has an uncertain outcome: an authorized operator must inspect only the relevant non-secret metadata and retry with the same retained vault version, not generate a replacement. A matching existing row is unchanged; a mismatch is refused. If the service-side update fails, restore the previous protected service-secret version or finish the coordinated handoff while the pilot remains disabled. Never recover the plaintext from, or display, the stored hash.

Existing configuration and the provided credential are compared; mismatches are refused rather than mutated. The confirmation flag is an operator attestation, not a check of deployed settings. If the connection fails around commit, securely inspect the database before retrying with the same vault value; never rotate or regenerate it blindly.

The CLI checks the approved target and reads stdin before calling the transaction in
`scripts/pilot-provisioning-transaction.mjs`. The transaction module is an internal
building block, not a safe production entrypoint: it does not perform the CLI's
host, TLS, issuer, acknowledgement or credential-format checks. Do not invoke it
directly for production provisioning. A disposable PostgreSQL test exercises this
same transaction, but does not validate any actual vault, Railway variable, TLS
certificate, database logging policy or production credential.

If provisioning committed but the Console handoff did not, leave authentication
disabled and retain the provisioned vault version. An authorized operator can
either securely set that same version as `HAPI_CERTIFICATION_CLIENT_SECRET` or
restore the prior sealed variable version; the latter does not make a newly
provisioned mismatching client usable. Confirm the matching version through a
separately approved controlled test before activation. If the version is lost,
do not retry with a new secret or edit the database ad hoc: the existing row will
refuse a different credential, and a separately reviewed rotation is required.

The mechanism creates or preserves:

- tenant `hapi-pilot`
- application ID supplied by the operator, slug `hapi-pilot-certification`
- application key `HAPI_PILOT`
- `HAPI_EMAIL` only, no identity providers, no face setup
- client `hapi-pilot-certification`
- authorization-code grant only
- PKCE S256 required
- `client_secret_basic`
- `openid email` only
- no refresh grant

It must not be run against production by this development task.

## Private certification application

The development branch contains `src/certification/PrivateOIDCCertificationClient.ts` and the standalone entrypoint `src/certification/server.ts`; neither belongs in the proposed backend release. The Console is independent of Bookwrm, Elite+, and Base44. It uses HTTP Basic operator access, a short-lived HttpOnly Secure session cookie, authorization code plus PKCE S256, random state and nonce, production JWKS signature validation, exact issuer `https://id.hapiinc.com`, exact pilot audience/client ID, expiration validation, and UserInfo `sub` equality.

It reports exactly four PASS/FAIL results and stores neither tokens nor private identity data. No staging-only route or staging console is mounted.

The simplest hosting arrangement is a separate lightweight Railway service or approved private HTTPS service. This task creates no hosting resource and does not register a hostname.

The previously proposed callback was `https://certification.hapiinc.com/oidc-certification/callback`. The operator must independently approve the exact callback in the pilot client and `HAPI_CERTIFICATION_REDIRECT_URI`; this document does not verify the current hostname or service configuration.

The app may hold short-lived state, nonce, PKCE verifier, CSRF token and one-time code in process memory, but no accounts or application data. It must not expose staging-only routes, Bookwrm migration actions or Elite+ privileges. It is intended for one Railway replica; multiple replicas require shared encrypted session storage or sticky routing, and a restart invalidates in-progress tests.

## Information required from the operator

1. Explicit pilot application UUID.
2. Exact approved HTTPS callback URI and approved hosted hostname.
3. Approval for the dedicated pilot tenant/application/client shape.
4. The production target PostgreSQL confirmation for the separate operator-controlled provisioning session.
5. Operator allowlist identities for private-app access.
6. Authorization to activate Email OTP and Universal Login only through a later controlled deployment procedure.

## Activation blockers

A production pilot client cannot be activated until callback approval, application UUID, hosted operator app, pilot mailbox allowlist, and separate production deployment approval exist. No blocker is bypassed by this implementation.

## Stage 5C.3 review-only backend release proposal

Base: currently reported production commit `4cea087d6c887865b322786e588c1ff1752a9314`.
Source: `feature/hapi-id-v2e-stage1` after the Stage 5C.3 development commit.
This is a file-level proposal, not a created release branch or an applied patch.
Select these changes rather than merging the development branch:

- OAuth and hash compatibility: `src/oidc/OIDCService.ts`,
  `src/security/OIDCClientSecret.ts`, `src/identity/H1ClientAuthority.ts`,
  `src/routes/registration.ts`.
- Pilot allowlist: `src/email/EmailPilotAllowlist.ts`,
  `src/email/EmailVerificationService.ts`,
  `src/adapters/email/EmailVerificationComposition.ts`,
  `src/registration/PostgresRegistrationRepository.ts`,
  `src/registration/RegistrationComposition.ts`.
- Production data guard: `src/adapters/base44/Base44ApplicationSeed.ts`,
  which prevents automatic legacy Bookwrm backfill into HAPI production while
  retaining the baseline behavior for other issuers.
- Provisioning: `scripts/provision-production-pilot.mjs` and
  `scripts/pilot-provisioning-transaction.mjs`. Invoke the former directly with
  Node; the development `package.json` changes are not needed.
- Review evidence: this document; `tests/ProductionPilotProvisioning.test.ts`,
  `tests/ProductionPilotProvisioning.postgres.test.ts`,
  `tests/OIDCClientSecretHash.test.ts`, `tests/OIDCTokenClientAuthentication.test.ts`,
  `tests/OIDCRefreshGrant.test.ts`, `tests/EmailVerification.test.ts`,
  `tests/Registration.http.test.ts`, `tests/Registration.postgres.test.ts`,
  `tests/TenantApplicationFoundation.test.ts`, `tests/HapiProductionStartup.postgres.test.ts`,
  and `tests/FederatedUniversalLogin.test.ts`. Existing unchanged PKCE tests
  should also be run against the assembled release.

Exclude `src/certification/PrivateOIDCCertificationClient.ts`,
`src/certification/server.ts`, `tests/PrivateOIDCCertificationClient.test.ts`,
and the development `package.json` changes. They belong to the separate
Certification Console, not the backend release. No SQL schema, migration or
dependency lockfile differs between the two specified commits; the existing
schema contains the required columns. This is a source comparison, not proof
that a particular live database has every required column.

The registered client's `require_pkce` flag enforces PKCE; S256-only enforcement
is in the existing OAuth server, not a separate database column. Existing
plaintext credentials remain supported, but stricter enforcement of registered
authentication methods is an intentional compatibility change. The reported
zero-client inventory does not rule out environment-configured clients, or
clients registered later; verify those separately without displaying secrets.
Keep `HAPI_EMAIL_AUTHENTICATION_ENABLED` and `HAPI_UNIVERSAL_LOGIN_ENABLED`
disabled throughout release preparation and any separately approved deployment.

### Data-preserving rollback (separate authorization required)

1. Keep or make the pilot unavailable using the approved operational controls;
   do not enable authentication to test a rollback. Preserve the current
   configuration, deployment identity, and a verified backup according to the
   operator's procedures without exposing credentials.
2. Before returning to the baseline, assess the impact of its startup code:
   unlike the proposed guard, it can backfill unassigned identity subjects and
   migrate legacy Bookwrm links on HAPI production. If affected rows exist or
   the impact is unknown, do not restart that baseline; use a separately
   reviewed rollback build that retains the production data guard.
3. Roll back only the backend deployment to the approved known-good artifact
   (or the reviewed guarded rollback build). Restore only compatible prior
   backend configuration; do not alter the Certification Console, drop tables,
   delete pilot records, restore the whole database over newer data, or rotate
   credentials as part of this rollback.
4. Verify backend health and that authentication remains disabled. The baseline
   does not verify scrypt client secrets, so an already provisioned pilot client
   must remain inactive until a compatible backend is restored. Investigate any
   uncertain transaction outcome separately and preserve all production data.

## Stage 5C.3 suspension safety certification

The OAuth pilot and safe rollback candidates enforce persisted client status on
each request to `/authorize`, `/token` (authorization-code and enabled refresh
grants), and `/userinfo`. This includes authorization codes, refresh tokens, and
access tokens issued before the client was suspended. H1 authority and
registration paths also reject suspended clients. Candidate-local tests against
synthetic disposable PostgreSQL verified that a status change takes effect
without a restart, readiness remains HTTP 200, and an unrelated active client
continues to work.

This does not describe the current live baseline
`4cea087d6c887865b322786e588c1ff1752a9314`: its UserInfo handler does not
re-check client status. During a transition from that build, an already-issued
access token can still reach UserInfo after suspension. Keep Email OTP and
Universal Login disabled, suspend an existing pilot row before switching, and
use a separately verified ingress/maintenance gate until the candidate is
healthy and the suspended-client behavior is verified. Railway has no
service-native path-specific deny; if the independent traffic gate cannot be
verified, do not switch while publicly reachable. No production database,
client, secret, configuration, or Railway service was accessed or changed for
this certification.
