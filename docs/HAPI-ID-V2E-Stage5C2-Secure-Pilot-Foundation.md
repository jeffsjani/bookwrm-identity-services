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

This defaults to a plan-only output and makes no database changes. Execution requires `--execute`, `DATABASE_URL`, `HAPI_PILOT_PROVISIONING_ACKNOWLEDGED=true`, `HAPI_PILOT_ALLOWLIST_CONFIRMED=true`, `HAPI_PILOT_PROVISIONING_TARGET=https://id.hapiinc.com`, `OIDC_ISSUER=https://id.hapiinc.com`, an exact approved `HAPI_PILOT_PROVISIONING_DATABASE_HOST`, and TLS (`sslmode=require` or `sslmode=verify-full`). The operator must first generate 48 cryptographically random bytes, encode them as 64 base64url characters, and store the value in an approved secret manager. In a separate approved session, stream the stored value to provisioning on standard input without echoing, logging, command arguments, or environment variables. The script does not generate or print the secret. An operator must securely configure the same vault value in the already deployed certification client separately; no secret-manager integration is provided here. Confirm the allowlist and secure handoff before activation.

Existing configuration and the provided credential are compared; mismatches are refused rather than mutated. The confirmation flag is an operator attestation, not a check of deployed settings. If the connection fails around commit, securely inspect the database before retrying with the same vault value; never rotate or regenerate it blindly.

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

The implementation is [src/certification/PrivateOIDCCertificationClient.ts](../src/certification/PrivateOIDCCertificationClient.ts), with a standalone entrypoint in [src/certification/server.ts](../src/certification/server.ts). It is independent of Bookwrm, Elite+, and Base44. It uses HTTP Basic operator access, a short-lived HttpOnly Secure session cookie, authorization code plus PKCE S256, random state and nonce, production JWKS signature validation, exact issuer `https://id.hapiinc.com`, exact pilot audience/client ID, expiration validation, and UserInfo `sub` equality.

It reports exactly four PASS/FAIL results and stores neither tokens nor private identity data. No staging-only route or staging console is mounted.

The simplest hosting arrangement is a separate lightweight Railway service or approved private HTTPS service. This task creates no hosting resource and does not register a hostname.

Proposed callback for operator approval: `https://certification.hapiinc.com/oidc-certification/callback`. This hostname is not active and must not be registered until explicitly approved. It can be replaced only after approval; it must be exact in the pilot client and in `HAPI_CERTIFICATION_REDIRECT_URI`.

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
