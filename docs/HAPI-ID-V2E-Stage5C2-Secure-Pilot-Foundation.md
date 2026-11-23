# HAPI ID Stage 5C.2 Secure Production Pilot Foundation

Status: prepared for operator review. No production database, identity, OAuth client, secret, callback or Railway setting was changed.

## Client-secret security

New confidential OIDC clients are stored with `scrypt$...` salted hashes using scrypt N=16384, r=8, p=1 and 32-byte derived keys. Verification uses Node timing-safe byte comparison. Existing plaintext credentials remain accepted unchanged and are not rewritten during normal seeding. A new or explicitly changed valid secret is hashed when inserted or updated. Missing, malformed and wrong secrets fail closed.

No raw secret is logged or returned by the repository contract. A separate hash migration is unnecessary: the existing `client_secret TEXT NOT NULL` column is additive-compatible, and the code recognizes both hashed and legacy plaintext values.

## Operator-controlled provisioning

Use:

```sh
node scripts/provision-production-pilot.mjs \
  --application-id <explicitly-approved-UUID> \
  --redirect-uri <exact-approved-HTTPS-callback>
```

This defaults to a plan-only output and makes no database changes. Execution requires `--execute`, `DATABASE_URL`, `HAPI_PILOT_PROVISIONING_ACKNOWLEDGED=true`, `HAPI_PILOT_PROVISIONING_TARGET=https://id.hapiinc.com`, `OIDC_ISSUER=https://id.hapiinc.com`, an exact approved `HAPI_PILOT_PROVISIONING_DATABASE_HOST`, and TLS (`sslmode=require` or `sslmode=verify-full`). Existing configuration is compared; mismatches or a different application are refused rather than mutated. A newly created secret is printed once to operator output and is not written to source control.

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
