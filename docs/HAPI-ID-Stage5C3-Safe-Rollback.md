# HAPI ID Stage 5C.3 Safe Rollback

This local rollback artifact is based on the production baseline. It preserves the HAPI production backfill guard and verifies both scrypt-backed client secrets and existing plaintext client secrets. It does not include the pilot Email OTP or Universal Login implementation.

## Blocking pilot OAuth clients

Set `HAPI_OIDC_BLOCKED_CLIENT_IDS` to a comma-separated list of exact client IDs, for example `hapi-pilot-certification`, before starting this build. Blocked clients are omitted from provider configuration, rejected by request-time OIDC and H1 client resolvers (including registration), and denied at `/userinfo` even when presenting an access token issued before the block was set. The default is empty, preserving existing clients. This is independent of database client status and Email OTP settings.

The validated upgrade candidate does not implement this setting. During a candidate-to-rollback deployment, first use an independently verified ingress/maintenance rule to deny OIDC traffic while the new build starts. Keep that gate in place until the rollback build is confirmed live with the client ID blocked. Then verify `/health/ready` and that an authorization request for the blocked client returns `invalid_client`. Do not rely on `status='suspended'`.

If an ingress or maintenance gate cannot be verified, do not switch versions while the service is publicly reachable. This repository does not establish that Railway currently provides such a control; that operational check remains a release blocker.

## Data-preserving recovery

1. Keep `HAPI_EMAIL_AUTHENTICATION_ENABLED` and `HAPI_UNIVERSAL_LOGIN_ENABLED` false, and keep pilot authentication configuration disabled.
2. Before switching versions, take and verify an operator-approved backup. Keep the externally verified OIDC traffic gate active throughout the rollout.
3. Start only this rollback build with the approved pilot client ID in `HAPI_OIDC_BLOCKED_CLIENT_IDS`. Do not delete pilot records, modify secrets, drop tables, or restore the whole database.
4. Verify the deployed artifact, production issuer, `/health/ready`, the blocked-client authorization response, and the unchanged schema version. Keep the client blocked until a separately approved release explicitly re-enables it.
5. If any unscoped identity or missing legacy application-account link exists, do not use the unguarded baseline. This rollback build skips both production backfills and makes no schema or migration changes.

The scrypt verifier reserves the `scrypt$` prefix for the supported stored-hash format. Ordinary legacy plaintext secrets continue to compare in constant time. A legacy plaintext secret beginning with that reserved prefix is ambiguous and must be rotated through an approved process rather than treated as a literal.
