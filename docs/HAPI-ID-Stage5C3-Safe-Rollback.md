# HAPI ID Stage 5C.3 Safe Rollback

This local rollback artifact is based on the production baseline. It preserves the HAPI production backfill guard and verifies both scrypt-backed client secrets and existing plaintext client secrets. It does not include the pilot Email OTP or Universal Login implementation.

## Blocking pilot OAuth clients

Set `HAPI_OIDC_BLOCKED_CLIENT_IDS` to a comma-separated list of exact client IDs, for example `hapi-pilot-certification`, before starting this build. Blocked clients are omitted from provider configuration, rejected by request-time OIDC and H1 client resolvers (including registration), and denied at `/userinfo` even when presenting an access token issued before the block was set. The default is empty, preserving existing clients. This is independent of database client status and Email OTP settings.

Stage 5C.3 certification confirms both candidate builds now enforce `oidc_clients.status='suspended'` on each request to `/authorize`, `/token` (authorization-code and enabled refresh grants), and `/userinfo`, including tokens issued before suspension. H1 authority and registration paths also reject the suspended client. The status is loaded from PostgreSQL for each request; no restart is required. Synthetic disposable-PostgreSQL tests confirmed readiness remains HTTP 200 and another active client continues to work.

The exact live production baseline `4cea087d6c887865b322786e588c1ff1752a9314` checks status for authorization and token operations but does not re-check it at `/userinfo`. Until an updated candidate is serving, previously issued access tokens can therefore still reach UserInfo after suspension. Suspension alone is not sufficient across that live-version cutover. The upgrade candidate does not implement `HAPI_OIDC_BLOCKED_CLIENT_IDS`; the safe rollback candidate does.

Before switching from the live baseline, keep Email OTP and Universal Login disabled, suspend the pilot row if it exists, and use an independently verified ingress/maintenance control to deny OIDC traffic throughout the switch. Keep that control in place until the selected candidate is confirmed live, `/health/ready` is HTTP 200, and synthetic checks confirm `/authorize`, `/token`, and `/userinfo` reject the suspended client while an unrelated active client works. Then retain the startup block-list on the rollback candidate as defense in depth. Railway has no service-native path-specific deny; if the separate traffic gate cannot be verified, do not switch while the service is publicly reachable.

## Data-preserving recovery

1. Keep `HAPI_EMAIL_AUTHENTICATION_ENABLED` and `HAPI_UNIVERSAL_LOGIN_ENABLED` false, and keep pilot authentication configuration disabled. If a pilot row exists, set its status to `suspended` before switching builds; do not provision one for rollback testing.
2. Before switching versions, take and verify an operator-approved backup. Keep the externally verified OIDC traffic gate active throughout the rollout.
3. Start only this rollback build with the approved pilot client ID in `HAPI_OIDC_BLOCKED_CLIENT_IDS`. Do not delete pilot records, modify secrets, drop tables, or restore the whole database.
4. Verify the deployed artifact, production issuer, `/health/ready`, rejection of the suspended/blocked client at all three OAuth paths, and an unrelated active client's operation. Keep the client suspended and blocked until a separately approved release explicitly re-enables it.
5. If any unscoped identity or missing legacy application-account link exists, do not use the unguarded baseline. This rollback build skips both production backfills and makes no schema or migration changes.

The scrypt verifier reserves the `scrypt$` prefix for the supported stored-hash format. Ordinary legacy plaintext secrets continue to compare in constant time. A legacy plaintext secret beginning with that reserved prefix is ambiguous and must be rotated through an approved process rather than treated as a literal.
