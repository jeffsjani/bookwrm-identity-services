# HAPI ID staging test console

Status: prepared only. Deployment, callback registration, email activation and real OTP delivery
require separate approval. This console is not a production feature.

The backend hosts `/staging-console/` and uses the existing Universal Login and email
registration/authentication pages. The console keeps the client secret, PKCE verifier, state and
nonce on the server. It validates the token using the local staging JWKS and calls the local
UserInfo handler. It does not call the production issuer. The browser only sees pass/fail results,
not tokens. The normal OAuth redirect briefly carries a one-time authorization code in the browser
URL; it is exchanged server-side and redirected to a clean results URL.

## Required checks before activation

- Confirm the staging service, staging PostgreSQL and staging Redis are isolated from Bookwrm
  production. The issuer must be exactly `https://id-staging.hapiinc.com`, with its existing
  single-issuer allowlist. Do not copy production credentials or data into staging.
- Confirm `jeff@hapiinc.com` is a controlled mailbox and approved for a staging identity. A first
  login creates a staging identity; subsequent logins use it. Enabling Universal Login and email
  also makes their normal staging routes available, not only the console.
- Confirm the staging Resend key, verified sender and verification secret exist and are dedicated
  to staging. Confirm `STAGING_WEB_CLIENT_SECRET` matches the database's `staging-web` secret.
  Do not paste any secret or OTP into chat.
- Railway terminates public HTTPS at the edge. The app does not trust `X-Forwarded-*` headers and
  validates the actual `Host` header against `id-staging.hapiinc.com`; TCP peer addresses are used
  only to scope a request-rate limit, never to grant console access. A caller that can reach the
  app over Railway's private network still must supply the independent HTTP Basic operator
  credential on every console endpoint. OAuth callback
  processing additionally requires the short-lived Secure, HttpOnly session cookie, server-side
  flow state, matching state, and an unused callback; PKCE, nonce, token signature/claims and
  UserInfo are verified server-side. Thus private-network reachability alone does not grant console
  access or bypass the OAuth flow. Public browser access relies on Railway's HTTPS edge.
- Application incoming-request logs contain paths only, not query strings; the console does not
  log OTPs, codes, verifiers, secrets or tokens. Railway edge HTTP query-string logging remains
  unverified and is outside application control; see [Railway logs](https://docs.railway.com/observability/logs).
  The operator accepts this limited residual risk for the isolated staging console, with S256
  and application-log redaction enforced. Ensure other proxies and collectors do not record
  authorization headers, request bodies or redirect `Location` headers.

## Dashboard-only staging configuration after approval

1. Deploy the reviewed revision to the **existing staging backend only**, with
   `STAGING_TEST_CONSOLE_ENABLED` and `STAGING_TEST_CONSOLE_REGISTER_CALLBACK` absent or `false`.
   Do not deploy it to Bookwrm production as part of this test.
2. Register the callback by temporarily setting `STAGING_TEST_CONSOLE_REGISTER_CALLBACK=true`
   on the staging backend and applying the variable change. The guarded boot transaction appends
   `https://id-staging.hapiinc.com/staging-console/callback` to the `staging-web` redirect URIs,
   retaining `https://staging-app.hapiinc.com/callback`. It checks the staging issuer, PostgreSQL,
   staging tenant/application, the two client profiles, and existing redirect set; it refuses
   unexpected data. Confirm the secret-free `Staging console callback registration` log reports
   `registered` or `unchanged`, then remove the registration flag and apply that change.
   The callback remains registered but inert while the console is off. A guard failure stops
   startup; investigate before proceeding.
3. Configure these variables on the staging backend only, using Railway Variables:

   | Variable | Required value |
   | --- | --- |
   | `STAGING_TEST_CONSOLE_USERNAME` | Dedicated operator username, without a colon |
   | `STAGING_TEST_CONSOLE_PASSWORD` | Independently generated high-entropy secret, at least 32 characters; never a client, service or signing key |
   | `STAGING_WEB_CLIENT_SECRET` | Existing matching staging OAuth client secret, server-side only |
   | `OIDC_ISSUER`, `OIDC_ALLOWED_ISSUERS` | Both exactly `https://id-staging.hapiinc.com` |
   | `CORS_TRUSTED_ORIGINS` | Explicit staging-only browser origin allowlist |
   | `DATABASE_URL`, `REDIS_URL` | Dedicated staging PostgreSQL and Redis URLs |
   | `IDENTITY_REGISTRY_DRIVER` | `postgres` (or absent outside test mode) |
   | `REDIS_ENABLED`, `OIDC_ENABLED` | `true` |
   | `JWT_PRIVATE_KEY` or `OIDC_JWKS_JSON` | Existing staging-only RSA private signing key or private JWKS ring |
   | `NODE_ENV` | `production` |
   | `PRIVATEID_REDIRECT_URL`, `PRIVATEID_CALLBACK_URL` | Required by production-mode boot validation, even when PrivateID is inactive: `https://id-staging.hapiinc.com/privateid/callback`, `https://id-staging.hapiinc.com/privateid/webhook` respectively |
   | `HAPI_EMAIL_PROVIDER` | `resend` |
   | `HAPI_EMAIL_AUTHENTICATION_ENABLED` | `true` |
   | `HAPI_UNIVERSAL_LOGIN_ENABLED` | `true` |
   | `RESEND_API_KEY`, `HAPI_EMAIL_FROM`, `HAPI_EMAIL_VERIFICATION_SECRET` | Existing staging-only email settings |
   | `STAGING_TEST_CONSOLE_ENABLED` | `true`, only when ready to run the approved test |

   Keep `HAPI_APPLE_FEDERATION_ENABLED`, `HAPI_GOOGLE_FEDERATION_ENABLED`,
   `HAPI_REFRESH_GRANT_ENABLED`, and `HAPI_PERSISTENT_SESSIONS_ENABLED` absent or `false`.
   The console refuses to start with those features enabled or without email and Universal Login.
   Do not enable the one-time client-secret rotation flag for this procedure.
4. After the separately approved activation, visit
   `https://id-staging.hapiinc.com/staging-console/`. Enter the dedicated operator credential in
   the browser's native prompt. Start the test, choose email, enter `jeff@hapiinc.com`, and enter
   the email OTP in the existing HAPI screen. The final page reports each check as PASS or FAIL.
   The positive exchange proves a verifier was used; a wrong-verifier rejection is covered by
   automated tests, not by an additional live OTP.
5. To return to the pre-test posture, disable the console, disable staging email authentication and
   Universal Login, and remove only email configuration added for the test. Apply the change to
   the same staging backend. Do not remove the callback registration or identity without a
   separate cleanup decision. Leave production unchanged.

The dedicated HTTP Basic password is sent by the browser to the staging origin over HTTPS, never
embedded in page JavaScript. Protect the workstation and rotate that password if exposed. The
console is not a replacement for an identity-aware access gateway or a general admin interface.
The host-only, HttpOnly, Secure console cookie and its pending state, nonce and PKCE verifier expire
after 10 minutes; results expire 10 minutes after the callback. Failed or expired flows must restart.
