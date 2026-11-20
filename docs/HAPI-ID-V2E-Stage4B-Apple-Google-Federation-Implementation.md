# HAPI ID V2-E Stage 4B — Apple and Google Universal Login Federation

**Status: EXISTING FEDERATION IMPLEMENTATION VERIFIED AND MINIMAL GAPS CLOSED; LIVE PROVIDER ACTIVATION NOT APPROVED.**

Date: 2026-11-20

Development branch: `feature/hapi-id-v2e-stage1`

Staging issuer: `https://id-staging.hapiinc.com`

Production issuer: `https://identity.bookwrm.com`

No provider credentials were added, no provider flags were enabled, no callback was registered externally,
no live provider request was sent and no staging or production deployment occurred.

## 1. Existing Apple functionality

The repository already contains:

- Apple authorization and token endpoints
- Apple ES256 client-secret JWT generation
- Server-side Apple identity-token signature verification
- Exact Apple issuer verification
- Registered Services ID audience verification
- Required nonce and subject validation
- Expiration validation
- Apple callback support with `response_mode=form_post`
- Apple private-relay metadata handling
- Stable external-identity binding by exact issuer and subject
- Explicit first-time registration choice
- Existing-account linking only through the authenticated account-linking API

Minimal gap closed in this build:

- `private.icloud.com` is now recognized alongside `privaterelay.appleid.com` as an Apple private relay address.
  Relay addresses remain contact hints and never participate in account matching.

Existing Apple implementation remains untested against a live Apple developer tenant.

## 2. Existing Google functionality

The repository already contains:

- Google authorization and token endpoints
- Server-side authorization-code exchange
- Google JWKS signature verification with RS256 only
- Exact Google issuer validation, including canonicalization of Google's legacy issuer
- Registered OAuth client audience validation
- Required nonce and subject validation
- Expiration validation
- `email_verified` handling as display metadata only
- Google callback support with GET query parameters
- Stable external-identity binding by exact issuer and subject
- Explicit first-time registration choice
- Existing-account linking only through the authenticated account-linking API

No Google engine rebuild is required.

Existing Google implementation remains untested against a live Google Cloud OAuth client.

## 3. Shared federation lifecycle already implemented

Both providers reuse:

- The existing Universal Login authorization interaction
- Server-generated, short-lived, single-use provider state and nonce
- Provider callback state replay protection
- Exact server-configured provider redirect URI
- Server-side provider code exchange
- Server-side identity-token verification
- HAPI Identity Registry subject resolution
- External identity records keyed by provider, issuer and subject
- Provider-link conflict and inactive-subject rejection
- Explicit account-choice handling for unknown provider identities
- Existing HAPI Email OTP as a separate provider path
- Revocation/link checks before authorization-code redemption

Unknown provider identities do not automatically resolve or merge with an existing email subject.
The implementation presents an explicit create-versus-email choice; authenticated account linking is
handled by the separate account-linking API.

## 4. Universal Login UI

The existing chooser already renders provider buttons only when:

- The provider feature flag is enabled
- The provider integration is fully configured
- The application allows `EXTERNAL_OIDC`

Continue with Email remains unchanged. Apple uses the existing form_post callback and Google uses
its GET callback. The UI does not expose provider state, nonce, code or token values.

## 5. Staging console support

The staging console guard was narrowed to permit Google or Apple independently with email and
Universal Login. Refresh grants and persistent sessions remain prohibited in console mode.

The existing console can continue to serve as the OIDC result validator after the normal
Universal Login flow returns to the console callback. Provider-specific live acceptance still requires
using the existing provider buttons or an approved provider test account; the console does not expose
tokens or provider secrets.

## 6. Exact callback URLs

These callback URLs come from the implemented routes and configuration fields:

| Provider | Implemented callback route |
| --- | --- |
| Google | `https://id-staging.hapiinc.com/federation/google/callback` |
| Apple | `https://id-staging.hapiinc.com/federation/apple/callback` |

Production callback URLs must remain separately defined and are not prepared or registered here.

## 7. Google Cloud setup, after separate activation approval

Create or reuse a Web OAuth client in Google Cloud Console:

- Application type: Web application
- Authorized JavaScript origins: staging issuer origin only, `https://id-staging.hapiinc.com`
- Authorized redirect URI: `https://id-staging.hapiinc.com/federation/google/callback`
- Scopes: `openid`, `email`, `profile`
- OAuth consent: staging test application and controlled test account
- Client secret: server variable only; never GitHub, browser JavaScript or logs

Required Railway staging variables:

```text
HAPI_GOOGLE_FEDERATION_ENABLED=true
GOOGLE_CLIENT_ID=<approved staging OAuth web client id>
GOOGLE_CLIENT_SECRET=<approved staging OAuth web client secret>
GOOGLE_REDIRECT_URI=https://id-staging.hapiinc.com/federation/google/callback
```

Keep the provider flag false until the staging activation approval is complete.

## 8. Apple Developer setup, after separate activation approval

Use a separate staging Services ID:

- Enable Sign in with Apple
- Register domain: `id-staging.hapiinc.com`
- Register return URL: `https://id-staging.hapiinc.com/federation/apple/callback`
- Associate the staging Services ID with the approved Apple primary App ID or service configuration
- Create a private ES256 Sign in with Apple key
- Record Team ID, Key ID and Services ID
- Store only the private key PEM in Railway server variables

Required Railway staging variables:

```text
HAPI_APPLE_FEDERATION_ENABLED=true
APPLE_SERVICES_ID=<approved staging Services ID>
APPLE_TEAM_ID=<approved Apple Team ID>
APPLE_KEY_ID=<approved Apple private-key key ID>
APPLE_CLIENT_SECRET_KEY=<approved Apple ES256 private key PEM>
APPLE_REDIRECT_URI=https://id-staging.hapiinc.com/federation/apple/callback
```

Never commit or log the Apple private key. Keep the provider flag false until activation approval.

## 9. Focused build and test results

Changes made:

- Added `private.icloud.com` recognition to Apple private-relay detection
- Allowed the staging console guard to coexist with independently enabled Apple/Google flags
- Kept refresh and persistent-session flags prohibited in staging-console mode

Validation:

- Build: `npm run build` passed
- Apple/Google/verifier/federation/account-linking suites: 94 tests passed
- Universal Login/staging-console/provider coexistence regression: 93 tests passed
- A later combined focused run covering verifier, authorization, Universal Login and linking suites:
  94 tests passed

Local synthetic certificates prove issuer, audience, nonce, replay, repeat subject, cross-provider
conflict and no unauthorized email merge behavior. They do not prove live Google or Apple tenant setup.

## 10. Minimal browser staging sequence

Google first:

1. Enable only Google in staging with the approved staging OAuth client.
2. Open `/staging-console/` and start the existing HAPI OIDC test.
3. Choose Continue with Google from the Universal Login chooser.
4. Complete the approved Google test account sign-in.
5. Verify callback, state and nonce, HAPI subject issuance, ID-token claims and UserInfo.
6. Repeat login with the same Google subject and verify the same HAPI subject.
7. Verify cancellation and replay behavior are rejectable and do not create an identity.

Apple second:

1. Enable only Apple after Google acceptance.
2. Repeat the staged console sequence using Apple Services Sign-In.
3. Test a normal address and a private relay address.
4. Verify repeat Apple login returns the same HAPI subject.
5. Verify no email-based merge occurs and explicit linking is required for an existing account.

## 11. GO/NO-GO

### Google

**CONDITIONAL GO for implementation and staging setup.**

**NO-GO for live Google activation** until the Google Cloud web client, exact redirect URI and Railway
staging variables are separately approved.

### Apple

**CONDITIONAL GO for implementation and staging setup.**

**NO-GO for live Apple activation** until Services ID, domain/return URL, Team ID, Key ID and private
signing key are separately approved and stored only in Railway.

### Production-facing Universal Login

**NO-GO.** Production callback registration, production variables and production Bookwrm behavior
remain out of scope.
