# HAPI ID V2-D Deliverable — Native iOS/Android Client Certification Design (Phase 5)

Status: **Design + readiness verification only — no production native client is registered or
activated by V2-D.**
Date: 2026-11-19
Scope authority: HAPI ID V2-D approved tranche, Phase 5.

---

## 1. Target clients

| Client | Platform | Type | Grant |
| --- | --- | --- | --- |
| Elite+ iOS | iOS 16+ | **Public** (no secret) | Authorization Code + PKCE S256 |
| Elite+ Android | Android 10+ | **Public** (no secret) | Authorization Code + PKCE S256 |

Both clients authenticate end users exclusively through the HAPI-hosted Universal Login in an
**external system browser context** — never an embedded WebView:

- iOS: `ASWebAuthenticationSession` (ephemeral session **off**, so Apple/Google provider cookies
  and the HAPI `__Host-hapi_sid` session survive across logins).
- Android: Custom Tabs (`androidx.browser`), with Trusted Web Activity explicitly out of scope.

This satisfies RFC 8252 (OAuth 2.0 for Native Apps) §7.3 and is REQUIRED for "Sign in with Apple"
App Store compliance when Apple federation is active.

## 2. Proposed client registrations (NOT created by V2-D)

```
client_id:                      hapi-eliteplus-ios      | hapi-eliteplus-android
token_endpoint_auth_method:     none                    | none
grant_types:                    authorization_code, refresh_token
response_types:                 code
require_pkce:                   true (S256 enforced; plain rejected platform-wide)
scopes:                         openid profile email
redirect_uris (exact-match):
  iOS:      https://id.hapiinc.com/native/ios/callback        (Universal Link, primary)
            com.hapiinc.eliteplus://oauth/callback            (claimed custom scheme, fallback)
  Android:  https://id.hapiinc.com/native/android/callback    (App Link, assetlinks verified)
            com.hapiinc.eliteplus://oauth/callback            (claimed custom scheme, fallback)
```

Redirect-URI rules already enforced by the platform and re-certified in V2-D:

- Exact string match at `/authorize` AND `/token` (no prefix, wildcard, or scheme-only matching).
- The code is bound to the exact `redirect_uri` presented at authorization; a mismatch at
  exchange is `invalid_grant`.

Universal Links / App Links are the primary redirect mechanism because the OS cryptographically
binds them to the app's signing identity (apple-app-site-association / assetlinks.json served
from `id.hapiinc.com`); custom schemes are fallback-only.

## 3. Verified: the existing browser-facing `/authorize` supports the native requirements

Re-certified on this branch (all synthetic, no production clients):

| Requirement | Evidence |
| --- | --- |
| Public client (`token_endpoint_auth_method=none`), zero secret anywhere | `tests/NativePublicClientCertification.test.ts` — "completes the Authorization Code + PKCE S256 flow with token_endpoint_auth_method=none and no secret" (6/6 green, re-run on V2-D) |
| PKCE S256 mandatory for public clients; `plain` rejected | same suite + platform-wide `/authorize` rejection of `code_challenge_method=plain` |
| Authorization-code replay rejected | same suite |
| Cross-client code theft rejected | same suite |
| Exact redirect-URI enforcement at both endpoints | same suite |
| Code expiration (60 s TTL) | same suite |
| Mandatory `nonce` (fail-fast at `/authorize`) | V2-B nonce policy tests (`tests/NonceAndRefreshTokenPolicy.test.ts`) |
| Apple/Google federation reachable from the same `/authorize` interaction | `tests/FederatedUniversalLogin.test.ts` (V2-D) — chooser → provider → callback → RP code, including Apple's cookieless cross-site `form_post` callback, which is exactly the shape an `ASWebAuthenticationSession`/Custom Tab round-trip produces |
| Refresh rotation for native profile (14 d sliding / 90 d absolute) | V2-C `tests/RefreshTokenRotation.test.ts` + `tests/OIDCRefreshGrant.test.ts` — `native_public` lifetimes, one-time rotation, reuse → family revocation |
| Per-device revocation | V2-C family `device_reference` + `revokeByDevice` (tested); V2-D adds unlink-triggered session/family revocation (`tests/AccountLinkingApi.test.ts`) |

Conclusion: **no `/authorize` or `/token` changes are required for native certification.** The
remaining work is pure registration + client-side integration.

## 4. Client integration requirements (normative for Elite+ apps)

1. **PKCE**: fresh 32-byte random verifier per attempt; S256 challenge; verifier kept in process
   memory only.
2. **State & nonce**: fresh cryptographically random values per attempt; validate `state` on the
   redirect before touching the code; the `nonce` returns inside the HAPI id_token and MUST be
   validated.
3. **Token storage (OS-protected only)**:
   - iOS: Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, no iCloud sync.
   - Android: EncryptedSharedPreferences / Jetpack Security backed by Android Keystore
     (StrongBox where available).
   - Access tokens may stay in memory only; refresh tokens never leave secure storage, are never
     logged, and are purged on sign-out and on `invalid_grant`.
4. **Refresh discipline** (V2-C family contract): serialize refreshes behind a single in-app
   mutex; NEVER blindly retry a refresh (a retried consumed token is reuse ⇒ family revocation);
   on `invalid_grant`, purge tokens and return to interactive login.
5. **Device revocation**: send a stable, non-identifying installation UUID as the device
   reference at code exchange so per-device revocation and the device-management UI work; rotate
   it on app reinstall.
6. **Apple/Google in-app expectations**: the system-browser Universal Login handles the entire
   provider round-trip server-side; the app never embeds provider SDK auth for the HAPI flow and
   never receives provider tokens — it only ever sees the final HAPI authorization code.

## 5. Certification checklist for a future activation tranche

1. Register both clients (registration API/seed, no secrets) — **not in V2-D**.
2. Serve `apple-app-site-association` + `assetlinks.json` from the production issuer host.
3. Device-lab run of the §3 matrix against a staging issuer with the federation flags on.
4. Pen-test pass: redirect hijack attempts via unclaimed schemes, PKCE downgrade, code replay,
   refresh reuse on a second device.
5. App Store / Play review prerequisites (Sign in with Apple parity rule: active the moment any
   third-party login ships in the iOS app).

## 6. Explicitly out of V2-D scope

Production client registration, production redirect-URI DNS/host changes, store submissions, any
`id.hapiinc.com` issuer cutover, and production refresh-grant activation
(`HAPI_REFRESH_GRANT_ENABLED` stays OFF).
