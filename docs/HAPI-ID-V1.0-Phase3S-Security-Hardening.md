# HAPI ID V1.0 — Phase 3S Security Hardening

## Service and diagnostic routes

The legacy `/identity/*` proxy is an internal service surface and now requires
`Authorization: Bearer <HAPI_PLATFORM_SERVICE_KEY>`. The diagnostic routes that
were previously unauthenticated now require the same service credential before
handler work. Diagnostics that already required `BOOKWRM_IDENTITY_API_KEY`
retain that existing service authentication.

No in-repository application, test helper, script, or checked-in healthcheck
targets `/identity/admin/health` without authentication. Railway's configured
healthcheck target is `/`; it does not use the administrative endpoint. A
seven-day Railway HTTP-log sample showed one `curl/8.5.0` request to
`/identity/admin/health` and one to `/diagnostics/routes`; these were successful
unauthenticated requests on the current production base and appear to be manual
probes, not Railway healthchecks. The Phase 3S-R recheck found no recurring
dependency in repository scripts, Railway deployment configuration, scheduled
jobs, or the seven-day HTTP logs. The logs contain the historical curl and the
previous release-certification curl only. The historical caller is classified
as an unidentified/manual probe, not a release blocker. No `/identity/*`
requests appeared in the original sample. Readiness checks belong on
`/health/ready`, not an administrative route.

The administrative routes are classified as ADMINISTRATIVE:

| Method | Path | Purpose | Caller evidence | Authentication | Removal candidate |
|---|---|---|---|---|---|
| GET | `/identity/admin/subjects` | Enumerate subjects | No in-repository production caller found | HAPI service key | No |
| GET | `/identity/admin/subject/:id` | Read subject and related state | One curl probe returned 404; no successful read observed | HAPI service key | No |
| GET | `/identity/admin/subject/:id/audit` | Read subject audit | No in-repository production caller found | HAPI service key | No |
| GET | `/identity/admin/provider/:provider/:subject` | Resolve provider identity | No in-repository production caller found | HAPI service key | No |
| GET | `/identity/admin/email/:email` | Search by email | No in-repository production caller found | HAPI service key | No |
| GET | `/identity/admin/health` | Administrative component health | One unauthenticated curl probe; Railway healthcheck uses `/` | HAPI service key; `/health/ready` for public monitoring | No |
| POST | `/identity/admin/subject/:id/recover` | Reassign identity ownership | No in-repository production caller found | HAPI service key | No |
| POST | `/identity/admin/merge` | Merge identities | No in-repository production caller found | HAPI service key | No |

Previously unauthenticated identity routes are internal-service routes:

| Method | Path | Purpose | Caller evidence | Category | Authentication | Removal candidate |
| GET | `/identity/health` | Upstream identity health | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| GET | `/identity/context` | Identity context | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| POST | `/identity/resolve` | Resolve provider identity | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| POST | `/identity/reverify` | Trigger identity reverification | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| GET | `/identity/security-context` | Security state | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| GET | `/identity/policies` | Identity policy data | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| GET | `/identity/timeline` | Identity activity | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| GET | `/identity/notifications` | Identity notifications | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |
| GET | `/identity/trusted-devices` | Trusted-device data | No in-repository caller; none in sampled production logs | INTERNAL SERVICE | HAPI service key | Yes; legacy proxy |

Previously unauthenticated diagnostic routes are internal diagnostics. No
in-repository production caller was found; external callers are unknown. All
now require the HAPI service key before handler execution:

| Method | Path | Purpose | Caller evidence | Category | Authentication | Removal candidate |
|---|---|---|---|---|---|
|---|---|---|---|---|---|---|
| GET | `/diagnostics/identityapi` | Upstream identity API health | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/base44` | Legacy upstream identity health alias | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/context` | Identity context | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/policies` | Identity policy data | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/security` | Identity security context | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/devices` | Trusted-device data | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/notifications` | Identity notifications | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/timeline` | Identity timeline | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| POST | `/diagnostics/reverify` | Trigger identity reverification | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| POST | `/diagnostics/resolve` | Resolve provider identity | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/privateid` | Create a PrivateID authentication session for diagnostics | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/oidc/dashboard` | OIDC and dependency operational snapshot | No in-repository caller; none in sampled production logs | DIAGNOSTIC | HAPI service key | Yes |
| GET | `/diagnostics/routes` | Internal route catalog | One curl probe in sampled production logs; owner unknown | DIAGNOSTIC | HAPI service key | Yes |

Diagnostic routes that already required `BOOKWRM_IDENTITY_API_KEY` keep their
existing service authentication and are classified DIAGNOSTIC: GET
`/diagnostics/privateid-webhook/:sessionId`,
`/diagnostics/enrollment-trace/:sessionId`, `/diagnostics/session/:sessionId`,
`/diagnostics/enrollment-transaction/:transactionId`,
`/diagnostics/privateid-webhook-recent`; POST `/diagnostics/claims`,
`/diagnostics/user-authenticator`, `/diagnostics/identity-record`,
`/diagnostics/identity-subject`, and
`/diagnostics/repair-user-authenticator-link`.

The public OIDC protocol surface is classified PUBLIC BY DESIGN and remains
separate: discovery, JWKS, authorization, token, userinfo, and supported
end-user authentication routes remain available according to their protocol
requirements.

## CORS and redirect URI policy

Credentialed CORS is restricted to the production origins
`https://bookwrm.com`, `https://www.bookwrm.com`, `https://app.base44.com`, and
`https://identity.bookwrm.com`. Unknown origins receive no credentialed CORS
access; requests without an `Origin` remain usable by non-browser clients.
Bookwrm, its `www` alias, and the Base44 production origin are intentionally
supported and match origins in the current production redirect registration.
The HAPI identity origin is intentionally supported for its hosted browser
surface. No additional required Base44 origin was found.

**The CORS origin allowlist is not the OIDC redirect URI allowlist.** CORS
controls whether browser JavaScript can read cross-origin responses. OIDC
redirect URIs are separately registered per client and must match exactly.
Allowing an origin for CORS never authorizes it as an OIDC callback.

## OIDC client authentication and discovery

`token_endpoint_auth_method` explicitly distinguishes public (`none`) from
confidential (`client_secret_basic` or `client_secret_post`) clients. Public
clients do not require a secret and always require PKCE S256. Confidential
clients require a non-empty configured secret and a supplied matching secret;
the comparison is constant-time. A confidential client with missing/empty
secret metadata is invalid.

Every authorization redirect must exactly match a non-empty registered redirect
URI list. An empty list is invalid, not an allow-all policy. Discovery advertises
only `authorization_code`, the grant currently supported by `/token`.
Refresh-token support is a future product decision; this release does not add
refresh-token behavior.

## Deferred product policy

Face behavior is unchanged. Per-client authentication-method policy, including
server-side Face availability for each client, is a Phase 4 P0 follow-up. No
Face enrollment or PrivateID request is part of this release.

## Phase 3S-R release certification

The release base is production commit
`1ef3c2da0a3c47c8bc966f127234c9708bea6066`. The application-ID startup backfill
already exists at this base and is unchanged by this patch. A repeatable-read,
read-only production snapshot found zero subjects with a null application ID,
so the existing backfill has no rows to update.

Pre-deployment counts are 13 identity subjects, 1 user authenticator, 1 identity
account link, 6 HAPI Face bindings, 1 Face consent, and 9 enrollment transactions.
Whole-row aggregate fingerprints are retained privately for post-deployment
comparison; no identity identifiers or credentials are included in this report.
Production Bookwrm remains confidential (`client_secret_basic`) with PKCE
required and four registered redirect URIs.

The unchanged implementation reuses the Phase 3S 610-test certification
(zero failures/skips). The eight requested release suites were rerun:
145 passed, zero failures/skips, including 98 mocked Face Setup/Chromium tests.
TypeScript/build and whitespace validation also pass.
