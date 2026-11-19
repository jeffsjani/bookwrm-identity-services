# HAPI ID V2-C Deliverable — Authenticated Account-Linking API Design (Phase 4)

Status: **Design only — no route in this document is implemented or exposed by V2-C.**
Date: 2026-11-19
Scope authority: HAPI ID V2-C approved tranche, Phase 4.

The policy and persistence layers these APIs consume already exist and are certified:

- `IdentityFederationService` (V2-B, commit `01f6398`) — link/conflict/unlink/list with
  database-enforced uniqueness, last-method protection and transactional audit.
- `AppleIdentityTokenVerifier` (V2-C) — server-side Apple assertion verification.
- `HapiSessionService` (V2-C) — persistent sessions with recent-authentication tracking and CSRF.

---

## 1. Design invariants (non-negotiable)

1. **Linking never occurs from a matching email address.** The only identity key is the verified
   `(provider, provider_issuer, provider_subject)` triple. The APIs below cannot even express an
   email-based link.
2. **The browser never supplies a trusted external subject.** Clients submit raw provider
   artifacts (an Apple/Google `id_token` + the server-issued transaction nonce); the server
   extracts the subject only after full JWKS signature, issuer, audience, nonce and expiry
   verification.
3. **Every endpoint requires an authenticated HAPI session** (the V2-C `__Host-hapi_sid` cookie),
   plus the double-submit CSRF token (`X-HAPI-CSRF` header) on every state-changing request.
4. **Sensitive changes require recent authentication.** Start-link, complete-link and unlink
   require `auth_time` within the step-up window (proposed: 10 minutes); otherwise the API
   returns `step_up_required` and the client must re-authenticate first.
5. **A subject can never remove its last usable sign-in method** (database- and service-enforced;
   re-certified by V2-B/V2-C tests).
6. **All mutations append audit events transactionally** to `identity_link_audit` (same-transaction
   on success; durable rejection records on failure).
7. The whole surface ships behind a default-off flag: `HAPI_ACCOUNT_LINKING_API_ENABLED`.

## 2. Endpoints

All endpoints live under the HAPI account surface (proposed mount: `/account/authentication-methods`)
and are same-origin browser APIs — they are NOT OAuth endpoints and are never called by relying
parties.

### 2.1 List linked sign-in methods

```
GET /account/authentication-methods
Auth: HAPI session cookie
```

200 response:

```json
{
  "methods": [
    { "id": "derived-hapi-email-…", "type": "HAPI_EMAIL", "status": "verified", "derived": true },
    { "id": "…", "type": "APPLE", "status": "linked", "externalIdentityId": "…",
      "linkedAt": "…", "lastAuthenticatedAt": "…" }
  ],
  "canUnlink": { "<methodId>": true, "…": false },
  "recentAuthentication": { "satisfied": false, "authTime": "…", "maxAgeSeconds": 600 }
}
```

Backed by `IdentityFederationService.listAuthenticationMethods` (includes the derived HAPI_EMAIL
method). `canUnlink` is advisory; the server re-checks on every unlink.

### 2.2 Start Apple or Google linking

```
POST /account/authentication-methods/link
Auth: HAPI session cookie + X-HAPI-CSRF + recent authentication
Body: { "provider": "APPLE" | "GOOGLE" }
```

Server effects:
- Mints a single-use, short-TTL (5 min) **linking transaction** bound to
  `(identity_subject_id, session_id, provider)` with a server-generated `nonce` and `state`,
  stored server-side (Redis/PG), never derived from client input.
- 200 response: `{ "transactionId": "…", "nonce": "…", "authorizationParameters": { … } }` —
  everything the front end needs to launch the provider's authorization request with that nonce.

Errors: `step_up_required` (428), `provider_already_linked` (409), `linking_disabled` (404 when
the flag is off).

### 2.3 Complete linking after fresh provider verification

```
POST /account/authentication-methods/link/complete
Auth: HAPI session cookie + X-HAPI-CSRF + recent authentication
Body: { "transactionId": "…", "identityToken": "<provider id_token>" }
```

Server flow (single logical operation):
1. Consume the linking transaction (one-time, bound to this session and subject; expired/absent →
   `invalid_transaction`).
2. Verify the identity token **server-side** with the provider verifier
   (`AppleIdentityTokenVerifier`; Google equivalent in a later tranche): exact issuer, JWKS
   signature, registered audience, **the transaction's nonce**, expiry, subject presence.
3. Call `IdentityFederationService.linkExternalIdentity` with the verified issuer+subject and
   `evidenceReference` = SHA-256 of the raw token (never the token itself).
4. Return the updated method list.

Responses map 1:1 to the repository contract:

| Repository result | HTTP | Body `error` |
| --- | --- | --- |
| `linked` | 200 | — |
| `already_linked` (idempotent) | 200 | — |
| `conflict` / `provider_identity_linked_to_other_subject` | 409 | `provider_identity_in_use` (owning subject NEVER revealed) |
| `conflict` / `subject_provider_already_linked` | 409 | `provider_already_linked` |
| `rejected` / subject ineligible | 403 | `subject_not_eligible` |
| verifier failure | 400 | `provider_verification_failed` (no claim detail echoed) |

### 2.4 Resolve linking conflicts

Conflicts are resolved **explicitly, never automatically**:

- `provider_identity_in_use`: the UI directs the user to sign in to the owning HAPI account and
  unlink there first (or invoke account recovery). There is NO API that transfers a provider
  identity between subjects in one step, and no automatic merging of any kind.
- `provider_already_linked`: the subject already has an active identity for that provider; the
  user must unlink it before linking a different provider account (relink-after-unlink is the
  supported rotation path, re-certified in V2-C tests).

### 2.5 Unlink a method safely

```
DELETE /account/authentication-methods/{externalIdentityId}
Auth: HAPI session cookie + X-HAPI-CSRF + recent authentication
```

Backed by `IdentityFederationService.unlinkExternalIdentity`:

| Result | HTTP | Notes |
| --- | --- | --- |
| `unlinked` | 200 | Also revokes refresh-token families and (optionally) sessions established via that method |
| `rejected` / `last_method` | 409 `last_method` | The subject would have zero usable sign-in methods |
| `rejected` / `not_found` | 404 | Includes another subject's identity id (no existence oracle) |

### 2.6 Recent-authentication (step-up) contract

Every 2.2/2.3/2.5 call evaluates `HapiSessionService.isRecentlyAuthenticated(session, 600_000)`.
On failure: HTTP 428 `{ "error": "step_up_required", "maxAgeSeconds": 600 }`. Completing a fresh
HAPI authentication (email OTP / face) replaces the session (fixation-safe) with a new
`auth_time`, after which the original request is retried by the UI.

## 3. Audit events

Every mutation writes `identity_link_audit` rows exactly as the V2-B repository already does
(action LINK/UNLINK; outcomes SUCCEEDED, IDEMPOTENT, REJECTED_CONFLICT, REJECTED_LAST_METHOD,
REJECTED_SUBJECT_INELIGIBLE, REJECTED_NOT_FOUND), with `provider_subject_ref` (keyed hash),
`evidence_reference` (token hash) and the request `correlation_id`. The API adds no new audit
channel — it reuses the proven transactional one.

## 4. Explicitly out of V2-C scope

Implementation and exposure of these routes, Google verifier implementation, provider
credentials, any UI, and any production flag activation. These require a separate approved
tranche (proposed V2-D, see the V2-C certification report).
