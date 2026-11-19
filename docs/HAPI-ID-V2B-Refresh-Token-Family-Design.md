# HAPI ID V2-B Deliverable — Rotating Refresh-Token Family Design (Proposal)

Status: **Design only — approved for later implementation, not implemented in V2-B.**
Date: 2026-11-19
Scope authority: HAPI ID V2-B approved tranche, Phase 4 ("Provide the proposed rotating
refresh-token family schema and lifecycle design as a separate deliverable for later
implementation").

---

## 1. Problem statement

As of V2-B, the platform:

- Advertises `grant_types_supported: ["authorization_code"]` in discovery.
- Implements **no** `grant_type=refresh_token` handler (`/token` rejects it with
  `unsupported_grant_type`).
- Before V2-B, unconditionally issued a `refresh_token` on every successful code exchange and
  stored it in Redis for 30 days (`REFRESH_TOKEN_TTL_MS = 2_592_000_000`).

### Security risks of issuing refresh tokens without a refresh grant

1. **Pure liability, zero utility.** A 30-day opaque bearer credential exists in Redis and in
   client storage but cannot be redeemed. It protects nothing and can only leak.
2. **No rotation or reuse detection.** If the stored value leaks (client storage, logs, Redis
   snapshot), nothing detects or revokes it; it silently expires after 30 days.
3. **No revocation surface.** There is no RFC 7009 revocation endpoint and no server-side
   invalidation tied to subject status changes (LOCKED/DISABLED) or unlink events.
4. **Future-activation hazard.** If a refresh grant were ever enabled naively, every token issued
   during the preceding 30 days — including to clients that never requested one — would instantly
   become a usable long-lived credential, with no family tracking or theft detection.

### V2-B interim policy (implemented and tested in this tranche)

- A refresh token is issued **only** when the client's persisted registration explicitly includes
  the `refresh_token` grant type (`clientAllowsRefreshTokenGrant`). Legacy registrations without a
  grant list keep their existing behavior.
- The legacy Bookwrm web client registration includes `refresh_token`, so its observable contract
  is unchanged (backward compatible; regression-tested in
  `tests/NonceAndRefreshTokenPolicy.test.ts` and `tests/OIDCToken.test.ts`).
- Newly registered clients — including the future Elite+ native public clients — are registered
  **without** `refresh_token` and therefore receive none until this design is implemented.
- Discovery continues to advertise only `authorization_code`. No untested refresh grant was added.

---

## 2. Proposed durable schema (PostgreSQL, additive, idempotent)

Refresh state moves from Redis to PostgreSQL: refresh tokens are long-lived, must survive restarts
and Redis flushes, and need relational integrity with `identity_subjects` and the client registry.

```sql
-- One row per grant "family": created at the authorization-code exchange that first issues a
-- refresh token, shared by every rotation of that token thereafter.
CREATE TABLE IF NOT EXISTS refresh_token_families (
    id UUID PRIMARY KEY,
    identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    -- Authentication context captured at issuance (e.g. PRIVATEID_FACE, HAPI_EMAIL) so refreshed
    -- tokens can carry honest amr/auth_time claims.
    authentication_method TEXT,
    authenticated_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    -- Absolute lifetime: no rotation may extend a family beyond this instant.
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,  -- e.g. 'reuse_detected', 'subject_locked', 'client_request', 'admin'
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (status <> 'revoked' OR revoked_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS refresh_token_families_subject_idx
    ON refresh_token_families (identity_subject_id);

-- One row per issued refresh token (one generation within a family). Only the keyed hash of the
-- token is stored -- never the token itself.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    family_id UUID NOT NULL REFERENCES refresh_token_families(id),
    -- SHA-256 (keyed) of the opaque token value presented by the client.
    token_hash TEXT NOT NULL,
    generation INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked', 'expired')),
    -- Sliding lifetime for this generation (min(now + sliding TTL, family absolute_expires_at)).
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    -- The successor generation minted when this token was rotated.
    replaced_by UUID REFERENCES refresh_tokens(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_token_hash_key
    ON refresh_tokens (token_hash);

-- At most one active generation per family at any instant (fail-closed under concurrent refresh).
CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_family_active_key
    ON refresh_tokens (family_id)
    WHERE status = 'active';
```

Audit: refresh issuance, rotation, reuse detection and revocation events append to the existing
`oidc` structured log stream and (optionally) a `refresh_token_audit` table following the
`identity_link_audit` pattern (append-only, same-transaction writes, no raw token material).

## 3. Lifecycle

1. **Issuance (code exchange).** If the client registration permits `refresh_token`, create a
   family (absolute lifetime, e.g. 90 days for native clients) and generation 1 (sliding lifetime,
   e.g. 14 days) inside the same transaction. Return the opaque token; store only its keyed hash.
2. **Refresh (`grant_type=refresh_token`).** In one transaction: look up by token hash
   `FOR UPDATE`; verify client identity binding (public clients: exact `client_id` match;
   confidential: full client authentication), family and generation status, and both expirations;
   mark the presented generation `rotated`; insert generation N+1 as `active`; issue new access +
   refresh tokens. The partial unique index makes concurrent refreshes fail closed — the loser
   hits the unique violation and receives `invalid_grant`.
3. **Reuse detection (theft signal).** Presenting a token whose status is `rotated` or `revoked`
   immediately revokes the **entire family** (`revocation_reason = 'reuse_detected'`), rejects the
   request with `invalid_grant`, and emits an audit event. The legitimate holder's next refresh
   also fails, forcing interactive re-authentication — the standard OAuth 2.1 family-revocation
   response to replay.
4. **Subject lifecycle binding.** Families are revoked when the subject is LOCKED/DISABLED, and on
   relevant authentication-method unlink events (V2-B `identity_link_audit` provides the hook).
5. **Revocation endpoint.** RFC 7009 `/revoke` accepting the refresh token, revoking its family.
6. **Expiry.** Families and generations past expiry are inert immediately (status checked on every
   use) and garbage-collected by a background sweep.

## 4. Activation preconditions (not part of V2-B)

1. Implement + test the refresh handler behind a feature flag, default off.
2. Add `refresh_token` to `grant_types_supported` only when the flag is on.
3. Only then register native production clients with the `refresh_token` grant.
4. Regression gate: all existing `/token` authorization-code tests unchanged.

Token lifetimes (proposed starting points, to be ratified at implementation review):

| Parameter | Native public client | Confidential web client |
| --- | --- | --- |
| Access token | 5 min (current) | 5 min (current) |
| Refresh sliding TTL | 14 days | 24 h |
| Family absolute TTL | 90 days | 30 days |
