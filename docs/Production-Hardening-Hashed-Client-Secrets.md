# Production Hardening Requirement — Hashed-at-Rest OAuth Client Credentials

**Status:** OPEN requirement (documented 2026-11-19 during HAPI ID V2-E Stage 3 review).
**Scope:** production security hardening. Explicitly **out of scope** for the staging-only
Stage 3 certification, which preserves the existing plaintext-compatible validation.

## Current state (verified against source)

`oidc_clients.client_secret` stores the **plaintext** client secret
([schema](../src/identity/schema.sql), `oidc_clients` table). Every comparison site hashes
only for constant-time equality, never for storage:

| Site | Mechanism |
| --- | --- |
| `src/oidc/OIDCService.ts` `/token` | `constantTimeStringEqual(storedPlaintext, presented)` |
| `src/identity/H1ClientAuthority.ts` `authorizeH1Client` | `timingSafeEqual(sha256(presented), sha256(storedPlaintext))` |
| `src/routes/registration.ts` `authorize` | same sha256/timingSafeEqual pattern |

Consequences of plaintext at rest:

- A database read (backup leak, SQL injection, over-privileged operator, misdirected
  `pg_dump`) discloses every confidential client's credential directly and reversibly.
- Secrets transit statement text during seeding/rotation, so operational tooling must take
  extraordinary care to avoid server-log capture (see
  [`scripts/rotate-staging-web-secret.sql`](../scripts/rotate-staging-web-secret.sql) for the
  leak-safe pattern this forces).

## Requirement

Before (or as a gated step of) production rollout of new confidential clients:

1. Store only a one-way, salted, memory-hard digest of each client secret (argon2id
   recommended; PBKDF2-HMAC-SHA256 acceptable). Client secrets are high-entropy
   machine-generated values, so parameters may be lighter than user-password settings, but
   digests must remain salted and one-way.
2. Replace all three comparison sites with digest verification against the stored record;
   keep constant-time comparison semantics.
3. Migration: add a `client_secret_hash` column, dual-verify during a rollout window
   (verify hash if present, else plaintext), backfill by rotating every confidential client
   secret (plaintext values cannot be hashed in place safely without rotation evidence),
   then drop the plaintext column. Rotation of the single production Bookwrm client is the
   only coordination point.
4. Update seed/rotation tooling to write digests, which also removes the plaintext-in-SQL
   operational hazard entirely.
5. Add regression tests asserting that no code path reads a plaintext
   `oidc_clients.client_secret` once migration completes.

## Non-goals

- `staging-native` and other public clients (`token_endpoint_auth_method=none`) store no
  secret and are unaffected.
- This document does not change any runtime behavior; it records the requirement only.
