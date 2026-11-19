-- HAPI ID V2-C: rotating refresh-token families (additive, idempotent).
-- Implements the approved V2-B design (docs/HAPI-ID-V2B-Refresh-Token-Family-Design.md).
-- The refresh grant itself is activated only behind the default-off
-- HAPI_REFRESH_GRANT_ENABLED feature gate; this schema alone changes no behavior.
--
-- Raw refresh tokens are opaque high-entropy secrets held only by the client; the database
-- stores exclusively their SHA-256 hashes. Tokens never appear in logs or plaintext persistence.

-- One row per grant "family": created at the authorization-code exchange that first issues a
-- refresh token, shared by every rotation of that token thereafter.
CREATE TABLE IF NOT EXISTS refresh_token_families (
		id UUID PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		client_id TEXT NOT NULL,
		scope TEXT NOT NULL,
		-- Optional association with the persistent HAPI session and device that established the
		-- grant, so logout / per-device revocation can cascade to refresh families.
		session_id UUID REFERENCES hapi_sessions(id),
		device_reference TEXT,
		-- Authentication context captured at issuance (e.g. PRIVATEID_FACE, HAPI_EMAIL) so refreshed
		-- tokens can carry honest amr/auth_time claims.
		authentication_method TEXT,
		authenticated_at TIMESTAMPTZ,
		status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
		-- Absolute lifetime: no rotation may extend a family beyond this instant.
		absolute_expires_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ,
		revocation_reason TEXT,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		CHECK (status <> 'revoked' OR revoked_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS refresh_token_families_subject_idx
		ON refresh_token_families (identity_subject_id);

CREATE INDEX IF NOT EXISTS refresh_token_families_session_idx
		ON refresh_token_families (session_id)
		WHERE session_id IS NOT NULL;

-- One row per issued refresh token (one generation within a family). Only the hash of the
-- token is stored -- never the token itself.
CREATE TABLE IF NOT EXISTS refresh_tokens (
		id UUID PRIMARY KEY,
		family_id UUID NOT NULL REFERENCES refresh_token_families(id),
		-- SHA-256 (base64url) of the opaque token value presented by the client.
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

-- At most one active generation per family at any instant (fail-closed under concurrent refresh:
-- the loser of a race hits this unique violation inside its transaction and rolls back).
CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_family_active_key
		ON refresh_tokens (family_id)
		WHERE status = 'active';

CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx
		ON refresh_tokens (family_id);
