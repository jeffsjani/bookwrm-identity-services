-- HAPI ID V2-C: persistent server-side HAPI sessions (additive, idempotent).
-- Never alters existing tables or rows. Sessions are NOT wired into the existing Bookwrm
-- authentication flow by this schema -- the session service is activated only behind the
-- default-off HAPI_PERSISTENT_SESSIONS_ENABLED feature gate.
--
-- The browser-held session identifier is a high-entropy opaque secret; only its SHA-256 hash is
-- persisted here (token_hash). The raw secret never touches the database or logs.

CREATE TABLE IF NOT EXISTS hapi_sessions (
		id UUID PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		-- SHA-256 (base64url) of the opaque session secret presented by the browser.
		token_hash TEXT NOT NULL,
		-- SHA-256 (base64url) of the per-session CSRF token (double-submit secret).
		csrf_token_hash TEXT NOT NULL,
		-- The authenticated client context this session was established through (nullable: a
		-- HAPI-first session may exist before any relying-party client is involved).
		client_id TEXT,
		-- Authentication context captured at establishment, for recent-authentication (step-up)
		-- decisions and honest amr/auth_time claims.
		authentication_method TEXT NOT NULL,
		authenticated_at TIMESTAMPTZ NOT NULL,
		-- Device/session management surface: label shown to the user, plus a server-computed
		-- fingerprint reference (never raw header material used for authorization decisions).
		device_label TEXT,
		user_agent_fingerprint TEXT,
		status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
		-- Sliding idle window; refreshed on activity but never beyond absolute_expires_at.
		idle_expires_at TIMESTAMPTZ NOT NULL,
		-- Hard ceiling set at establishment; no activity may extend a session past this instant.
		absolute_expires_at TIMESTAMPTZ NOT NULL,
		last_seen_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ,
		revocation_reason TEXT,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
		CHECK (idle_expires_at <= absolute_expires_at)
);

-- Exact-match lookup by hashed secret; uniqueness makes a (cryptographically implausible)
-- duplicate secret fail closed at insert instead of resolving ambiguously at login.
CREATE UNIQUE INDEX IF NOT EXISTS hapi_sessions_token_hash_key
		ON hapi_sessions (token_hash);

CREATE INDEX IF NOT EXISTS hapi_sessions_subject_idx
		ON hapi_sessions (identity_subject_id);

CREATE INDEX IF NOT EXISTS hapi_sessions_subject_status_idx
		ON hapi_sessions (identity_subject_id, status);
