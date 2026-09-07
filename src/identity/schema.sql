-- Identity Registry system-of-record table (Phase 2, RC1-D / RC1-K).
CREATE TABLE IF NOT EXISTS identity_subjects (
		id UUID PRIMARY KEY,
		oidc_subject UUID NOT NULL,
		primary_provider TEXT NOT NULL,
		primary_provider_subject TEXT NOT NULL,
		email TEXT,
		email_verified BOOLEAN,
		display_name TEXT,
		status TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		last_authenticated_at TIMESTAMPTZ,
		CONSTRAINT identity_subjects_oidc_subject_key UNIQUE (oidc_subject),
		CONSTRAINT identity_subjects_provider_identity_key UNIQUE (primary_provider, primary_provider_subject)
);

ALTER TABLE identity_subjects ALTER COLUMN email DROP NOT NULL;
ALTER TABLE identity_subjects ALTER COLUMN email_verified DROP NOT NULL;
ALTER TABLE identity_subjects ALTER COLUMN display_name DROP NOT NULL;

-- Provider authenticator storage. It is intentionally not used by runtime authentication yet.
CREATE TABLE IF NOT EXISTS user_authenticators (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES identity_subjects(id),
		provider TEXT NOT NULL CHECK (provider = 'privateid'),
		provider_subject TEXT NOT NULL,
		authenticator_type TEXT NOT NULL CHECK (authenticator_type = 'face'),
		status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
		linked_at TIMESTAMPTZ NOT NULL,
		verified_at TIMESTAMPTZ,
		last_used_at TIMESTAMPTZ,
		revoked_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		CONSTRAINT user_authenticators_provider_subject_key UNIQUE (provider, provider_subject)
);

CREATE UNIQUE INDEX IF NOT EXISTS user_authenticators_one_active_face_per_user_key
		ON user_authenticators (user_id)
		WHERE status = 'active' AND authenticator_type = 'face';

CREATE TABLE IF NOT EXISTS privateid_enrollment_transactions (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES identity_subjects(id),
		purpose TEXT NOT NULL CHECK (purpose = 'face_enrollment'),
		provider_transaction_id UUID NOT NULL UNIQUE,
		status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
		created_at TIMESTAMPTZ NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS authenticator_login_transactions (
		id UUID PRIMARY KEY,
		provider TEXT NOT NULL CHECK (provider = 'privateid'),
		provider_transaction_id UUID NOT NULL UNIQUE,
		provider_subject TEXT,
		resolved_user_id UUID REFERENCES identity_subjects(id),
		status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
		created_at TIMESTAMPTZ NOT NULL,
		completed_at TIMESTAMPTZ
);

-- Formal schema version tracking (Sprint 5.1).
CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		description TEXT,
		applied_at TIMESTAMP NOT NULL
);

-- TEMPORARY RELEASE PATCH 8.4: remove after production certification.
CREATE TABLE IF NOT EXISTS privateid_webhook_diagnostics (
		received_at TIMESTAMP NOT NULL,
		session_id TEXT PRIMARY KEY,
		transaction_id TEXT NOT NULL,
		status TEXT NOT NULL,
		raw_webhook_json JSONB NOT NULL
);
