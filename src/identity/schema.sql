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

-- Formal schema version tracking (Sprint 5.1).
CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		description TEXT,
		applied_at TIMESTAMP NOT NULL
);
