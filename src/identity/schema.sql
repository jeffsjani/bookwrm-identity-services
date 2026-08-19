-- Identity Registry system-of-record table (Phase 2, RC1-D / RC1-K).
CREATE TABLE IF NOT EXISTS identity_subjects (
		id UUID PRIMARY KEY,
		oidc_subject UUID NOT NULL,
		primary_provider TEXT NOT NULL,
		primary_provider_subject TEXT NOT NULL,
		email TEXT NOT NULL,
		email_verified BOOLEAN NOT NULL,
		display_name TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		last_authenticated_at TIMESTAMPTZ,
		CONSTRAINT identity_subjects_oidc_subject_key UNIQUE (oidc_subject),
		CONSTRAINT identity_subjects_provider_identity_key UNIQUE (primary_provider, primary_provider_subject)
);
