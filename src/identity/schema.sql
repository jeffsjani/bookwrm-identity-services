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

-- HAPI ID H1 (Multi-Tenant/Application Foundation): top-level IDaaS customer boundary.
CREATE TABLE IF NOT EXISTS tenants (
		id UUID PRIMARY KEY,
		name TEXT NOT NULL,
		slug TEXT NOT NULL UNIQUE,
		status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
);

-- A registered relying-party product within a Tenant (e.g. Bookwrm's Base44 app). Owns one or more oidc_clients rows.
CREATE TABLE IF NOT EXISTS applications (
		id UUID PRIMARY KEY,
		tenant_id UUID NOT NULL REFERENCES tenants(id),
		name TEXT NOT NULL,
		slug TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		CONSTRAINT applications_tenant_slug_key UNIQUE (tenant_id, slug)
);

-- Persisted replacement for the hardcoded Base44 OIDC client configuration previously in src/oidc/clients.ts.
CREATE TABLE IF NOT EXISTS oidc_clients (
		id UUID PRIMARY KEY,
		application_id UUID NOT NULL REFERENCES applications(id),
		client_id TEXT NOT NULL UNIQUE,
		client_secret TEXT NOT NULL,
		redirect_uris TEXT[] NOT NULL,
		scopes TEXT[] NOT NULL,
		grant_types TEXT[] NOT NULL,
		response_types TEXT[] NOT NULL,
		token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('client_secret_post', 'client_secret_basic', 'none')),
		require_pkce BOOLEAN NOT NULL DEFAULT true,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
);

-- Scopes an IdentitySubject to the Application it was minted under; nullable so pre-H1 rows remain valid
-- until PlatformSeed.ts backfills them to the Bookwrm application (see ensureBookwrmApplicationSeed()).
ALTER TABLE identity_subjects ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES applications(id);

-- Provider authenticator storage used by Face login and HAPI authenticator attachment.
CREATE TABLE IF NOT EXISTS user_authenticators (
		id UUID PRIMARY KEY,
		-- HAPI uses identity_subjects.id::text; legacy product identifiers remain compatible.
		user_id TEXT NOT NULL,
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

-- Release C3.7: existing deployments created the column as UUID with an identity_subjects FK; migrate in place.
ALTER TABLE user_authenticators DROP CONSTRAINT IF EXISTS user_authenticators_user_id_fkey;
ALTER TABLE user_authenticators ALTER COLUMN user_id TYPE TEXT USING user_id::text;

CREATE UNIQUE INDEX IF NOT EXISTS user_authenticators_one_active_face_per_user_key
		ON user_authenticators (user_id)
		WHERE status = 'active' AND authenticator_type = 'face';

CREATE TABLE IF NOT EXISTS privateid_enrollment_transactions (
		id UUID PRIMARY KEY,
		-- HAPI uses identity_subjects.id::text; legacy product identifiers remain compatible.
		user_id TEXT NOT NULL,
		purpose TEXT NOT NULL CHECK (purpose = 'face_enrollment'),
		provider_transaction_id UUID NOT NULL UNIQUE,
		status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
		created_at TIMESTAMPTZ NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		completed_at TIMESTAMPTZ
);

-- Release C3.7: existing deployments created the column as UUID with an identity_subjects FK; migrate in place.
ALTER TABLE privateid_enrollment_transactions DROP CONSTRAINT IF EXISTS privateid_enrollment_transactions_user_id_fkey;
ALTER TABLE privateid_enrollment_transactions ALTER COLUMN user_id TYPE TEXT USING user_id::text;

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

-- HAPI ID H3P: durable governance metadata for which source currently owns each IdentitySubject
-- claim (Release C5.1/H3). Additive only; keyed by the immutable identity_subjects.id, never by
-- email/oidcSubject/providerSubject. Deliberately minimal -- not a generalized evidence system.
CREATE TABLE IF NOT EXISTS identity_claim_provenance (
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		claim_name TEXT NOT NULL,
		source TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (identity_subject_id, claim_name)
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

-- Release C5.1: provider-neutral mapping from an external Bookwrm account to an IdentitySubject.
-- Deliberately separate from providerSubject/user_authenticators.user_id/oidc_subject.
CREATE TABLE IF NOT EXISTS identity_account_links (
		id UUID PRIMARY KEY,
		source TEXT NOT NULL CHECK (source = 'bookwrm'),
		external_user_id TEXT NOT NULL,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		status TEXT NOT NULL CHECK (status = 'active'),
		linked_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		CONSTRAINT identity_account_links_source_external_user_id_key UNIQUE (source, external_user_id)
);
