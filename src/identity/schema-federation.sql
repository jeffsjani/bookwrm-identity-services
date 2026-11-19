-- HAPI ID V2-B: Universal identity federation foundation (additive, idempotent).
-- Never alters or rewrites existing identity_subjects rows, oidc_subject values, or any existing
-- table. Apple/Google authentication is NOT activated by this schema -- it only prepares the
-- durable registry for explicitly linked external provider identities. identity_subjects remains
-- the sole authoritative identity registry; rows here always reference an existing subject.

-- One row per external provider identity linking transaction. The exact external identity key is
-- (provider, provider_issuer, provider_subject) -- never an email address, so a matching email can
-- never merge or link accounts implicitly.
CREATE TABLE IF NOT EXISTS external_identities (
		id UUID PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		provider TEXT NOT NULL CHECK (provider IN ('APPLE', 'GOOGLE')),
		provider_issuer TEXT NOT NULL CHECK (length(trim(provider_issuer)) > 0),
		provider_subject TEXT NOT NULL CHECK (length(trim(provider_subject)) > 0),
		-- Provider client/audience context (e.g. Apple Services ID or Google OAuth client id) the
		-- assertion that established this link was issued for.
		provider_client_context TEXT,
		status TEXT NOT NULL CHECK (status IN ('linked', 'revoked')),
		linked_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ,
		last_authenticated_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		CHECK (status <> 'revoked' OR revoked_at IS NOT NULL)
);

-- Atomic platform-wide uniqueness: one ACTIVE link per exact external provider identity. The
-- database (not application code) is the final arbiter for concurrent linking -- the second of two
-- racing transactions fails closed with a unique violation here. Revoked rows are retained as
-- history, so the same provider identity may later be explicitly re-linked.
CREATE UNIQUE INDEX IF NOT EXISTS external_identities_provider_identity_active_key
		ON external_identities (provider, provider_issuer, provider_subject)
		WHERE status = 'linked';

-- One active identity per provider per HAPI subject.
CREATE UNIQUE INDEX IF NOT EXISTS external_identities_subject_provider_active_key
		ON external_identities (identity_subject_id, provider)
		WHERE status = 'linked';

CREATE INDEX IF NOT EXISTS external_identities_subject_idx
		ON external_identities (identity_subject_id);

-- Verified authentication methods attached to a HAPI subject. HAPI_EMAIL for existing subjects is
-- additionally DERIVED at read time from identity_subjects (primary_provider = 'HAPI_EMAIL' with a
-- verified email) -- no backfill rewrite of existing data is performed.
CREATE TABLE IF NOT EXISTS identity_authentication_methods (
		id UUID PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		method_type TEXT NOT NULL CHECK (method_type IN ('HAPI_EMAIL', 'APPLE', 'GOOGLE', 'PASSKEY')),
		external_identity_id UUID REFERENCES external_identities(id),
		-- Opaque reference to a credential record (e.g. future passkey id); never raw credential material.
		credential_reference TEXT,
		status TEXT NOT NULL CHECK (status IN ('verified', 'linked', 'revoked')),
		last_used_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ,
		CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
		CHECK (method_type NOT IN ('APPLE', 'GOOGLE') OR external_identity_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_authentication_methods_active_per_type_key
		ON identity_authentication_methods (identity_subject_id, method_type)
		WHERE status <> 'revoked';

CREATE UNIQUE INDEX IF NOT EXISTS identity_authentication_methods_external_identity_active_key
		ON identity_authentication_methods (external_identity_id)
		WHERE external_identity_id IS NOT NULL AND status <> 'revoked';

CREATE INDEX IF NOT EXISTS identity_authentication_methods_subject_idx
		ON identity_authentication_methods (identity_subject_id);

-- Append-only account-linking audit. Successful mutations write their audit row inside the same
-- transaction as the state change; rejected attempts are recorded immediately afterwards (the
-- failed transaction changed nothing). provider_subject_ref is a server-computed SHA-256 keyed
-- reference -- raw tokens and assertions are never stored (matching existing audit conventions).
CREATE TABLE IF NOT EXISTS identity_link_audit (
		id UUID PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		provider TEXT NOT NULL CHECK (provider IN ('APPLE', 'GOOGLE')),
		external_identity_id UUID REFERENCES external_identities(id),
		provider_issuer TEXT NOT NULL,
		provider_subject_ref TEXT NOT NULL,
		-- Reference to the authentication evidence (e.g. a challenge/assertion record id or hash);
		-- never a raw provider token.
		evidence_reference TEXT,
		correlation_id TEXT NOT NULL,
		action TEXT NOT NULL CHECK (action IN ('LINK', 'UNLINK')),
		outcome TEXT NOT NULL CHECK (outcome IN (
				'SUCCEEDED',
				'IDEMPOTENT',
				'REJECTED_CONFLICT',
				'REJECTED_LAST_METHOD',
				'REJECTED_SUBJECT_INELIGIBLE',
				'REJECTED_NOT_FOUND'
		)),
		detail TEXT,
		occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS identity_link_audit_subject_idx
		ON identity_link_audit (identity_subject_id, occurred_at);
