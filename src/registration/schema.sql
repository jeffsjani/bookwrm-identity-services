-- HAPI ID H3: Canonical Identity Registration.
-- Additive only; never alters existing identity_subjects/verification_challenges rows or columns.

-- Registration evidence linkage (Task 17): records which verified H2 challenge established which
-- canonical IdentitySubject, under which tenant/application, and when. One row per verification
-- challenge (primary key), which also doubles as the idempotency anchor for retry handling
-- (Task 10) -- a consumed challenge with no linkage row here is treated as ambiguous/foreign
-- consumption, never as proof of a successful H3 registration.
CREATE TABLE IF NOT EXISTS registration_evidence (
		verification_challenge_id UUID PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		tenant_id UUID NOT NULL,
		application_id UUID NOT NULL,
		email_normalized TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS registration_evidence_identity_subject_id_idx ON registration_evidence (identity_subject_id);

-- Registration audit (Task 12). Append-only; privacy-conscious metadata only (never codes/secrets).
CREATE TABLE IF NOT EXISTS identity_registration_audit (
		id UUID PRIMARY KEY,
		tenant_id UUID NOT NULL,
		application_id UUID NOT NULL,
		verification_challenge_id UUID,
		identity_subject_id UUID,
		type TEXT NOT NULL CHECK (type IN (
				'IDENTITY_REGISTRATION_STARTED',
				'IDENTITY_REGISTERED',
				'IDENTITY_REGISTRATION_IDEMPOTENT',
				'IDENTITY_REGISTRATION_CONFLICT',
				'IDENTITY_REGISTRATION_FAILED'
		)),
		detail TEXT,
		occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS identity_registration_audit_tenant_id_idx ON identity_registration_audit (tenant_id);
