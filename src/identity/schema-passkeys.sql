-- Passkeys always belong to an existing identity subject. Handles are random and stable per subject.
CREATE TABLE IF NOT EXISTS passkey_user_handles (
		identity_subject_id UUID PRIMARY KEY REFERENCES identity_subjects(id),
		user_handle BYTEA NOT NULL UNIQUE CHECK (octet_length(user_handle) = 32),
		UNIQUE (identity_subject_id, user_handle)
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
		credential_id TEXT PRIMARY KEY,
		identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
		user_handle BYTEA NOT NULL,
		public_key BYTEA NOT NULL CHECK (octet_length(public_key) > 0),
		signature_counter BIGINT NOT NULL CHECK (signature_counter >= 0),
		transports TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
		backup_eligible BOOLEAN NOT NULL,
		backup_state BOOLEAN NOT NULL,
		enrollment_authority_ref TEXT NOT NULL UNIQUE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		last_used_at TIMESTAMPTZ,
		revoked_at TIMESTAMPTZ,
		FOREIGN KEY (identity_subject_id, user_handle)
				REFERENCES passkey_user_handles(identity_subject_id, user_handle),
		CHECK (NOT backup_state OR backup_eligible)
);

CREATE INDEX IF NOT EXISTS passkey_credentials_subject_idx
		ON passkey_credentials (identity_subject_id);
