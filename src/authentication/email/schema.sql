CREATE TABLE IF NOT EXISTS email_authentication_results (
	token_hash TEXT PRIMARY KEY,
	verification_challenge_id UUID NOT NULL UNIQUE REFERENCES verification_challenges(id),
	identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID NOT NULL REFERENCES applications(id),
	client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
	authenticated_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS email_authentication_audit (
	id UUID PRIMARY KEY,
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID REFERENCES applications(id),
	client_id TEXT NOT NULL,
	challenge_id UUID,
	type TEXT NOT NULL CHECK (type IN (
		'EMAIL_AUTHENTICATION_STARTED', 'EMAIL_AUTHENTICATION_VERIFIED',
		'EMAIL_AUTHENTICATION_SUCCEEDED', 'EMAIL_AUTHENTICATION_FAILED',
		'EMAIL_AUTHENTICATION_RATE_LIMITED'
	)),
	outcome TEXT NOT NULL,
	occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS email_authentication_audit_challenge_idx
	ON email_authentication_audit (challenge_id, occurred_at);
