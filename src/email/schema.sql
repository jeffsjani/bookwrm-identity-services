CREATE TABLE IF NOT EXISTS verification_challenges (
	id UUID PRIMARY KEY,
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID REFERENCES applications(id),
	channel TEXT NOT NULL CHECK (channel = 'EMAIL'),
	purpose TEXT NOT NULL CHECK (purpose IN ('REGISTRATION', 'INVITATION', 'RECOVERY', 'EMAIL_CHANGE')),
	destination_normalized TEXT NOT NULL,
	destination_hash TEXT NOT NULL,
	code_hash TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'LOCKED', 'CONSUMED')),
	expires_at TIMESTAMPTZ NOT NULL,
	attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
	max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
	send_count INTEGER NOT NULL CHECK (send_count >= 0),
	last_sent_at TIMESTAMPTZ NOT NULL,
	verified_at TIMESTAMPTZ,
	consumed_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	CHECK (status NOT IN ('VERIFIED', 'CONSUMED') OR verified_at IS NOT NULL),
	CHECK (status <> 'CONSUMED' OR consumed_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS verification_challenges_destination_idx ON verification_challenges (tenant_id, destination_hash);

CREATE TABLE IF NOT EXISTS verification_delivery_events (
	id TEXT PRIMARY KEY,
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID REFERENCES applications(id),
	challenge_id UUID NOT NULL REFERENCES verification_challenges(id),
	destination_hash TEXT NOT NULL,
	send_id UUID,
	provider_message_id TEXT,
	state TEXT NOT NULL CHECK (state IN ('CHALLENGE_CREATED', 'SEND_REQUESTED', 'PROVIDER_ACCEPTED', 'DELIVERED', 'DEFERRED', 'BOUNCED', 'COMPLAINED', 'SUPPRESSED', 'USER_VERIFIED', 'PROVIDER_FAILED', 'PROVIDER_TIMEOUT')),
	occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS verification_delivery_destination_idx ON verification_delivery_events (tenant_id, destination_hash, occurred_at);
CREATE INDEX IF NOT EXISTS verification_delivery_message_idx ON verification_delivery_events (provider_message_id) WHERE provider_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS email_verification_audit (
	id UUID PRIMARY KEY,
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID REFERENCES applications(id),
	challenge_id UUID NOT NULL,
	destination_hash TEXT NOT NULL,
	type TEXT NOT NULL CHECK (type IN ('EMAIL_VERIFICATION_STARTED', 'EMAIL_VERIFICATION_SENT', 'EMAIL_VERIFICATION_RESENT', 'EMAIL_VERIFICATION_FAILED', 'EMAIL_VERIFICATION_VERIFIED', 'EMAIL_VERIFICATION_EXPIRED', 'EMAIL_VERIFICATION_LOCKED', 'EMAIL_VERIFICATION_RATE_LIMITED')),
	occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS email_verification_audit_challenge_idx ON email_verification_audit (tenant_id, challenge_id, occurred_at);