-- Durable authority for HAPI attachment only; legacy enrollment retains its existing behavior.
CREATE TABLE IF NOT EXISTS hapi_face_enrollment_bindings (
	enrollment_id UUID PRIMARY KEY REFERENCES privateid_enrollment_transactions(id),
	identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID NOT NULL REFERENCES applications(id),
	client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
	authenticated_at TIMESTAMPTZ NOT NULL,
	session_id TEXT UNIQUE,
	authenticator_id UUID REFERENCES user_authenticators(id)
);

CREATE INDEX IF NOT EXISTS hapi_face_enrollment_subject_idx
	ON hapi_face_enrollment_bindings (identity_subject_id);

-- HAPI-owned, versioned consent evidence; Base44 consent records are never authorization evidence.
CREATE TABLE IF NOT EXISTS hapi_face_authentication_consents (
	id UUID PRIMARY KEY,
	identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID NOT NULL REFERENCES applications(id),
	client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
	purpose TEXT NOT NULL CHECK (purpose = 'FACE_AUTHENTICATION'),
	consent_version TEXT NOT NULL,
	accepted_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS hapi_face_authentication_consents_subject_context_idx
	ON hapi_face_authentication_consents (identity_subject_id, tenant_id, application_id, client_id, accepted_at DESC);

CREATE TABLE IF NOT EXISTS authenticator_enrollment_audit (
	id UUID PRIMARY KEY,
	tenant_id UUID NOT NULL REFERENCES tenants(id),
	application_id UUID NOT NULL REFERENCES applications(id),
	client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
	identity_subject_id UUID NOT NULL REFERENCES identity_subjects(id),
	enrollment_id UUID REFERENCES privateid_enrollment_transactions(id),
	provider TEXT NOT NULL CHECK (provider = 'privateid'),
	type TEXT NOT NULL CHECK (type IN (
		'AUTHENTICATOR_ENROLLMENT_STARTED', 'AUTHENTICATOR_ENROLLED',
		'AUTHENTICATOR_ALREADY_ACTIVE', 'AUTHENTICATOR_ENROLLMENT_CONFLICT',
		'AUTHENTICATOR_ENROLLMENT_FAILED')),
	outcome TEXT NOT NULL,
	occurred_at TIMESTAMPTZ NOT NULL
);
