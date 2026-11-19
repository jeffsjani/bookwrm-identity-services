// HAPI ID V2-B: external provider identities and authentication methods explicitly linked to an
// existing, immutable HAPI identity (identity_subjects). The external identity key is always the
// provider's exact (issuer, subject) pair -- never an email address.

export type ExternalIdentityProvider = "APPLE" | "GOOGLE";

export type ExternalIdentityStatus = "linked" | "revoked";

export type ExternalIdentity = {
		id: string;
		identitySubjectId: string;
		provider: ExternalIdentityProvider;
		providerIssuer: string;
		providerSubject: string;
		providerClientContext?: string;
		status: ExternalIdentityStatus;
		linkedAt: string;
		revokedAt?: string;
		lastAuthenticatedAt?: string;
		createdAt: string;
		updatedAt: string;
};

export type AuthenticationMethodType = "HAPI_EMAIL" | "APPLE" | "GOOGLE" | "PASSKEY";

export type AuthenticationMethodStatus = "verified" | "linked" | "revoked";

export type IdentityAuthenticationMethod = {
		id: string;
		identitySubjectId: string;
		methodType: AuthenticationMethodType;
		externalIdentityId?: string;
		credentialReference?: string;
		status: AuthenticationMethodStatus;
		lastUsedAt?: string;
		createdAt: string;
		updatedAt: string;
		revokedAt?: string;
		// True for the implicit HAPI_EMAIL method derived at read time from identity_subjects
		// (primary_provider = 'HAPI_EMAIL' with a verified email); such methods have no table row.
		derived?: boolean;
};

export type IdentityLinkAction = "LINK" | "UNLINK";

export type IdentityLinkOutcome =
		| "SUCCEEDED"
		| "IDEMPOTENT"
		| "REJECTED_CONFLICT"
		| "REJECTED_LAST_METHOD"
		| "REJECTED_SUBJECT_INELIGIBLE"
		| "REJECTED_NOT_FOUND";

export type IdentityLinkAuditEntry = {
		id: string;
		identitySubjectId: string;
		provider: ExternalIdentityProvider;
		externalIdentityId?: string;
		providerIssuer: string;
		// Server-computed SHA-256 reference to the provider subject; raw tokens are never stored.
		providerSubjectRef: string;
		evidenceReference?: string;
		correlationId: string;
		action: IdentityLinkAction;
		outcome: IdentityLinkOutcome;
		detail?: string;
		occurredAt: string;
};
