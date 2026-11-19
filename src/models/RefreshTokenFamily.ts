// HAPI ID V2-C: rotating refresh-token families (implements the approved V2-B design,
// docs/HAPI-ID-V2B-Refresh-Token-Family-Design.md). A family is created at the authorization-code
// exchange that first issues a refresh token; each rotation mints a new generation. Only token
// hashes are ever persisted.

export type RefreshTokenFamilyStatus = "active" | "revoked" | "expired";

export type RefreshTokenGenerationStatus = "active" | "rotated" | "revoked" | "expired";

export type RefreshTokenFamilyRevocationReason =
		| "reuse_detected"
		| "subject_locked"
		| "client_request"
		| "logout"
		| "session_revoked"
		| "device_revoked"
		| "admin";

export type RefreshTokenFamily = {
		id: string;
		identitySubjectId: string;
		clientId: string;
		scope: string;
		sessionId?: string;
		deviceReference?: string;
		authenticationMethod?: string;
		authenticatedAt?: string;
		status: RefreshTokenFamilyStatus;
		absoluteExpiresAt: string;
		revokedAt?: string;
		revocationReason?: string;
		createdAt: string;
		updatedAt: string;
};

export type RefreshTokenGeneration = {
		id: string;
		familyId: string;
		// SHA-256 (base64url) of the opaque token value presented by the client.
		tokenHash: string;
		generation: number;
		status: RefreshTokenGenerationStatus;
		expiresAt: string;
		rotatedAt?: string;
		replacedBy?: string;
		createdAt: string;
		updatedAt: string;
};
