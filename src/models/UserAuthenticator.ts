export type AuthenticatorProvider = "privateid";

export type AuthenticatorType = "face";

export type UserAuthenticatorStatus = "active" | "revoked";

// Provider-backed credential metadata; HAPI links userId to the existing IdentitySubject.id.
export type UserAuthenticator = {
	id: string;
	userId: string;
	provider: AuthenticatorProvider;
	providerSubject: string;
	authenticatorType: AuthenticatorType;
	status: UserAuthenticatorStatus;
	linkedAt: string;
	verifiedAt?: string;
	lastUsedAt?: string;
	revokedAt?: string;
	createdAt: string;
	updatedAt: string;
};