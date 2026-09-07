export type AuthenticatorProvider = "privateid";

export type AuthenticatorType = "face";

export type UserAuthenticatorStatus = "active" | "revoked";

// Provider-backed credential metadata. It is intentionally not wired into authentication yet.
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