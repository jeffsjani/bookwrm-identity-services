// Release Patch 6.1: only stable, protocol-level fields belong here -- mutable claims (email/name/etc.)
// are owned exclusively by the Identity Registry and must be re-resolved at token issuance, not snapshotted.
export type OIDCAuthorizationCode = {
		code: string;
		clientId: string;
		redirectUri: string;
		scope: string;
		nonce: string;
		codeChallenge: string;
		userId: string;
		userSub: string;
		expiresAt: number;
		consumed: boolean;
};
