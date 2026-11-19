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
		// HAPI ID V2-E Stage 0: issuer binding. Codes minted before Stage 0 carry no issuer and
		// are honored only by the default Bookwrm issuer.
		issuer?: string;
		authenticationMethod?: "HAPI_EMAIL" | "PRIVATEID_FACE" | "APPLE" | "GOOGLE";
		authenticatedAt?: string;
};
