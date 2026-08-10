export type OIDCAuthorizationCode = {
		code: string;
		clientId: string;
		redirectUri: string;
		scope: string;
		nonce: string;
		codeChallenge: string;
		userId: string;
		expiresAt: number;
		consumed: boolean;
};
