export type OIDCAuthorizationCode = {
		code: string;
		clientId: string;
		redirectUri: string;
		scope: string;
		nonce: string;
		codeChallenge: string;
		userId: string;
		userSub: string;
		userEmail?: string;
		userEmailVerified?: boolean;
		userName?: string;
		expiresAt: number;
		consumed: boolean;
};
