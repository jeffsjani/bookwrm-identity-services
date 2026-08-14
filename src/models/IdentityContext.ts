export interface IdentityContext {

		userId: string;

		email: string;

		emailVerified: boolean;

		confidence: number;

		risk: number;

		securityLevel: string;

		verified: boolean;

		trustedDevice: boolean;

		verificationRequired: boolean;

}
