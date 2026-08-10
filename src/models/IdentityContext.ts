export interface IdentityContext {

		userId: string;

		confidence: number;

		risk: number;

		securityLevel: string;

		verified: boolean;

		trustedDevice: boolean;

		verificationRequired: boolean;

}
