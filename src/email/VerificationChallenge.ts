export const verificationPurposes = ["REGISTRATION", "INVITATION", "RECOVERY", "EMAIL_CHANGE"] as const;
export type VerificationPurpose = typeof verificationPurposes[number];
export type VerificationStatus = "PENDING" | "VERIFIED" | "EXPIRED" | "LOCKED" | "CONSUMED";

export interface VerificationContext {
	tenantId: string;
	applicationId: string | null;
}

export interface VerificationChallenge extends VerificationContext {
	id: string;
	channel: "EMAIL";
	purpose: VerificationPurpose;
	destinationNormalized: string;
	destinationHash: string;
	codeHash: string;
	status: VerificationStatus;
	expiresAt: string;
	attemptCount: number;
	maxAttempts: number;
	sendCount: number;
	lastSentAt: string;
	verifiedAt: string | null;
	consumedAt: string | null;
	createdAt: string;
	updatedAt: string;
}

export class VerificationError extends Error {
	constructor(public readonly code: string, public readonly statusCode = 400) {
		super(code);
	}
}