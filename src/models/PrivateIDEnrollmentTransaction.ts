export type PrivateIDEnrollmentPurpose = "face_enrollment";

export type PrivateIDEnrollmentTransactionStatus = "pending" | "completed" | "failed" | "expired";

export type PrivateIDEnrollmentTransaction = {
	id: string;
	userId: string;
	purpose: PrivateIDEnrollmentPurpose;
	providerTransactionId: string;
	status: PrivateIDEnrollmentTransactionStatus;
	createdAt: string;
	expiresAt: string;
	completedAt?: string;
};