export type PrivateIDSessionStatus =
		| "created"
		| "initialized"
		| "launching"
		| "waiting"
		| "polling"
		| "ready"
		| "cancelled"
		| "failed"
		| "expired";

export type PrivateIDSession = {
		sessionId: string;
		transactionId: string;
		status: PrivateIDSessionStatus;
		launchUrl: string;
		expires: number;
		created: number;
		completed?: number;
};