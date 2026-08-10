export type PrivateIDResult = {
		success: boolean;
		privateIdUserId: string;
		confidence: number;
		risk: number;
		liveness: boolean;
		sessionId: string;
		transactionId: string;
		rawResponse: unknown;
};
