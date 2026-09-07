import type { AuthenticatorProvider } from "./UserAuthenticator.js";

export type AuthenticatorLoginTransactionStatus = "pending" | "completed" | "failed";

export type AuthenticatorLoginTransaction = {
	id: string;
	provider: AuthenticatorProvider;
	providerTransactionId: string;
	providerSubject?: string;
	resolvedUserId?: string;
	status: AuthenticatorLoginTransactionStatus;
	createdAt: string;
	completedAt?: string;
};