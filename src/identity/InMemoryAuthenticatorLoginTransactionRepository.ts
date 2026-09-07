import type { AuthenticatorLoginTransaction, AuthenticatorLoginTransactionStatus } from "../models/AuthenticatorLoginTransaction.js";

export class InMemoryAuthenticatorLoginTransactionRepository {
	private readonly transactions = new Map<string, AuthenticatorLoginTransaction>();
	async create(input: Omit<AuthenticatorLoginTransaction, "createdAt" | "completedAt">): Promise<AuthenticatorLoginTransaction> {
		const transaction = { ...input, createdAt: new Date().toISOString() };
		this.transactions.set(transaction.id, transaction);
		return { ...transaction };
	}
	async complete(id: string, status: AuthenticatorLoginTransactionStatus, providerSubject?: string, resolvedUserId?: string): Promise<AuthenticatorLoginTransaction | undefined> {
		const transaction = this.transactions.get(id);
		if (!transaction) return undefined;
		Object.assign(transaction, { status, providerSubject, resolvedUserId, completedAt: new Date().toISOString() });
		return { ...transaction };
	}
}