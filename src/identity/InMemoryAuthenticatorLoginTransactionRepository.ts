import type { AuthenticatorLoginTransaction, AuthenticatorLoginTransactionStatus } from "../models/AuthenticatorLoginTransaction.js";

export class InMemoryAuthenticatorLoginTransactionRepository {
	private readonly transactions = new Map<string, AuthenticatorLoginTransaction>();
	async create(input: Omit<AuthenticatorLoginTransaction, "createdAt" | "completedAt">): Promise<AuthenticatorLoginTransaction> {
		// Release C4.6: mirrors the Postgres repository's ON CONFLICT (provider_transaction_id) reuse --
		// a webhook/callback retry for the same providerTransactionId must reuse the existing row, never
		// create a duplicate.
		const existing = [...this.transactions.values()].find((transaction) => transaction.providerTransactionId === input.providerTransactionId);
		if (existing) {
			return { ...existing };
		}
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