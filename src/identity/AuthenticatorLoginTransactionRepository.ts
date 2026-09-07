import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";
import type { AuthenticatorLoginTransaction, AuthenticatorLoginTransactionStatus } from "../models/AuthenticatorLoginTransaction.js";

type Row = {
	id: string; provider: string; provider_transaction_id: string; provider_subject: string | null;
	resolved_user_id: string | null; status: string; created_at: string | Date; completed_at: string | Date | null;
};

function asIso(value: string | Date | null): string | undefined {
	return value === null ? undefined : value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function mapRow(row: Row): AuthenticatorLoginTransaction {
	return { id: row.id, provider: row.provider as AuthenticatorLoginTransaction["provider"], providerTransactionId: row.provider_transaction_id, providerSubject: row.provider_subject ?? undefined, resolvedUserId: row.resolved_user_id ?? undefined, status: row.status as AuthenticatorLoginTransactionStatus, createdAt: asIso(row.created_at) as string, completedAt: asIso(row.completed_at) };
}

export class AuthenticatorLoginTransactionRepository {
	private explicitClient?: PostgresClient;
	constructor(client?: PostgresClient) { this.explicitClient = client; }
	private get client(): PostgresClient { return this.explicitClient ?? (this.explicitClient = getPostgresPool()); }

	async create(transaction: Omit<AuthenticatorLoginTransaction, "createdAt" | "completedAt">): Promise<AuthenticatorLoginTransaction> {
		const result = await this.client.query<Row>(
			`INSERT INTO authenticator_login_transactions (id, provider, provider_transaction_id, provider_subject, resolved_user_id, status, created_at, completed_at)
			 VALUES ($1, $2, $3, NULL, NULL, $4, $5, NULL) RETURNING *`,
			[transaction.id, transaction.provider, transaction.providerTransactionId, transaction.status, new Date()]
		);
		return mapRow(result.rows[0]);
	}

	async complete(id: string, status: AuthenticatorLoginTransactionStatus, providerSubject?: string, resolvedUserId?: string): Promise<AuthenticatorLoginTransaction | undefined> {
		const result = await this.client.query<Row>(
			`UPDATE authenticator_login_transactions SET status = $2, provider_subject = $3, resolved_user_id = $4, completed_at = $5 WHERE id = $1 RETURNING *`,
			[id, status, providerSubject ?? null, resolvedUserId ?? null, new Date()]
		);
		return result.rows[0] ? mapRow(result.rows[0]) : undefined;
	}
}