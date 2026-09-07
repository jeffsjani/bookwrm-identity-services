import type {
	PrivateIDEnrollmentTransaction,
	PrivateIDEnrollmentTransactionStatus
} from "../models/PrivateIDEnrollmentTransaction.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

export type CreatePrivateIDEnrollmentTransactionInput = Omit<PrivateIDEnrollmentTransaction, "createdAt" | "completedAt">;

type PrivateIDEnrollmentTransactionRow = {
	id: string;
	user_id: string;
	purpose: string;
	provider_transaction_id: string;
	status: string;
	created_at: string | Date;
	expires_at: string | Date;
	completed_at: string | Date | null;
};

function toIsoString(value: string | Date | null): string | undefined {
	if (value === null) {
		return undefined;
	}
	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toEnrollmentTransaction(row: PrivateIDEnrollmentTransactionRow): PrivateIDEnrollmentTransaction {
	return {
		id: row.id,
		userId: row.user_id,
		purpose: row.purpose as PrivateIDEnrollmentTransaction["purpose"],
		providerTransactionId: row.provider_transaction_id,
		status: row.status as PrivateIDEnrollmentTransactionStatus,
		createdAt: toIsoString(row.created_at) as string,
		expiresAt: toIsoString(row.expires_at) as string,
		completedAt: toIsoString(row.completed_at)
	};
}

export class PrivateIDEnrollmentTransactionRepository {
	private explicitClient?: PostgresClient;

	constructor(client?: PostgresClient) {
		this.explicitClient = client;
	}

	private get client(): PostgresClient {
		return this.explicitClient ?? (this.explicitClient = getPostgresPool());
	}

	async create(input: CreatePrivateIDEnrollmentTransactionInput): Promise<PrivateIDEnrollmentTransaction> {
		const createdAt = new Date();
		const result = await this.client.query<PrivateIDEnrollmentTransactionRow>(
			`INSERT INTO privateid_enrollment_transactions
				(id, user_id, purpose, provider_transaction_id, status, created_at, expires_at, completed_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
			 RETURNING *`,
			[input.id, input.userId, input.purpose, input.providerTransactionId, input.status, createdAt, new Date(input.expiresAt)]
		);
		return toEnrollmentTransaction(result.rows[0]);
	}

	async findByProviderTransactionId(providerTransactionId: string): Promise<PrivateIDEnrollmentTransaction | undefined> {
		const result = await this.client.query<PrivateIDEnrollmentTransactionRow>(
			`SELECT * FROM privateid_enrollment_transactions WHERE provider_transaction_id = $1`,
			[providerTransactionId]
		);
		return result.rows[0] ? toEnrollmentTransaction(result.rows[0]) : undefined;
	}

	async updateStatus(
		id: string,
		status: PrivateIDEnrollmentTransactionStatus,
		completedAt?: Date
	): Promise<PrivateIDEnrollmentTransaction | undefined> {
		const result = await this.client.query<PrivateIDEnrollmentTransactionRow>(
			`UPDATE privateid_enrollment_transactions
			 SET status = $2, completed_at = $3
			 WHERE id = $1
			 RETURNING *`,
			[id, status, completedAt ?? null]
		);
		return result.rows[0] ? toEnrollmentTransaction(result.rows[0]) : undefined;
	}
}