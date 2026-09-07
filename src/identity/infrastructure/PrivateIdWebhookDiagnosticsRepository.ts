import { getPostgresPool, type PostgresClient } from "./PostgresInfrastructure.js";
import { configuration } from "../../config/ConfigurationService.js";

type PrivateIdWebhookDiagnosticRow = {
		raw_webhook_json: unknown;
};

export type RecentPrivateIdWebhookDiagnostic = {
		receivedAt: string;
		sessionId: string;
		transactionId: string;
		status: string;
};

export class PrivateIdWebhookDiagnosticsConnectionError extends Error {}

export class PrivateIdWebhookDiagnosticsQueryError extends Error {}

function isConnectionFailure(error: unknown): boolean {
		const code = typeof error === "object" && error !== null && "code" in error
				? String(error.code)
				: "";
		return new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ETIMEDOUT", "08001", "08006", "57P01", "57P02", "57P03"]).has(code);
}

export class PrivateIdWebhookDiagnosticsRepository {
		private explicitClient?: PostgresClient;

		constructor(client?: PostgresClient) {
				this.explicitClient = client;
		}

		private get client(): PostgresClient {
				return this.explicitClient ?? (this.explicitClient = getPostgresPool());
		}

		private get configured(): boolean {
				return Boolean(this.explicitClient || configuration.get("DATABASE_URL")?.trim());
		}

		async capture(receivedAt: Date, sessionId: string, transactionId: string, rawWebhook: unknown): Promise<void> {
				if (!this.configured) {
						return;
				}

				await this.client.query(
						`INSERT INTO privateid_webhook_diagnostics
							(received_at, session_id, transaction_id, status, raw_webhook_json)
						 VALUES ($1, $2, $3, $4, $5::jsonb)
						 ON CONFLICT (session_id) DO UPDATE SET
							received_at = EXCLUDED.received_at,
							transaction_id = EXCLUDED.transaction_id,
							status = EXCLUDED.status,
							raw_webhook_json = EXCLUDED.raw_webhook_json`,
						[receivedAt, sessionId, transactionId, "SUCCESS", JSON.stringify(rawWebhook)]
				);
		}

		async findActiveBySessionId(sessionId: string): Promise<PrivateIdWebhookDiagnosticRow | undefined> {
				if (!this.configured) {
						return undefined;
				}

				const result = await this.client.query<PrivateIdWebhookDiagnosticRow>(
						`SELECT raw_webhook_json
						 FROM privateid_webhook_diagnostics
						 WHERE session_id = $1
							AND received_at >= NOW() - INTERVAL '7 days'`,
						[sessionId]
				);

				return result.rows[0];
		}

		async findRecent(): Promise<RecentPrivateIdWebhookDiagnostic[]> {
				if (!this.configured) {
						throw new PrivateIdWebhookDiagnosticsConnectionError();
				}

				let result;
				try {
						result = await this.client.query<{
							received_at: string;
							session_id: string;
							transaction_id: string;
							status: string;
						}>(
								`SELECT
									received_at,
									session_id,
									transaction_id,
									status
								 FROM privateid_webhook_diagnostics
								 ORDER BY received_at DESC
								 LIMIT 20`
						);
				} catch (error) {
						if (isConnectionFailure(error)) {
								throw new PrivateIdWebhookDiagnosticsConnectionError();
						}

						throw new PrivateIdWebhookDiagnosticsQueryError();
				}

				return result.rows.map((row) => ({
					receivedAt: row.received_at,
					sessionId: row.session_id,
					transactionId: row.transaction_id,
					status: row.status
				}));
		}
}

export const privateIdWebhookDiagnosticsRepository = new PrivateIdWebhookDiagnosticsRepository();