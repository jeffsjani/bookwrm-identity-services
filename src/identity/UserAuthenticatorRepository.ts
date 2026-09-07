import type {
	AuthenticatorProvider,
	UserAuthenticator,
	UserAuthenticatorStatus
} from "../models/UserAuthenticator.js";
import { getPostgresPool, type PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

export type CreateUserAuthenticatorInput = Omit<
	UserAuthenticator,
	"linkedAt" | "createdAt" | "updatedAt" | "verifiedAt" | "lastUsedAt" | "revokedAt"
> & {
	linkedAt?: string;
	verifiedAt?: string;
	lastUsedAt?: string;
};

export type UpdateUserAuthenticatorInput = Partial<
	Pick<UserAuthenticator, "status" | "verifiedAt" | "lastUsedAt" | "revokedAt">
>;

type UserAuthenticatorRow = {
	id: string;
	user_id: string;
	provider: string;
	provider_subject: string;
	authenticator_type: string;
	status: string;
	linked_at: string | Date;
	verified_at: string | Date | null;
	last_used_at: string | Date | null;
	revoked_at: string | Date | null;
	created_at: string | Date;
	updated_at: string | Date;
};

function toIsoString(value: string | Date | null): string | undefined {
	if (value === null) {
		return undefined;
	}

	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toUserAuthenticator(row: UserAuthenticatorRow): UserAuthenticator {
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider as AuthenticatorProvider,
		providerSubject: row.provider_subject,
		authenticatorType: row.authenticator_type as UserAuthenticator["authenticatorType"],
		status: row.status as UserAuthenticatorStatus,
		linkedAt: toIsoString(row.linked_at) as string,
		verifiedAt: toIsoString(row.verified_at),
		lastUsedAt: toIsoString(row.last_used_at),
		revokedAt: toIsoString(row.revoked_at),
		createdAt: toIsoString(row.created_at) as string,
		updatedAt: toIsoString(row.updated_at) as string
	};
}

// Dormant persistence boundary for provider authenticators. No runtime flows use it yet.
export class UserAuthenticatorRepository {
	private explicitClient?: PostgresClient;

	constructor(client?: PostgresClient) {
		this.explicitClient = client;
	}

	private get client(): PostgresClient {
		return this.explicitClient ?? (this.explicitClient = getPostgresPool());
	}

	async findByProvider(provider: AuthenticatorProvider): Promise<UserAuthenticator[]> {
		const result = await this.client.query<UserAuthenticatorRow>(
			`SELECT * FROM user_authenticators WHERE provider = $1 ORDER BY created_at ASC`,
			[provider]
		);
		return result.rows.map(toUserAuthenticator);
	}

	async findByProviderSubject(
		provider: AuthenticatorProvider,
		providerSubject: string
	): Promise<UserAuthenticator | undefined> {
		const result = await this.client.query<UserAuthenticatorRow>(
			`SELECT * FROM user_authenticators WHERE provider = $1 AND provider_subject = $2`,
			[provider, providerSubject]
		);
		return result.rows[0] ? toUserAuthenticator(result.rows[0]) : undefined;
	}

	async findByUser(userId: string): Promise<UserAuthenticator[]> {
		const result = await this.client.query<UserAuthenticatorRow>(
			`SELECT * FROM user_authenticators WHERE user_id = $1 ORDER BY created_at ASC`,
			[userId]
		);
		return result.rows.map(toUserAuthenticator);
	}

	async create(input: CreateUserAuthenticatorInput): Promise<UserAuthenticator> {
		const now = new Date();
		const linkedAt = input.linkedAt ? new Date(input.linkedAt) : now;
		const result = await this.client.query<UserAuthenticatorRow>(
			`INSERT INTO user_authenticators
				(id, user_id, provider, provider_subject, authenticator_type, status, linked_at, verified_at, last_used_at, revoked_at, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10, $10)
			 RETURNING *`,
			[
				input.id,
				input.userId,
				input.provider,
				input.providerSubject,
				input.authenticatorType,
				input.status,
				linkedAt,
				input.verifiedAt ? new Date(input.verifiedAt) : null,
				input.lastUsedAt ? new Date(input.lastUsedAt) : null,
				now
			]
		);
		return toUserAuthenticator(result.rows[0]);
	}

	async update(id: string, changes: UpdateUserAuthenticatorInput): Promise<UserAuthenticator | undefined> {
		const fields: string[] = [];
		const values: unknown[] = [];
		const timestampChanges: Array<[keyof UpdateUserAuthenticatorInput, string]> = [
			["verifiedAt", "verified_at"],
			["lastUsedAt", "last_used_at"],
			["revokedAt", "revoked_at"]
		];

		if (changes.status !== undefined) {
			values.push(changes.status);
			fields.push(`status = $${values.length}`);
		}
		for (const [property, column] of timestampChanges) {
			if (changes[property] !== undefined) {
				values.push(new Date(changes[property] as string));
				fields.push(`${column} = $${values.length}`);
			}
		}

		if (fields.length === 0) {
			const result = await this.client.query<UserAuthenticatorRow>(`SELECT * FROM user_authenticators WHERE id = $1`, [id]);
			return result.rows[0] ? toUserAuthenticator(result.rows[0]) : undefined;
		}

		values.push(new Date());
		fields.push(`updated_at = $${values.length}`);
		values.push(id);
		const result = await this.client.query<UserAuthenticatorRow>(
			`UPDATE user_authenticators SET ${fields.join(", ")} WHERE id = $${values.length} RETURNING *`,
			values
		);
		return result.rows[0] ? toUserAuthenticator(result.rows[0]) : undefined;
	}

	async revoke(id: string): Promise<UserAuthenticator | undefined> {
		const now = new Date();
		const result = await this.client.query<UserAuthenticatorRow>(
			`UPDATE user_authenticators
			 SET status = $2, revoked_at = $3, updated_at = $3
			 WHERE id = $1
			 RETURNING *`,
			[id, "revoked", now]
		);
		return result.rows[0] ? toUserAuthenticator(result.rows[0]) : undefined;
	}
}