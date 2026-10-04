import { readFileSync } from "node:fs";
import type pg from "pg";
import type { VerificationChallenge, VerificationContext } from "../../email/VerificationChallenge.js";
import type { DeliveryEvent, VerificationAuditEvent, VerificationChallengeRepository, VerificationSnapshot } from "../../email/VerificationChallengeRepository.js";

function decode<Result>(row: Record<string, unknown>): Result {
	return Object.fromEntries(Object.entries(row).map(([key, value]) => [
		key.replace(/_([a-z])/g, (_match, character: string) => character.toUpperCase()),
		value instanceof Date ? value.toISOString() : value
	])) as Result;
}

function encode(value: object): string {
	return JSON.stringify(Object.fromEntries(Object.entries(value).map(([key, entry]) => [
		key.replace(/[A-Z]/g, character => `_${character.toLowerCase()}`), entry
	])));
}

export class PostgresVerificationChallengeRepository implements VerificationChallengeRepository {
	constructor(private readonly pool: pg.Pool) {}

	async ensureSchema(): Promise<void> {
		await this.pool.query(readFileSync(new URL("../../email/schema.sql", import.meta.url), "utf8"));
	}
	async findById(id: string): Promise<VerificationChallenge | undefined> {
		const result = await this.pool.query("SELECT * FROM verification_challenges WHERE id = $1", [id]);
		return result.rows[0] ? decode(result.rows[0]) : undefined;
	}
	async findByProviderMessageId(id: string): Promise<DeliveryEvent | undefined> {
		const result = await this.pool.query(
			"SELECT * FROM verification_delivery_events WHERE provider_message_id = $1 AND state = 'PROVIDER_ACCEPTED' LIMIT 1", [id]);
		return result.rows[0] ? decode(result.rows[0]) : undefined;
	}
	async transaction<Result>(context: VerificationContext, destinationHash: string,
		work: (snapshot: VerificationSnapshot) => Result): Promise<Result> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [JSON.stringify([context.tenantId, destinationHash])]);
			const challenges = await client.query("SELECT * FROM verification_challenges WHERE tenant_id = $1 AND destination_hash = $2 FOR UPDATE", [context.tenantId, destinationHash]);
			const delivery = await client.query("SELECT * FROM verification_delivery_events WHERE tenant_id = $1 AND destination_hash = $2", [context.tenantId, destinationHash]);
			const snapshot: VerificationSnapshot = {
				challenges: challenges.rows.map(row => decode<VerificationChallenge>(row)),
				delivery: delivery.rows.map(row => decode<DeliveryEvent>(row)), audit: []
			};
			const original = new Map(snapshot.challenges.map(challenge => [challenge.id, JSON.stringify(challenge)]));
			const existingEvents = new Set(snapshot.delivery.map(event => event.id));
			const result = work(snapshot);
			for (const challenge of snapshot.challenges) {
				if (original.get(challenge.id) === JSON.stringify(challenge)) continue;
				await client.query(
					`INSERT INTO verification_challenges SELECT * FROM jsonb_populate_record(NULL::verification_challenges, $1::jsonb)
					 ON CONFLICT (id) DO UPDATE SET
					 code_hash = EXCLUDED.code_hash, status = EXCLUDED.status, expires_at = EXCLUDED.expires_at,
					 attempt_count = EXCLUDED.attempt_count, send_count = EXCLUDED.send_count,
					 last_sent_at = EXCLUDED.last_sent_at, verified_at = EXCLUDED.verified_at,
					 consumed_at = EXCLUDED.consumed_at, updated_at = EXCLUDED.updated_at`, [encode(challenge)]);
			}
			for (const event of snapshot.delivery) {
				if (!existingEvents.has(event.id)) await this.insertEvent(client, "verification_delivery_events", event);
			}
			for (const event of snapshot.audit) await this.insertEvent(client, "email_verification_audit", event);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}
	private async insertEvent(client: pg.PoolClient, table: "verification_delivery_events" | "email_verification_audit", event: DeliveryEvent | VerificationAuditEvent) {
		await client.query(`INSERT INTO ${table} SELECT * FROM jsonb_populate_record(NULL::${table}, $1::jsonb) ON CONFLICT (id) DO NOTHING`, [encode(event)]);
	}
}