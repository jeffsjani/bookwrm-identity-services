import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import { getRedisClient, oidcRedisKey, type RedisClient } from "./infrastructure/RedisInfrastructure.js";

export const AUTHORIZATION_INTERACTION_TTL_MS = 600_000;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

// The validated GET /authorize request exactly as received; retained for audit/binding, never re-parsed.
export type AuthorizationRequestSnapshot = {
	client_id: string;
	redirect_uri: string;
	response_type: string;
	scope: string;
	state?: string;
	nonce?: string;
	code_challenge?: string;
	code_challenge_method?: string;
};

export type AuthorizationInteractionBinding = {
	tenantId: string;
	applicationId: string;
	tenantName: string;
};

export type AuthorizationInteraction = {
	version: 1;
	clientId: string;
	binding?: AuthorizationInteractionBinding;
	authorization: PendingAuthorizationContext;
	request: AuthorizationRequestSnapshot;
	csrf: string;
	createdAt: number;
	expiresAt: number;
	email?: { challengeId: string };
};

export type NewAuthorizationInteraction = Pick<AuthorizationInteraction, "clientId" | "binding" | "authorization" | "request">;

const digest = (value: string) => createHash("sha256").update(value).digest("base64url");

// Opaque, short-lived, single-use server-side record of a validated interactive authorization request.
// Only a SHA-256 of the browser handle is used as the storage key.
export class AuthorizationInteractionStore {
	constructor(private readonly redis: RedisClient = getRedisClient(),
		private readonly ttlMs = AUTHORIZATION_INTERACTION_TTL_MS,
		private readonly clock: () => number = () => Date.now()) {}

	async create(input: NewAuthorizationInteraction): Promise<{ handle: string; interaction: AuthorizationInteraction }> {
		const handle = randomBytes(32).toString("base64url");
		const createdAt = this.clock();
		const interaction: AuthorizationInteraction = {
			version: 1, ...input, csrf: randomBytes(32).toString("base64url"),
			createdAt, expiresAt: createdAt + this.ttlMs
		};
		await this.redis.set(this.key(handle), JSON.stringify(interaction), "PX", this.ttlMs, "NX");
		return { handle, interaction };
	}

	async find(handle: string | undefined): Promise<AuthorizationInteraction | null> {
		if (!handle || !HANDLE_PATTERN.test(handle)) return null;
		const raw = await this.redis.get(this.key(handle));
		if (!raw) return null;
		const interaction = JSON.parse(raw) as AuthorizationInteraction;
		if (interaction.version !== 1 || interaction.expiresAt <= this.clock()) {
			await this.redis.del(this.key(handle));
			return null;
		}
		if (await this.redis.get(this.consumedKey(handle))) return null;
		return interaction;
	}

	// Diagnostics-only, read-only probe (H6.5B): classifies why find() returned null without ever
	// mutating state. Never used for authorization decisions -- callers must keep using find()/consume().
	async inspect(handle: string | undefined): Promise<{ state: "not_found" | "expired" | "consumed" | "valid"; remainingMs?: number }> {
		if (!handle || !HANDLE_PATTERN.test(handle)) return { state: "not_found" };
		// Check the consumed marker first: consume() deletes the main key, so a stale/replayed
		// handle would otherwise be misclassified as "not_found" instead of "consumed".
		if (await this.redis.get(this.consumedKey(handle))) return { state: "consumed" };
		const raw = await this.redis.get(this.key(handle));
		if (!raw) return { state: "not_found" };
		let interaction: AuthorizationInteraction;
		try {
			interaction = JSON.parse(raw) as AuthorizationInteraction;
		} catch {
			return { state: "not_found" };
		}
		if (interaction.version !== 1) return { state: "not_found" };
		const remainingMs = interaction.expiresAt - this.clock();
		if (remainingMs <= 0) return { state: "expired", remainingMs };
		return { state: "valid", remainingMs };
	}

	// Persists step state (e.g. the H4 challenge id) without extending the original absolute expiry.
	async save(handle: string, interaction: AuthorizationInteraction): Promise<boolean> {
		const remaining = interaction.expiresAt - this.clock();
		if (remaining <= 0) return false;
		return await this.redis.set(this.key(handle), JSON.stringify(interaction), "PX", remaining, "XX") === "OK";
	}

	// Atomic single-use: exactly one caller can win the consumed marker for a handle.
	async consume(handle: string | undefined): Promise<AuthorizationInteraction | null> {
		const interaction = await this.find(handle);
		if (!interaction || !handle) return null;
		const remaining = interaction.expiresAt - this.clock();
		if (remaining <= 0) return null;
		const won = await this.redis.set(this.consumedKey(handle), "1", "PX", remaining, "NX");
		if (won !== "OK") return null;
		await this.redis.del(this.key(handle));
		return interaction;
	}

	static csrfMatches(interaction: AuthorizationInteraction, candidate: unknown): boolean {
		if (typeof candidate !== "string") return false;
		return timingSafeEqual(Buffer.from(digest(candidate)), Buffer.from(digest(interaction.csrf)));
	}

	private key(handle: string): string {
		return oidcRedisKey(`interaction:${digest(handle)}`);
	}

	private consumedKey(handle: string): string {
		return oidcRedisKey(`interaction_consumed:${digest(handle)}`);
	}
}
