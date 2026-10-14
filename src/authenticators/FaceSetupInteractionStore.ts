import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { getRedisClient, oidcRedisKey, type RedisClient } from "../oidc/infrastructure/RedisInfrastructure.js";
import { FACE_SETUP_PURPOSE, FACE_SETUP_TTL_MS, type FaceSetupInteraction } from "./FaceSetupTypes.js";

const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const digest = (value: string) => createHash("sha256").update(value).digest("base64url");

export type NewFaceSetupInteraction = Pick<FaceSetupInteraction, "clientId" | "returnUri">;

// Opaque, short-lived, single-ceremony server-side record -- mirrors AuthorizationInteractionStore's
// browser-handle model but is purpose-bound (FACE_SETUP) and never carries an OIDC authorization request.
export class FaceSetupInteractionStore {
	constructor(private readonly redis: RedisClient = getRedisClient(),
		private readonly ttlMs = FACE_SETUP_TTL_MS,
		private readonly clock: () => number = () => Date.now()) {}

	async create(input: NewFaceSetupInteraction): Promise<{ handle: string; interaction: FaceSetupInteraction }> {
		const handle = randomBytes(32).toString("base64url");
		const createdAt = this.clock();
		const interaction: FaceSetupInteraction = {
			version: 1, purpose: FACE_SETUP_PURPOSE, ...input,
			csrf: randomBytes(32).toString("base64url"),
			phase: "EMAIL", createdAt, expiresAt: createdAt + this.ttlMs
		};
		await this.redis.set(this.key(handle), JSON.stringify(interaction), "PX", this.ttlMs, "NX");
		return { handle, interaction };
	}

	async find(handle: string | undefined): Promise<FaceSetupInteraction | null> {
		if (!handle || !HANDLE_PATTERN.test(handle)) return null;
		const raw = await this.redis.get(this.key(handle));
		if (!raw) return null;
		const interaction = JSON.parse(raw) as FaceSetupInteraction;
		if (interaction.version !== 1 || interaction.purpose !== FACE_SETUP_PURPOSE || interaction.expiresAt <= this.clock()) {
			await this.redis.del(this.key(handle));
			return null;
		}
		return interaction;
	}

	// Persists step state (challenge id, authority, enrollment binding) without extending the absolute expiry.
	async save(handle: string, interaction: FaceSetupInteraction): Promise<boolean> {
		const remaining = interaction.expiresAt - this.clock();
		if (remaining <= 0) return false;
		return await this.redis.set(this.key(handle), JSON.stringify(interaction), "PX", remaining, "XX") === "OK";
	}

	async clear(handle: string | undefined): Promise<void> {
		if (!handle || !HANDLE_PATTERN.test(handle)) return;
		await this.redis.del(this.key(handle));
	}

	static csrfMatches(interaction: FaceSetupInteraction, candidate: unknown): boolean {
		if (typeof candidate !== "string" || candidate.length === 0) return false;
		return timingSafeEqual(Buffer.from(digest(candidate)), Buffer.from(digest(interaction.csrf)));
	}

	private key(handle: string): string {
		return oidcRedisKey(`face_setup_interaction:${digest(handle)}`);
	}
}
