import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { getRedisClient, oidcRedisKey, type RedisClient } from "../oidc/infrastructure/RedisInfrastructure.js";
import { FACE_SETUP_PURPOSE, FACE_SETUP_TTL_MS, FaceSetupError, type FaceSetupInteraction } from "./FaceSetupTypes.js";

const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const digest = (value: string) => createHash("sha256").update(value).digest("base64url");
const interactionSchema = z.object({
	version: z.literal(1), purpose: z.literal(FACE_SETUP_PURPOSE),
	clientId: z.string().min(1), returnUri: z.string().url(), csrf: z.string().min(1),
	phase: z.enum(["EMAIL", "CONSENT", "STARTING", "ENROLLING", "CANCELLED"]),
	createdAt: z.number().finite(), expiresAt: z.number().finite(),
	emailOperation: z.enum(["START", "VERIFY", "RESEND"]).optional(),
	email: z.object({ challengeId: z.string().min(1) }).optional(),
	authority: z.object({
		sub: z.string().min(1), clientId: z.string().min(1), authenticationMethod: z.literal("HAPI_EMAIL"),
		authenticatedAt: z.string().datetime(), expiresAt: z.number().finite(), scope: z.string()
	}).optional(),
	enrollment: z.object({
		enrollmentId: z.string().min(1), expiresAt: z.string().datetime(),
		launchUrl: z.string().url().refine(value => new URL(value).protocol === "https:")
	}).optional()
}).refine(value => value.expiresAt > value.createdAt && value.expiresAt - value.createdAt <= FACE_SETUP_TTL_MS)
	.refine(value => value.phase === "EMAIL" || Boolean(value.authority))
	.refine(value => !value.emailOperation || value.phase === "EMAIL")
	.refine(value => value.phase !== "ENROLLING" || Boolean(value.enrollment));

// Compare the complete loaded snapshot atomically; stale writers cannot undo a claim or resurrect
// deleted state. Cap persistence by Redis's existing TTL as well as the absolute application deadline.
const SAVE_SCRIPT = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local ttl = math.min(tonumber(ARGV[3]), redis.call('PTTL', KEYS[1]))
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl, 'XX')
return 1`;
const CLEAR_SCRIPT = `
local ttl = redis.call('PTTL', KEYS[1])
if ttl > 0 then redis.call('SET', KEYS[2], 'consumed', 'PX', ttl) end
return redis.call('DEL', KEYS[1])`;
const CONSUME_SCRIPT = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
${CLEAR_SCRIPT}`;

export type NewFaceSetupInteraction = Pick<FaceSetupInteraction, "clientId" | "returnUri">;
export type FaceSetupInspection = {
	state: "missing" | "invalid" | "expired" | "consumed" | "valid";
	interaction?: FaceSetupInteraction;
	remainingMs?: number;
};

export class FaceSetupInteractionStore {
	private readonly snapshots = new WeakMap<FaceSetupInteraction, string>();

	constructor(private readonly redis: RedisClient = getRedisClient(),
		private readonly ttlMs = FACE_SETUP_TTL_MS,
		private readonly clock: () => number = () => Date.now()) {}

	private async storage<T>(operation: () => Promise<T>): Promise<T> {
		try { return await operation(); }
		catch (error) {
			throw new FaceSetupError("INTERACTION_STORE_UNAVAILABLE", 503, { cause: error });
		}
	}

	async create(input: NewFaceSetupInteraction): Promise<{ handle: string; interaction: FaceSetupInteraction }> {
		const handle = randomBytes(32).toString("base64url");
		const createdAt = this.clock();
		const interaction: FaceSetupInteraction = {
			version: 1, purpose: FACE_SETUP_PURPOSE, ...input,
			csrf: randomBytes(32).toString("base64url"),
			phase: "EMAIL", createdAt, expiresAt: createdAt + this.ttlMs
		};
		const raw = JSON.stringify(interaction);
		if (await this.storage(() => this.redis.set(this.key(handle), raw, "PX", this.ttlMs, "NX")) !== "OK") {
			throw new FaceSetupError("INTERACTION_SAVE_FAILED", 503);
		}
		this.snapshots.set(interaction, raw);
		return { handle, interaction };
	}

	async inspect(handle: string | undefined): Promise<FaceSetupInspection> {
		if (!handle) return { state: "missing" };
		if (!HANDLE_PATTERN.test(handle)) return { state: "invalid" };
		const raw = await this.storage(() => this.redis.get(this.key(handle)));
		if (!raw) {
			return { state: await this.storage(() => this.redis.get(this.consumedKey(handle))) ? "consumed" : "missing" };
		}
		let parsed: unknown;
		try { parsed = JSON.parse(raw); }
		catch { return { state: "invalid" }; }
		const result = interactionSchema.safeParse(parsed);
		if (!result.success) return { state: "invalid" };
		const interaction = result.data;
		const remainingMs = interaction.expiresAt - this.clock();
		if (remainingMs <= 0) return { state: "expired", remainingMs };
		this.snapshots.set(interaction, raw);
		return { state: "valid", interaction, remainingMs };
	}

	async find(handle: string | undefined): Promise<FaceSetupInteraction | null> {
		return (await this.inspect(handle)).interaction ?? null;
	}

	async save(handle: string, interaction: FaceSetupInteraction): Promise<boolean> {
		const remaining = interaction.expiresAt - this.clock();
		const expected = this.snapshots.get(interaction);
		if (remaining <= 0 || !expected || !interactionSchema.safeParse(interaction).success) return false;
		const raw = JSON.stringify(interaction);
		const saved = await this.storage(() => this.redis.eval(SAVE_SCRIPT, 1, this.key(handle), expected, raw, Math.floor(remaining))) === 1;
		if (saved) this.snapshots.set(interaction, raw);
		return saved;
	}

	async claimConsent(handle: string, interaction: FaceSetupInteraction, decision: "agree" | "not_now"): Promise<boolean> {
		if (interaction.phase !== "CONSENT") return false;
		interaction.phase = decision === "agree" ? "STARTING" : "CANCELLED";
		return this.save(handle, interaction);
	}

	async claimEmail(handle: string, interaction: FaceSetupInteraction, operation: NonNullable<FaceSetupInteraction["emailOperation"]>): Promise<boolean> {
		if (interaction.phase !== "EMAIL" || interaction.emailOperation) return false;
		interaction.emailOperation = operation;
		return this.save(handle, interaction);
	}

	async consume(handle: string | undefined, interaction: FaceSetupInteraction): Promise<boolean> {
		const expected = this.snapshots.get(interaction);
		if (!handle || !HANDLE_PATTERN.test(handle) || !expected || interaction.expiresAt <= this.clock()) return false;
		return await this.storage(() => this.redis.eval(CONSUME_SCRIPT, 2,
			this.key(handle), this.consumedKey(handle), expected)) === 1;
	}

	async clear(handle: string | undefined): Promise<void> {
		if (!handle || !HANDLE_PATTERN.test(handle)) return;
		await this.storage(() => this.redis.eval(CLEAR_SCRIPT, 2, this.key(handle), this.consumedKey(handle)));
	}

	static csrfMatches(interaction: FaceSetupInteraction, candidate: unknown): boolean {
		if (typeof candidate !== "string" || candidate.length === 0) return false;
		return timingSafeEqual(Buffer.from(digest(candidate)), Buffer.from(digest(interaction.csrf)));
	}

	private key(handle: string): string {
		return oidcRedisKey(`face_setup_interaction:${digest(handle)}`);
	}

	private consumedKey(handle: string): string {
		return oidcRedisKey(`face_setup_consumed:${digest(handle)}`);
	}
}
