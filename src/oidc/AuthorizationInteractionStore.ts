import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { AuthenticatedUser, PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import type { InteractiveEmailMode } from "../authentication/InteractiveEmailAuthentication.js";
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
	email?: { challengeId: string; mode: InteractiveEmailMode };
	// V2-D: a SERVER-verified federated identity awaiting explicit account resolution (create new
	// vs. sign in differently). Written only by the provider-callback handler after full JWKS,
	// issuer, audience, nonce and expiry verification -- never from any browser-supplied value.
	federation?: {
		provider: "APPLE" | "GOOGLE";
		providerIssuer: string;
		providerSubject: string;
		audience: string;
		email?: string;
		emailVerified?: boolean;
		isPrivateRelayEmail: boolean;
		evidenceReference: string;
		verifiedAt: number;
		linkExisting?: boolean;
	};
};

export type NewAuthorizationInteraction = Pick<AuthorizationInteraction, "clientId" | "binding" | "authorization" | "request">;

const digest = (value: string) => createHash("sha256").update(value).digest("base64url");
const ENROLLMENT_AUTHORITY_TTL_MS = 300_000;

type EnrollmentAuthority = {
	version: 1;
	purpose: "PASSKEY_ENROLLMENT";
	principal: AuthenticatedUser;
	browserProofHash: string;
	csrfHash: string;
	expiresAt: number;
	state: "OFFERED" | "ENROLLING" | "VERIFYING" | "SKIPPED" | "ENROLLED" | "FAILED";
	registration?: { challenge: string; userHandle: string };
};

const SAVE_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('EXISTS', KEYS[3]) ~= 0 then return 0 end
local ttl = math.min(tonumber(ARGV[2]), redis.call('PTTL', KEYS[1]))
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl, 'XX')
return 1`;

const CONSUME_SCRIPT = `
if redis.call('EXISTS', KEYS[3]) ~= 0 or redis.call('EXISTS', KEYS[2]) ~= 0 then return 0 end
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local ttl = math.min(tonumber(ARGV[2]), redis.call('PTTL', KEYS[1]))
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[2], '1', 'PX', ttl, 'NX')
redis.call('DEL', KEYS[1])
return 1`;

// Keep the authority for skip/failure recovery, but enforce its shorter lifetime atomically.
const OFFER_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('EXISTS', KEYS[3]) ~= 0 or redis.call('EXISTS', KEYS[4]) ~= 0 then return 0 end
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local ttl = math.min(tonumber(ARGV[3]), redis.call('PTTL', KEYS[1]))
local liveTtl = math.min(ttl, tonumber(ARGV[4]))
if liveTtl <= 0 then return 0 end
redis.call('SET', KEYS[3], ARGV[2], 'PX', ttl, 'NX')
redis.call('SET', KEYS[4], '1', 'PX', liveTtl, 'NX')
return 1`;

const TRANSITION_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
if ARGV[5] == '1' and redis.call('EXISTS', KEYS[4]) == 0 then return 0 end
local ttl = math.min(tonumber(ARGV[4]), redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[3]))
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[3], ARGV[3], 'PX', ttl, 'XX')
return 1`;

const FINISH_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
if ARGV[4] == '1' and redis.call('EXISTS', KEYS[4]) == 0 then return 0 end
local ttl = math.min(tonumber(ARGV[3]), redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[3]))
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[2], '1', 'PX', ttl, 'NX')
redis.call('DEL', KEYS[1], KEYS[3], KEYS[4])
return 1`;

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
		return await this.redis.eval(SAVE_SCRIPT, 3, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), JSON.stringify(interaction), Math.floor(remaining)) === 1;
	}

	// Atomic single-use: exactly one caller can win the consumed marker for a handle.
	async consume(handle: string | undefined): Promise<AuthorizationInteraction | null> {
		const interaction = await this.find(handle);
		if (!interaction || !handle) return null;
		const remaining = interaction.expiresAt - this.clock();
		if (remaining <= 0) return null;
		const won = await this.redis.eval(CONSUME_SCRIPT, 3, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), JSON.stringify(interaction), Math.floor(remaining));
		return won === 1 ? interaction : null;
	}

	// Locks the original interaction while a separately browser-bound enrollment authority exists.
	async offerPasskeyEnrollment(handle: string, interaction: AuthorizationInteraction, principal: AuthenticatedUser):
		Promise<{ browserProof: string } | null> {
		if (!HANDLE_PATTERN.test(handle) || !principal.id || !principal.sub ||
			!["HAPI_EMAIL", "APPLE", "GOOGLE"].includes(principal.authenticationMethod ?? "")) return null;
		const remaining = interaction.expiresAt - this.clock();
		if (remaining <= 0) return null;
		const browserProof = randomBytes(32).toString("base64url");
		const authority: EnrollmentAuthority = {
			version: 1, purpose: "PASSKEY_ENROLLMENT", principal,
			browserProofHash: digest(browserProof), csrfHash: digest(interaction.csrf),
			expiresAt: Math.min(interaction.expiresAt, this.clock() + ENROLLMENT_AUTHORITY_TTL_MS),
			state: "OFFERED"
		};
		const result = await this.redis.eval(OFFER_SCRIPT, 4, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), this.enrollmentLiveKey(handle), JSON.stringify(interaction),
			JSON.stringify(authority), Math.floor(remaining), Math.floor(authority.expiresAt - this.clock()));
		return result === 1 ? { browserProof } : null;
	}

	async transitionPasskeyEnrollment(handle: string, browserProof: string, csrf: string,
		subjectId: string, from: EnrollmentAuthority["state"], to: EnrollmentAuthority["state"]): Promise<boolean> {
		if (!subjectId) return false;
		const allowed = (from === "OFFERED" && (to === "SKIPPED" || to === "ENROLLING")) ||
			(from === "ENROLLING" && (to === "ENROLLED" || to === "FAILED")) ||
			(from === "VERIFYING" && (to === "ENROLLED" || to === "FAILED"));
		if (!allowed) return false;
		const loaded = await this.loadEnrollmentAuthority(handle, browserProof, csrf, subjectId, to === "FAILED");
		if (!loaded || loaded.authority.state !== from) return false;
		const updated = JSON.stringify({ ...loaded.authority, state: to });
		const result = await this.redis.eval(TRANSITION_SCRIPT, 4, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), this.enrollmentLiveKey(handle), loaded.interactionRaw, loaded.authorityRaw, updated,
			Math.floor(loaded.interaction.expiresAt - this.clock()), to === "FAILED" ? "0" : "1");
		return result === 1;
	}

	async beginPasskeyRegistration(handle: string, browserProof: string, csrf: string,
		subjectId: string, challenge: string, userHandle: string): Promise<boolean> {
		if (!HANDLE_PATTERN.test(challenge) || !HANDLE_PATTERN.test(userHandle)) return false;
		const loaded = await this.loadEnrollmentAuthority(handle, browserProof, csrf, subjectId);
		if (!loaded || loaded.authority.state !== "OFFERED") return false;
		const updated = JSON.stringify({ ...loaded.authority, state: "ENROLLING", registration: { challenge, userHandle } });
		const result = await this.redis.eval(TRANSITION_SCRIPT, 4, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), this.enrollmentLiveKey(handle), loaded.interactionRaw, loaded.authorityRaw, updated,
			Math.floor(loaded.interaction.expiresAt - this.clock()), "1");
		return result === 1;
	}

	async claimPasskeyRegistration(handle: string, browserProof: string, csrf: string, subjectId: string):
		Promise<{ principal: AuthenticatedUser; challenge: string; userHandle: string; expiresAt: number; authorityRef: string } | null> {
		const loaded = await this.loadEnrollmentAuthority(handle, browserProof, csrf, subjectId);
		if (!loaded || loaded.authority.state !== "ENROLLING" || !loaded.authority.registration) return null;
		const updated = JSON.stringify({ ...loaded.authority, state: "VERIFYING" });
		const result = await this.redis.eval(TRANSITION_SCRIPT, 4, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), this.enrollmentLiveKey(handle), loaded.interactionRaw, loaded.authorityRaw, updated,
			Math.floor(loaded.interaction.expiresAt - this.clock()), "1");
		if (result !== 1) return null;
		return { principal: loaded.authority.principal, ...loaded.authority.registration,
			expiresAt: loaded.authority.expiresAt, authorityRef: digest(handle) };
	}

	// Expiry ends enrollment, but the original browser-bound OIDC request may still be completed.
	async expirePasskeyEnrollment(handle: string, browserProof: string, csrf: string, subjectId: string): Promise<boolean> {
		if (!subjectId) return false;
		const loaded = await this.loadEnrollmentAuthority(handle, browserProof, csrf, subjectId, true);
		if (!loaded || loaded.authority.state !== "OFFERED" || loaded.authority.expiresAt > this.clock()) return false;
		const updated = JSON.stringify({ ...loaded.authority, state: "SKIPPED" });
		const result = await this.redis.eval(TRANSITION_SCRIPT, 4, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), this.enrollmentLiveKey(handle), loaded.interactionRaw, loaded.authorityRaw, updated,
			Math.floor(loaded.interaction.expiresAt - this.clock()), "0");
		return result === 1;
	}

	async finishPasskeyEnrollment(handle: string, browserProof: string, csrf: string, subjectId: string):
		Promise<{ interaction: AuthorizationInteraction; principal: AuthenticatedUser } | null> {
		if (!subjectId) return null;
		const loaded = await this.loadEnrollmentAuthority(handle, browserProof, csrf, subjectId, true);
		if (!loaded || !["SKIPPED", "ENROLLED", "FAILED"].includes(loaded.authority.state)) return null;
		if (loaded.authority.state === "ENROLLED" && loaded.authority.expiresAt <= this.clock()) return null;
		const result = await this.redis.eval(FINISH_SCRIPT, 4, this.key(handle), this.consumedKey(handle),
			this.enrollmentKey(handle), this.enrollmentLiveKey(handle), loaded.interactionRaw, loaded.authorityRaw,
			Math.floor(loaded.interaction.expiresAt - this.clock()), loaded.authority.state === "ENROLLED" ? "1" : "0");
		return result === 1 ? { interaction: loaded.interaction, principal: loaded.authority.principal } : null;
	}

	async inspectPasskeyEnrollment(handle: string, browserProof: string, csrf: string) {
		const loaded = await this.loadEnrollmentAuthority(handle, browserProof, csrf, undefined, true);
		if (!loaded) return null;
		return { principal: loaded.authority.principal, state: loaded.authority.state,
			expired: loaded.authority.expiresAt <= this.clock() };
	}

	private async loadEnrollmentAuthority(handle: string, browserProof: string, csrf: string, subjectId?: string,
		allowExpired = false) {
		if (!HANDLE_PATTERN.test(handle) || !HANDLE_PATTERN.test(browserProof) || !csrf) return null;
		const [interactionRaw, authorityRaw] = await Promise.all([
			this.redis.get(this.key(handle)), this.redis.get(this.enrollmentKey(handle))
		]);
		if (!interactionRaw || !authorityRaw) return null;
		const interaction = JSON.parse(interactionRaw) as AuthorizationInteraction;
		const authority = JSON.parse(authorityRaw) as EnrollmentAuthority;
		if (interaction.version !== 1 || authority.version !== 1 || authority.purpose !== "PASSKEY_ENROLLMENT" ||
			interaction.expiresAt <= this.clock() || (!allowExpired && authority.expiresAt <= this.clock()) ||
			(subjectId !== undefined && authority.principal.id !== subjectId) ||
			!timingSafeEqual(Buffer.from(digest(browserProof)), Buffer.from(authority.browserProofHash)) ||
			!timingSafeEqual(Buffer.from(digest(csrf)), Buffer.from(authority.csrfHash))) return null;
		return { interaction, authority, interactionRaw, authorityRaw };
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

	private enrollmentKey(handle: string): string {
		return oidcRedisKey(`interaction_passkey_enrollment:${digest(handle)}`);
	}

	private enrollmentLiveKey(handle: string): string {
		return oidcRedisKey(`interaction_passkey_enrollment_live:${digest(handle)}`);
	}
}
