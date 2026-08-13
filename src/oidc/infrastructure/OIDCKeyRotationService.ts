import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";

import { configuration } from "../../config/ConfigurationService.js";
import { oidcRedisKey, getRedisClient } from "./RedisInfrastructure.js";

type KeyRecord = {
		privateJwk: JsonWebKey;
		publicJwk: JsonWebKey;
		kid: string;
};

export class OIDCKeyRotationService {
		private readonly redis = getRedisClient();
		private readonly rotationIntervalSeconds = configuration.getNumber("OIDC_KEY_ROTATION_INTERVAL_SECONDS", 3600);

		private async loadConfiguredKeyRing(): Promise<KeyRecord[]> {
			const privatePemKeys = this.readPemKeysFromEnv("JWT_PRIVATE_KEY");
			if (privatePemKeys.length > 0) {
				return privatePemKeys.map((pem, index) => {
						const privateKey = createPrivateKey(pem);
						const publicKey = createPublicKey(privateKey);
						const kid = this.createKid(publicKey, index);
						const privateJwk = privateKey.export({ format: "jwk" });
						const publicJwk = publicKey.export({ format: "jwk" });
						return { privateJwk, publicJwk, kid };
				});
			}

				const rawJwks = configuration.get("OIDC_JWKS_JSON")?.trim();
			if (!rawJwks) {
				if (configuration.getEnvironment() !== "production") {
					return [this.createGeneratedKeyRecord(0)];
				}
				return [];
			}

			const parsed = JSON.parse(rawJwks) as { keys?: JsonWebKey[] };
			const keys = parsed.keys ?? [];
			return keys
				.filter((key) => typeof (key as Record<string, unknown>).d === "string")
				.map((privateJwk, index) => {
						const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
						const publicKey = createPublicKey(privateKey);
						const existingKid = (privateJwk as Record<string, unknown>).kid;
						const kid = typeof existingKid === "string" ? existingKid : this.createKid(publicKey, index);
						const publicJwk = publicKey.export({ format: "jwk" });
						return { privateJwk, publicJwk, kid };
				});
		}

		async getSigningKey(): Promise<{ privateKey: KeyObject; kid: string }> {
			const keyRing = await this.ensureKeyRing();
			const activeKid = await this.getActiveKid(keyRing);
			const active = keyRing.find((key) => key.kid === activeKid) ?? keyRing[0];

			return {
				privateKey: createPrivateKey({ key: active.privateJwk, format: "jwk" }),
				kid: active.kid
			};
		}

		async getSigningKeys(): Promise<JsonWebKey[]> {
			const keyRing = await this.ensureKeyRing();
			return keyRing.map((key) => ({
				...key.privateJwk,
				kid: key.kid,
				alg: "RS256",
				use: "sig"
			}));
		}

		async getPublicKeys(): Promise<JsonWebKey[]> {
			const keyRing = await this.ensureKeyRing();
			return keyRing.map((key) => ({
				...key.publicJwk,
				kid: key.kid,
				alg: "RS256",
				use: "sig"
			}));
		}

		private async ensureKeyRing(): Promise<KeyRecord[]> {
			const keyRing = await this.loadConfiguredKeyRing();
			if (keyRing.length === 0) {
				throw new Error("No signing keys configured for rotation");
			}

			const serialized = JSON.stringify(keyRing);
			await this.redis.set(oidcRedisKey("keys:ring"), serialized);

			if (keyRing.length > 1) {
				await this.rotateIfNeeded(keyRing);
			}

			return keyRing;
		}

		private async rotateIfNeeded(keyRing: KeyRecord[]): Promise<void> {
			const rotationKey = oidcRedisKey("keys:last_rotation_at");
			const activeKey = oidcRedisKey("keys:active_kid");
			const now = Date.now();
			const lastRotationRaw = await this.redis.get(rotationKey);
			const lastRotation = lastRotationRaw ? Number(lastRotationRaw) : 0;

			if (now - lastRotation < this.rotationIntervalSeconds * 1000) {
				if (!(await this.redis.get(activeKey))) {
					await this.redis.set(activeKey, keyRing[0].kid);
				}
				return;
			}

			const currentKid = (await this.redis.get(activeKey)) ?? keyRing[0].kid;
			const currentIndex = Math.max(
				0,
				keyRing.findIndex((key) => key.kid === currentKid)
			);
			const nextKey = keyRing[(currentIndex + 1) % keyRing.length];
			await this.redis.set(activeKey, nextKey.kid);
			await this.redis.set(rotationKey, String(now));
		}

		private async getActiveKid(keyRing: KeyRecord[]): Promise<string> {
			const active = await this.redis.get(oidcRedisKey("keys:active_kid"));
			if (active && keyRing.some((key) => key.kid === active)) {
				return active;
			}

			await this.redis.set(oidcRedisKey("keys:active_kid"), keyRing[0].kid);
			return keyRing[0].kid;
		}

		private readPemKeysFromEnv(envName: "JWT_PRIVATE_KEY"): string[] {
				const raw = configuration.get(envName)?.trim();
			if (!raw) {
				return [];
			}
			const trimmed = raw.trim();
			if (!trimmed) {
				return [];
			}
			if (trimmed.startsWith("[")) {
				const parsed = JSON.parse(trimmed) as string[];
				return parsed.map((value) => this.normalizePem(value));
			}
			const pemBlocks = trimmed.match(/-----BEGIN [^-]+-----[\s\S]+?-----END [^-]+-----/g) ?? [];
			if (pemBlocks.length > 0) {
				return pemBlocks.map((value) => this.normalizePem(value));
			}
			return [this.normalizePem(trimmed)];
		}

		private normalizePem(raw: string): string {
			return raw.replace(/\\n/g, "\n").trim();
		}

		private createGeneratedKeyRecord(index: number): KeyRecord {
			const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
			const kid = this.createKid(publicKey, index);
			const privateJwk = privateKey.export({ format: "jwk" }) as JsonWebKey;
			const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
			return { privateJwk, publicJwk, kid };
		}

		private createKid(publicKey: KeyObject, index: number): string {
			const der = publicKey.export({ type: "spki", format: "der" });
			const fingerprint = createHash("sha256").update(der).digest("base64url").slice(0, 16);
			return `rsa-${index + 1}-${fingerprint}`;
		}
}
