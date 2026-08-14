import type { OIDCAuthorizationCode } from "../../models/OIDCAuthorizationCode.js";
import type { OIDCLogEntry } from "../types.js";
import { getRedisClient, oidcRedisKey } from "./RedisInfrastructure.js";

type AccessTokenRecord = {
		sub: string;
		email: string;
		emailVerified: boolean;
		name: string;
		clientId: string;
		expiresAt: number;
};

type RefreshTokenRecord = {
		userId: string;
		clientId: string;
		scope: string;
		expiresAt: number;
};

export class RedisOIDCStore {
		private readonly redis = getRedisClient();

		async storeAuthorizationCode(code: Omit<OIDCAuthorizationCode, "expiresAt" | "consumed">, ttlMs: number): Promise<void> {
				const record: OIDCAuthorizationCode = {
						...code,
						expiresAt: Date.now() + ttlMs,
						consumed: false
				};

				const key = oidcRedisKey(`auth_code:${record.code}`);
				await this.redis.set(key, JSON.stringify(record), "PX", ttlMs);
		}

		async consumeAuthorizationCode(code: string): Promise<OIDCAuthorizationCode | null> {
				const key = oidcRedisKey(`auth_code:${code}`);
				const raw = await this.redis.get(key);
				if (!raw) {
						return null;
				}

				const record = JSON.parse(raw) as OIDCAuthorizationCode;
				if (record.consumed || record.expiresAt <= Date.now()) {
						await this.redis.del(key);
						return null;
				}

				record.consumed = true;
				await this.redis.set(key, JSON.stringify(record), "PX", 5_000);
				return record;
		}

		async storeAccessToken(accessToken: string, tokenRecord: Omit<AccessTokenRecord, "expiresAt">, ttlMs: number): Promise<void> {
				const record: AccessTokenRecord = {
						...tokenRecord,
						expiresAt: Date.now() + ttlMs
				};

				const key = oidcRedisKey(`access_token:${accessToken}`);
				await this.redis.set(key, JSON.stringify(record), "PX", ttlMs);
		}

		async getAccessTokenRecord(accessToken: string): Promise<AccessTokenRecord | null> {
				const key = oidcRedisKey(`access_token:${accessToken}`);
				const raw = await this.redis.get(key);
				if (!raw) {
						return null;
				}

				const record = JSON.parse(raw) as AccessTokenRecord;
				if (record.expiresAt <= Date.now()) {
						await this.redis.del(key);
						return null;
				}

				return record;
		}

		async storeRefreshToken(refreshToken: string, tokenRecord: Omit<RefreshTokenRecord, "expiresAt">, ttlMs: number): Promise<void> {
				const record: RefreshTokenRecord = {
						...tokenRecord,
						expiresAt: Date.now() + ttlMs
				};

				const key = oidcRedisKey(`refresh_token:${refreshToken}`);
				await this.redis.set(key, JSON.stringify(record), "PX", ttlMs);
		}

		async pushAuditLog(entry: OIDCLogEntry): Promise<void> {
				const key = oidcRedisKey("audit");
				await this.redis.xadd(
						key,
						"MAXLEN",
						"~",
						10_000,
						"*",
						"requestId",
						entry.requestId,
						"clientId",
						entry.clientId,
						"flow",
						entry.flow,
						"latency",
						String(entry.latency),
						"success",
						String(entry.success),
						"error",
						entry.error,
						"user",
						entry.user,
						"pkce",
						entry.pkce,
						"correlationId",
						entry.correlationId,
						"timestamp",
						new Date().toISOString()
				);
		}
}

export type { AccessTokenRecord, RefreshTokenRecord };
