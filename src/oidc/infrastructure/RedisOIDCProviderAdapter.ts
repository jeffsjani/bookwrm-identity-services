import { getRedisClient, oidcRedisKey } from "./RedisInfrastructure.js";

export class RedisOIDCProviderAdapter {
		private readonly redis = getRedisClient();

		async upsert(id: string, payload: unknown, expiresIn: number): Promise<void> {
				const ttlMs = Math.max(1, Math.floor(expiresIn * 1000));
				await this.redis.set(oidcRedisKey(`provider:${id}`), JSON.stringify(payload), "PX", ttlMs);
		}

		async find<T>(id: string): Promise<T | undefined> {
				const raw = await this.redis.get(oidcRedisKey(`provider:${id}`));
				if (!raw) {
						return undefined;
				}

				return JSON.parse(raw) as T;
		}

		async findByUid<T>(uid: string): Promise<T | undefined> {
				return this.find<T>(uid);
		}

		async destroy(id: string): Promise<void> {
				await this.redis.del(oidcRedisKey(`provider:${id}`));
		}

		revokeByGrantId(grantId: string): Promise<void> {
				return this.redis.del(oidcRedisKey(`provider:grant:${grantId}`)).then(() => undefined);
		}

		consume(id: string): Promise<void> {
				return this.redis.hset(oidcRedisKey(`provider:${id}:meta`), "consumed", String(Date.now())).then(() => undefined);
		}
	}
