import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { getRedisClient, oidcRedisKey } from "../oidc/infrastructure/RedisInfrastructure.js";

type CacheEntry<T> = {
		value: T;
		cachedAt: number;
};

export type IdentityCacheSnapshot = {
		enabled: boolean;
		ttlSeconds: number;
		hitCount: number;
		missCount: number;
};

export class IdentityCache {
		private readonly redis = getRedisClient();
		private readonly ttlSeconds = configuration.getNumber("OIDC_CACHE_TTL_SECONDS", 60);
		private hitCount = 0;
		private missCount = 0;

		private isEnabled(): boolean {
				return featureFlags.isCacheEnabled();
		}

		async get<T>(key: string): Promise<T | undefined> {
				if (!this.isEnabled()) {
						this.missCount += 1;
						return undefined;
				}

				const raw = await this.redis.get(oidcRedisKey(`cache:${key}`));
				if (!raw) {
						this.missCount += 1;
						return undefined;
				}

				try {
						const entry = JSON.parse(raw) as CacheEntry<T>;
						this.hitCount += 1;
						return entry.value;
				} catch {
						this.missCount += 1;
						return undefined;
				}
		}

		async set<T>(key: string, value: T): Promise<void> {
				if (!this.isEnabled()) {
						return;
				}

				const entry: CacheEntry<T> = {
						value,
						cachedAt: Date.now()
				};

				await this.redis.set(
						oidcRedisKey(`cache:${key}`),
						JSON.stringify(entry),
						"PX",
						this.ttlSeconds * 1000
				);
		}

		async invalidate(key: string): Promise<void> {
				await this.redis.del(oidcRedisKey(`cache:${key}`));
		}

		async invalidatePrefix(prefix: string): Promise<void> {
				await this.redis.del(oidcRedisKey(`cache:${prefix}:identity`));
				await this.redis.del(oidcRedisKey(`cache:${prefix}:security`));
				await this.redis.del(oidcRedisKey(`cache:${prefix}:policies`));
		}

		getSnapshot(): IdentityCacheSnapshot {
				return {
					enabled: this.isEnabled(),
					ttlSeconds: this.ttlSeconds,
					hitCount: this.hitCount,
					missCount: this.missCount
				};
		}
}

export const identityCache = new IdentityCache();