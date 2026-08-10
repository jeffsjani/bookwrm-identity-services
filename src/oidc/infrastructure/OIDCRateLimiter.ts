import { getRedisClient, oidcRedisKey } from "./RedisInfrastructure.js";
import { configuration } from "../../config/ConfigurationService.js";

type LimitBucket = {
		limit: number;
		windowSeconds: number;
};

type OIDCRateLimitContext = {
		ip: string;
		clientId: string;
		userId: string;
};

const PER_IP: LimitBucket = { limit: configuration.getNumber("OIDC_RATE_LIMIT_IP", 120), windowSeconds: 60 };
const PER_CLIENT: LimitBucket = { limit: configuration.getNumber("OIDC_RATE_LIMIT_CLIENT", 300), windowSeconds: 60 };
const PER_USER: LimitBucket = { limit: configuration.getNumber("OIDC_RATE_LIMIT_USER", 180), windowSeconds: 60 };

export class OIDCRateLimiter {
		private readonly redis = getRedisClient();

		async assertWithinLimits(context: OIDCRateLimitContext): Promise<void> {
				await this.assertBucket("ip", context.ip, PER_IP);
				if (context.clientId) {
						await this.assertBucket("client", context.clientId, PER_CLIENT);
				}
				if (context.userId) {
						await this.assertBucket("user", context.userId, PER_USER);
				}
		}

		private async assertBucket(prefix: string, identifier: string, bucket: LimitBucket): Promise<void> {
				const key = oidcRedisKey(`ratelimit:${prefix}:${identifier}`);
				const count = await this.redis.incr(key);
				if (count === 1) {
						await this.redis.expire(key, bucket.windowSeconds);
				}

				if (count > bucket.limit) {
						const error = new Error(`Rate limit exceeded for ${prefix}`);
						(error as Error & { statusCode?: number }).statusCode = 429;
						throw error;
				}
		}
}
