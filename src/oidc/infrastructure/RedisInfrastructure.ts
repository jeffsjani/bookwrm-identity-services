import IORedisModule from "ioredis";
import RedisMock from "ioredis-mock";

import { configuration } from "../../config/ConfigurationService.js";

const IORedis = IORedisModule as unknown as {
		new (...args: unknown[]): unknown;
};

export interface RedisClient {
		set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
		get(key: string): Promise<string | null>;
		del(...keys: string[]): Promise<number>;
		expire(key: string, seconds: number): Promise<number>;
		incr(key: string): Promise<number>;
		ping(): Promise<string>;
		quit(): Promise<string>;
		xadd(key: string, ...args: Array<string | number>): Promise<unknown>;
		hset(key: string, field: string, value: string): Promise<number>;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
		if (!value) {
				return fallback;
		}

		const normalized = value.trim().toLowerCase();
		if (normalized === "true") {
				return true;
		}

		if (normalized === "false") {
				return false;
		}

		return fallback;
}

let redisClient: RedisClient | undefined;

function buildRedisClient(): RedisClient {
		const useRedisMock =
				parseBoolean(configuration.get("OIDC_USE_REDIS_MOCK"), false) || configuration.isTest();
		if (useRedisMock) {
				return new RedisMock() as unknown as RedisClient;
		}

		const redisUrl = configuration.get("REDIS_URL")?.trim();
		if (redisUrl && redisUrl.length > 0) {
				return new IORedis(redisUrl, {
						maxRetriesPerRequest: null,
						enableReadyCheck: true
				}) as RedisClient;
		}

		const host = configuration.get("REDIS_HOST")?.trim() || "127.0.0.1";
		const port = configuration.getNumber("REDIS_PORT", 6379);
		const password = configuration.get("REDIS_PASSWORD")?.trim();
		const tlsEnabled = parseBoolean(configuration.get("REDIS_TLS"), false);

		return new IORedis({
				host,
				port,
				password: password && password.length > 0 ? password : undefined,
				tls: tlsEnabled ? {} : undefined,
				maxRetriesPerRequest: null,
				enableReadyCheck: true
		}) as RedisClient;
}

export function getRedisClient(): RedisClient {
		if (!redisClient) {
				redisClient = buildRedisClient();
		}

		return redisClient;
}

export function oidcRedisKey(key: string): string {
		const namespace = configuration.get("OIDC_REDIS_NAMESPACE")?.trim() || "oidc";
		return `${namespace}:${key}`;
}

export async function closeRedisClient(): Promise<void> {
		if (!redisClient) {
				return;
		}

		await redisClient.quit();
		redisClient = undefined;
}
