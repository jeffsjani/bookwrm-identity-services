import Redlock from "redlock";

import { getRedisClient, oidcRedisKey } from "./RedisInfrastructure.js";

export class RedisLockService {
		private readonly redlock: Redlock;

		constructor() {
				this.redlock = new Redlock([getRedisClient()], {
					retryCount: 3,
					retryDelay: 100,
					retryJitter: 50,
					automaticExtensionThreshold: 200
				});
		}

		async withAuthorizationCodeLock<T>(code: string, fn: () => Promise<T>): Promise<T> {
				const resource = oidcRedisKey(`lock:auth_code:${code}`);
				const lock = await this.redlock.acquire([resource], 2_000);

				try {
						return await fn();
				} finally {
						await lock.release();
				}
		}
}
