import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { identityService } from "../identity/IdentityService.js";
import { oidcService } from "../oidc/OIDCService.js";
import { getRedisClient } from "../oidc/infrastructure/RedisInfrastructure.js";

export async function registerHealthRoutes(app: FastifyInstance): Promise<void> {
		app.get("/health/live", async () => {
				return {
						status: "alive"
				};
		});

		app.get("/health/startup", async (_request, reply) => {
				const configurationLoaded = Boolean(configuration.getEnvironment());
				const keysLoaded = oidcService.hasSigningKeysAvailable();
				const redisInitialized = featureFlags.isRedisEnabled() ? await thisRedisPing() : true;

				if (!configurationLoaded || !keysLoaded || !redisInitialized) {
						reply.code(503);
				}

				return {
						status: "ready",
						configurationLoaded,
						keysLoaded,
						redisInitialized
				};
		});

		app.get("/health/ready", async (_request, reply) => {
				const redisHealthy = featureFlags.isRedisEnabled() ? await thisRedisPing() : true;
				const base44Healthy = await safeBoolean(() => identityService.health());
				const signingKeysLoaded = oidcService.hasSigningKeysAvailable();
				const providerReady = oidcService.isProviderReady();

				const ready = redisHealthy && base44Healthy && signingKeysLoaded && providerReady;
				if (!ready) {
						reply.code(503);
				}

				return {
						status: "ready"
				};
		});

		app.get("/health", async () => {
				return {
					status: "alive",
						service: "Bookwrm Identity Services",
						version: "6A.1",
						timestamp: new Date().toISOString(),
						uptime: process.uptime()
				};
		});
}

async function thisRedisPing(): Promise<boolean> {
		try {
				await getRedisClient().ping();
				return true;
		} catch {
				return false;
		}
}

async function safeBoolean(operation: () => Promise<unknown>): Promise<boolean> {
		try {
				await operation();
				return true;
		} catch {
			return false;
		}
}