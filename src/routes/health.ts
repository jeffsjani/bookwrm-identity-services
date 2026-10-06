import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { identityService } from "../identity/IdentityService.js";
import { oidcService } from "../oidc/oidcServiceInstance.js";
import { getRedisClient } from "../oidc/infrastructure/RedisInfrastructure.js";
import { getPostgresPool } from "../identity/infrastructure/PostgresInfrastructure.js";
import { identityCircuitBreaker } from "../infrastructure/CircuitBreaker.js";
import { DependencyHealthMonitor } from "../infrastructure/DependencyHealthMonitor.js";

const DATABASE_PING_TIMEOUT_MS = 2_000;

export type ReadinessChecks = {
		configurationLoaded: () => boolean;
		redisRequired: () => boolean;
		pingRedis: () => Promise<boolean>;
		// Undefined when the identity registry is not Postgres-backed (e.g. the in-memory test driver).
		pingDatabase?: () => Promise<boolean>;
		signingKeysLoaded: () => boolean;
		providerReady: () => boolean;
		base44: DependencyHealthMonitor;
};

export function defaultReadinessChecks(app: FastifyInstance): ReadinessChecks {
		return {
				configurationLoaded: () => Boolean(configuration.getEnvironment()),
				redisRequired: () => featureFlags.isRedisEnabled(),
				pingRedis: thisRedisPing,
				pingDatabase: configuration.getIdentityRegistryDriver() === "postgres" ? pingDatabase : undefined,
				signingKeysLoaded: () => oidcService.hasSigningKeysAvailable(),
				providerReady: () => oidcService.isProviderReady(),
				// The Base44 identity platform is a relying-application adapter, not a core HAPI dependency.
				base44: new DependencyHealthMonitor({
						name: "base44",
						probe: () => identityService.health(),
						breakerState: () => identityCircuitBreaker.getSnapshot().state,
						logger: app.log
				})
		};
}

export async function registerHealthRoutes(app: FastifyInstance, checks: ReadinessChecks = defaultReadinessChecks(app)): Promise<void> {
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
				const base44 = checks.base44.observe();
				const [redisInitialized, databaseConnected] = await Promise.all([
						checks.redisRequired() ? checks.pingRedis() : Promise.resolve(true),
						checks.pingDatabase ? checks.pingDatabase() : Promise.resolve(true)
				]);
				const configurationLoaded = checks.configurationLoaded();
				const keysLoaded = checks.signingKeysLoaded();
				const providerReady = checks.providerReady();

				const ready = configurationLoaded && redisInitialized && databaseConnected && keysLoaded && providerReady;
				if (!ready) {
						reply.code(503);
				}

				return {
						status: "ready",
						configurationLoaded,
						redisInitialized,
						databaseConnected,
						keysLoaded,
						providerReady,
						dependencies: {
								base44: base44.status
						}
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

async function pingDatabase(): Promise<boolean> {
		let timer: NodeJS.Timeout | undefined;
		try {
				const timeout = new Promise<never>((_resolve, reject) => {
						timer = setTimeout(() => reject(new Error("database ping timeout")), DATABASE_PING_TIMEOUT_MS);
				});
				await Promise.race([getPostgresPool().query("SELECT 1"), timeout]);
				return true;
		} catch {
				return false;
		} finally {
				clearTimeout(timer);
		}
}