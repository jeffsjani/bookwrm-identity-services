import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import { registerHealthRoutes, type ReadinessChecks } from "../src/routes/health.js";
import { DependencyHealthMonitor } from "../src/infrastructure/DependencyHealthMonitor.js";
import { ApiError } from "../src/utils/ApiError.js";

type Harness = {
		app: FastifyInstance;
		base44: DependencyHealthMonitor;
		probe: ReturnType<typeof vi.fn>;
};

const apps: FastifyInstance[] = [];

afterEach(async () => {
		await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function harness(options: {
		probe?: () => Promise<unknown>;
		breakerState?: () => string;
		now?: () => number;
		overrides?: Partial<ReadinessChecks>;
		logger?: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> };
} = {}): Promise<Harness> {
		const probe = vi.fn(options.probe ?? (async () => ({ success: true, data: { status: "healthy" } })));
		const base44 = new DependencyHealthMonitor({
				name: "base44",
				probe,
				breakerState: options.breakerState ?? (() => "closed"),
				now: options.now,
				logger: options.logger
		});
		const checks: ReadinessChecks = {
				configurationLoaded: () => true,
				redisRequired: () => true,
				pingRedis: async () => true,
				pingDatabase: async () => true,
				signingKeysLoaded: () => true,
				providerReady: () => true,
				base44,
				...options.overrides
		};
		const app = Fastify();
		apps.push(app);
		await registerHealthRoutes(app, checks);
		await app.ready();
		return { app, base44, probe };
}

async function ready(app: FastifyInstance) {
		const response = await app.inject({ method: "GET", url: "/health/ready" });
		return { statusCode: response.statusCode, body: response.json() };
}

// Readiness after the first background probe has completed.
async function readyAfterProbe(h: Harness) {
		await ready(h.app);
		await h.base44.settled();
		return ready(h.app);
}

describe("H6.2 core readiness isolation", () => {
		it("core healthy + Base44 healthy -> ready 200 and base44 healthy", async () => {
				const h = await harness();
				const result = await readyAfterProbe(h);

				expect(result.statusCode).toBe(200);
				expect(result.body).toMatchObject({
						status: "ready",
						configurationLoaded: true,
						redisInitialized: true,
						databaseConnected: true,
						keysLoaded: true,
						providerReady: true,
						dependencies: { base44: "healthy" }
				});
		});

		it("core healthy + Base44 timeout -> ready 200 and base44 degraded", async () => {
				const h = await harness({ probe: async () => { throw ApiError.timeout({ action: "health" }); } });
				const result = await readyAfterProbe(h);

				expect(result.statusCode).toBe(200);
				expect(result.body.dependencies).toEqual({ base44: "degraded" });
				expect(h.base44.getSnapshot()).toMatchObject({ status: "degraded", reason: "timeout" });
		});

		it("core healthy + Base44 circuit open -> ready 200 and base44 degraded", async () => {
				const h = await harness({
						probe: async () => { throw ApiError.internal({ message: "Circuit breaker is open" }); },
						breakerState: () => "open"
				});
				const result = await readyAfterProbe(h);

				expect(result.statusCode).toBe(200);
				expect(result.body.dependencies).toEqual({ base44: "degraded" });
				expect(h.base44.getSnapshot()).toMatchObject({ status: "degraded", reason: "circuit_open" });
		});

		it("core healthy + Base44 rejecting credentials -> ready 200 and base44 unavailable", async () => {
				const h = await harness({ probe: async () => { throw ApiError.unauthorized({ action: "health" }); } });
				const result = await readyAfterProbe(h);

				expect(result.statusCode).toBe(200);
				expect(result.body.dependencies).toEqual({ base44: "unavailable" });
		});

		it("never waits on a slow Base44 health call", async () => {
				const h = await harness({ probe: () => new Promise(() => undefined) });

				const startedAt = Date.now();
				const result = await ready(h.app);

				expect(result.statusCode).toBe(200);
				expect(result.body.dependencies).toEqual({ base44: "unknown" });
				expect(Date.now() - startedAt).toBeLessThan(1_000);
				expect(h.probe).toHaveBeenCalledTimes(1);
		});

		it("probes Base44 at most once per refresh interval, single-flight", async () => {
				let now = 1_000_000;
				const h = await harness({ now: () => now });

				await Promise.all([ready(h.app), ready(h.app), ready(h.app)]);
				await h.base44.settled();
				await ready(h.app);
				expect(h.probe).toHaveBeenCalledTimes(1);

				now += 30_000;
				await ready(h.app);
				await h.base44.settled();
				expect(h.probe).toHaveBeenCalledTimes(2);
		});

		it("logs Base44 status transitions without error details", async () => {
				const logger = { info: vi.fn(), warn: vi.fn() };
				const h = await harness({
						probe: async () => { throw ApiError.timeout({ action: "health", requestId: "r", timeoutMs: 5000 }); },
						logger
				});
				await readyAfterProbe(h);

				expect(logger.warn).toHaveBeenCalledTimes(1);
				const [fields] = logger.warn.mock.calls[0];
				expect(fields).toMatchObject({
						event: "DEPENDENCY_HEALTH_CHANGED",
						dependency: "base44",
						previousStatus: "unknown",
						status: "degraded",
						reason: "timeout"
				});
				expect(Object.keys(fields).sort()).toEqual(["dependency", "event", "latencyMs", "previousStatus", "reason", "status"]);
		});

		it("a throwing logger cannot reject the background probe", async () => {
				const logger = { info: vi.fn(), warn: vi.fn(() => { throw new Error("log sink down"); }) };
				const h = await harness({ probe: async () => { throw ApiError.timeout(); }, logger });
				const result = await readyAfterProbe(h);

				expect(result.statusCode).toBe(200);
				expect(result.body.dependencies).toEqual({ base44: "degraded" });
		});

		it("database unavailable -> ready 503", async () => {
				const h = await harness({ overrides: { pingDatabase: async () => false } });
				const result = await ready(h.app);

				expect(result.statusCode).toBe(503);
				expect(result.body.databaseConnected).toBe(false);
		});

		it("Redis unavailable while required -> ready 503", async () => {
				const h = await harness({ overrides: { pingRedis: async () => false } });
				const result = await ready(h.app);

				expect(result.statusCode).toBe(503);
				expect(result.body.redisInitialized).toBe(false);
		});

		it("Redis disabled -> Redis not required", async () => {
				const pingRedis = vi.fn(async () => false);
				const h = await harness({ overrides: { redisRequired: () => false, pingRedis } });
				const result = await ready(h.app);

				expect(result.statusCode).toBe(200);
				expect(pingRedis).not.toHaveBeenCalled();
		});

		it("signing keys unavailable -> ready 503", async () => {
				const h = await harness({ overrides: { signingKeysLoaded: () => false } });
				expect((await ready(h.app)).statusCode).toBe(503);
		});

		it("OIDC provider not ready -> ready 503", async () => {
				const h = await harness({ overrides: { providerReady: () => false } });
				expect((await ready(h.app)).statusCode).toBe(503);
		});

		it("configuration not loaded -> ready 503", async () => {
				const h = await harness({ overrides: { configurationLoaded: () => false } });
				expect((await ready(h.app)).statusCode).toBe(503);
		});

		it("core failure with Base44 healthy is still 503", async () => {
				const h = await harness({ overrides: { pingDatabase: async () => false } });
				const result = await readyAfterProbe(h);

				expect(result.statusCode).toBe(503);
				expect(result.body.dependencies).toEqual({ base44: "healthy" });
		});

		it("non-Postgres registry driver -> database not required", async () => {
				const h = await harness({ overrides: { pingDatabase: undefined } });
				const result = await ready(h.app);

				expect(result.statusCode).toBe(200);
				expect(result.body.databaseConnected).toBe(true);
		});

		it("/health, /health/live and /health/startup are unchanged and ignore Base44", async () => {
				const h = await harness({ probe: async () => { throw ApiError.timeout(); } });

				expect((await h.app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
				expect((await h.app.inject({ method: "GET", url: "/health/live" })).json()).toEqual({ status: "alive" });
				expect(h.probe).not.toHaveBeenCalled();
		});
});
