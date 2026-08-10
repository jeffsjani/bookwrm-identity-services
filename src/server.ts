import Fastify from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import formbody from "@fastify/formbody";

import { configuration } from "./config/ConfigurationService.js";
import { registerHealthRoutes } from "./routes/health.js";
import { registerDiagnosticsRoutes } from "./routes/diagnostics.js";
import { registerPrivateIdRoutes } from "./routes/privateid.js";
import { registerIdentityRoutes } from "./routes/identity.js";
import { oidcService } from "./oidc/OIDCService.js";
import { metricsContentType, renderMetrics } from "./oidc/infrastructure/OIDCMetrics.js";
import { closeRedisClient } from "./oidc/infrastructure/RedisInfrastructure.js";

const app = Fastify({
		logger: {
					level: configuration.getLogLevel()
		}
});

configuration.validatePrivateIdConfiguration();

// Security
await app.register(helmet);

// CORS
await app.register(cors, {
		origin: true,
		credentials: true
});

// OAuth token requests commonly use application/x-www-form-urlencoded bodies.
await app.register(formbody);

// Routes
registerHealthRoutes(app);
await registerDiagnosticsRoutes(app);
await registerPrivateIdRoutes(app);
await registerIdentityRoutes(app);
await oidcService.registerEndpoints(app);

app.get("/metrics", async (_request, reply) => {
		if (!configuration.getFeatureFlag("METRICS_ENABLED", true)) {
				reply.code(404);
				return { status: "disabled" };
		}
		reply.type(metricsContentType());
		return renderMetrics();
});

app.get("/", async () => {
		return {
				service: "Bookwrm Identity Services",
				version: "SPRINT-7.75-VERIFY",
				build: "2026-08-10-verify",
				status: "healthy",
				environment: configuration.getEnvironment()
		};
});

const port = configuration.getPort();

let shuttingDown = false;

async function shutdown(signal: NodeJS.Signals): Promise<void> {
		if (shuttingDown) {
				return;
		}

		shuttingDown = true;
		app.log.info({ signal }, "Shutting down Bookwrm Identity Services");
		try {
				await app.close();
				await closeRedisClient();
		} catch (error) {
				app.log.error(error);
		} finally {
				process.exit(0);
		}
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

try {

		await app.listen({
				host: "0.0.0.0",
				port
		});

		app.log.info(`Bookwrm Identity Services running on ${port}`);

} catch (err) {

		app.log.error(err);

		process.exit(1);

}
