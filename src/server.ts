import Fastify from "fastify";
import helmet from "@fastify/helmet";
import formbody from "@fastify/formbody";

import { configuration } from "./config/ConfigurationService.js";
import { registerHealthRoutes } from "./routes/health.js";
import { registerDiagnosticsRoutes } from "./routes/diagnostics.js";
import { registerPrivateIdRoutes } from "./routes/privateid.js";
import { registerIdentityRoutes } from "./routes/identity.js";
import { registerIdentityAdminRoutes } from "./routes/identityAdmin.js";
import { registerHapiIdentityBridgeRoutes } from "./routes/hapiIdentityBridge.js";
import { registerPrivateIDEnrollmentRoutes } from "./routes/privateidEnrollment.js";
import { registerIdentityAccountLinkRoutes } from "./routes/identityAccountLink.js";
import { registerAccountAuthenticationMethodRoutes } from "./routes/accountAuthenticationMethods.js";
import { registerAuthenticatorStatusRoutes } from "./routes/authenticatorStatus.js";
import { ensureIdentitySchema } from "./identity/infrastructure/PostgresInfrastructure.js";
import { ensureBookwrmApplicationSeed } from "./adapters/base44/Base44ApplicationSeed.js";
import { rotateStagingWebSecretAtBoot } from "./identity/StagingWebSecretRotation.js";
import { oidcService } from "./oidc/oidcServiceInstance.js";
import { metricsContentType, renderMetrics } from "./oidc/infrastructure/OIDCMetrics.js";
import { closeRedisClient } from "./oidc/infrastructure/RedisInfrastructure.js";
import { configureEmailVerification } from "./adapters/email/EmailVerificationComposition.js";
import { configureRegistration } from "./registration/RegistrationComposition.js";
import { configureFaceEnrollment } from "./authenticators/FaceEnrollmentComposition.js";
import { configureFaceSetupCeremony } from "./authenticators/FaceSetupComposition.js";
import { registerCorsPolicy } from "./security/CorsPolicy.js";
import { enforceDeploymentIssuerPin } from "./config/IssuerPolicy.js";

const app = Fastify({
		logger: {
					level: configuration.getLogLevel()
		}
});

configuration.validatePrivateIdConfiguration();

// HAPI ID V2-E Stage 1: fail closed at boot on issuer-environment misconfiguration. Non-default
// issuers (staging/canonical HAPI services) require an exact single-issuer OIDC_ALLOWED_ISSUERS
// pin and an explicit CORS_TRUSTED_ORIGINS allowlist; the default Bookwrm issuer is unchanged.
enforceDeploymentIssuerPin();

// Bootstrap the Identity Registry schema (identity_subjects, schema_migrations) before serving traffic.
// Non-fatal: a transient DB issue here surfaces via /identity/admin/health instead of blocking boot.
if (configuration.getIdentityRegistryDriver() === "postgres") {
		try {
				await ensureIdentitySchema();
		} catch (error) {
				app.log.error({ error }, "Failed to bootstrap Identity Registry schema at startup");
		}

		// HAPI ID H1: idempotently seeds Tenant #1 (Bookwrm) + Application #1 + its OIDCClient row,
		// and backfills any pre-H1 IdentitySubjects onto that Application.
		try {
				await ensureBookwrmApplicationSeed();
		} catch (error) {
				app.log.error({ error }, "Failed to seed Bookwrm Tenant/Application at startup");
		}
}

// HAPI ID V2-E Stage 3: one-time, flag-gated staging-web client-secret rotation. No-op unless
// STAGING_WEB_SECRET_ROTATION_ENABLED=true on the staging deployment (see the Stage 3 runbook §7).
// Non-fatal on failure: the old secret keeps working and the service stays up; the operator must
// verify the rotation log line (or this error) before removing the flag.
try {
		await rotateStagingWebSecretAtBoot(app.log);
} catch (error) {
		app.log.error({ error }, "STAGING-WEB SECRET ROTATION FAILED — fail closed, no change persisted; resolve the guard before retrying");
}

// Security
await app.register(helmet);

// CORS
await registerCorsPolicy(app);

// OAuth token requests commonly use application/x-www-form-urlencoded bodies.
await app.register(formbody);

// Routes
registerHealthRoutes(app);
await registerDiagnosticsRoutes(app);
const faceEnrollment = await configureFaceEnrollment(app);
await registerPrivateIdRoutes(app, faceEnrollment);
await registerIdentityRoutes(app);
await registerIdentityAdminRoutes(app);
await registerHapiIdentityBridgeRoutes(app);
await registerPrivateIDEnrollmentRoutes(app);
await registerIdentityAccountLinkRoutes(app);
// HAPI ID V2-D: authenticated account-linking API (default-off HAPI_ACCOUNT_LINKING_API_ENABLED).
await registerAccountAuthenticationMethodRoutes(app);
await registerAuthenticatorStatusRoutes(app);
const emailAuthentication = await configureEmailVerification(app);
const registration = await configureRegistration(app);
emailAuthentication?.configureRegistration(registration);
if (emailAuthentication) oidcService.configureEmailAuthentication(emailAuthentication);
await configureFaceSetupCeremony(app, faceEnrollment, emailAuthentication);
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
