import type pg from "pg";
import type { FastifyInstance } from "fastify";
import { getPostgresPool } from "../../identity/infrastructure/PostgresInfrastructure.js";
import { PostgresApplicationRepository } from "../../identity/PostgresApplicationRepository.js";
import { PostgresTenantRepository } from "../../identity/PostgresTenantRepository.js";
import { PostgresOIDCClientRepository } from "../../identity/PostgresOIDCClientRepository.js";
import { EmailVerificationService } from "../../email/EmailVerificationService.js";
import { VerificationSecrets } from "../../email/VerificationSecrets.js";
import { verificationPolicyFromEnvironment } from "../../email/VerificationPolicy.js";
import { registerEmailVerificationRoutes } from "../../routes/emailVerification.js";
import { PostgresVerificationChallengeRepository } from "./PostgresVerificationChallengeRepository.js";
import { ResendEmailDeliveryProvider } from "./resend/ResendEmailDeliveryProvider.js";
import { registerResendWebhook } from "./resend/ResendWebhookAdapter.js";

export async function configureEmailVerification(app: FastifyInstance, env = process.env): Promise<void> {
	if (!env.HAPI_EMAIL_PROVIDER) return;
	if (env.HAPI_EMAIL_PROVIDER !== "resend") throw new Error("Unsupported HAPI_EMAIL_PROVIDER");
	const requireSetting = (key: string): string => {
		if (!env[key]) throw new Error(`Missing required ${key}`);
		return env[key]!;
	};
	const secrets = new VerificationSecrets(requireSetting("HAPI_EMAIL_VERIFICATION_SECRET"));
	const policy = verificationPolicyFromEnvironment(env);
	const provider = new ResendEmailDeliveryProvider(requireSetting("RESEND_API_KEY"), requireSetting("HAPI_EMAIL_FROM"));
	const webhookSecret = env.RESEND_WEBHOOK_SECRET;
	requireSetting("DATABASE_URL");
	const repository = new PostgresVerificationChallengeRepository(getPostgresPool() as pg.Pool);
	await repository.ensureSchema();
	const service = new EmailVerificationService(repository, provider, secrets, policy);
	await registerEmailVerificationRoutes(app, service, {
		clients: new PostgresOIDCClientRepository(), applications: new PostgresApplicationRepository(), tenants: new PostgresTenantRepository()
	});
	await registerResendWebhook(app, service, webhookSecret);
}