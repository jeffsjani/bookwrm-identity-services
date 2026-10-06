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
import { authorizeH1Client, resolveH1ClientAuthority, type H1ClientAuthority } from "../../identity/H1ClientAuthority.js";
import type { InteractiveEmailAuthentication, InteractiveEmailAuthority } from "../../authentication/InteractiveEmailAuthentication.js";
import { PostgresEmailAuthenticationRepository } from "../../authentication/email/PostgresEmailAuthenticationRepository.js";
import { EmailAuthenticationService } from "../../authentication/email/EmailAuthenticationService.js";
import { EmailAuthenticationError } from "../../authentication/email/EmailAuthenticationTypes.js";
import type { EmailOIDCHandoff } from "../../authentication/EmailOIDCHandoff.js";
import { registerEmailAuthenticationRoutes } from "../../routes/emailAuthentication.js";

export async function configureEmailVerification(app: FastifyInstance, env = process.env): Promise<EmailOIDCHandoff | undefined> {
	if (env.HAPI_EMAIL_AUTHENTICATION_ENABLED !== undefined &&
		!["true", "false"].includes(env.HAPI_EMAIL_AUTHENTICATION_ENABLED)) {
		throw new Error("HAPI_EMAIL_AUTHENTICATION_ENABLED must be true or false");
	}
	if (env.HAPI_EMAIL_AUTHENTICATION_ENABLED === "true" && !env.HAPI_EMAIL_PROVIDER) {
		throw new Error("Email authentication requires H2 email verification");
	}
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
	const pool = getPostgresPool() as pg.Pool;
	const repository = new PostgresVerificationChallengeRepository(pool);
	await repository.ensureSchema();
	const service = new EmailVerificationService(repository, provider, secrets, policy);
	const authority = {
		clients: new PostgresOIDCClientRepository(), applications: new PostgresApplicationRepository(), tenants: new PostgresTenantRepository()
	};
	await registerEmailVerificationRoutes(app, service, authority);
	await registerResendWebhook(app, service, webhookSecret);
	const authenticationRepository = new PostgresEmailAuthenticationRepository(pool);
	await authenticationRepository.ensureSchema();
	if (env.HAPI_EMAIL_AUTHENTICATION_ENABLED !== "true") return;
	const authentication = new EmailAuthenticationService(service, repository, authenticationRepository);
	await registerEmailAuthenticationRoutes(app, authentication, authority);
	return {
		async consume(request, result, clientId) {
			const authorized = await authorizeH1Client(request, authority);
			if (authorized.clientId !== clientId) throw new EmailAuthenticationError();
			return authentication.consumeResult(authorized, result);
		},
		interactive: interactiveEmailAuthentication(authentication, authority)
	};
}

export function interactiveEmailAuthentication(authentication: EmailAuthenticationService,
	authority: H1ClientAuthority): InteractiveEmailAuthentication {
	// H4 receives exactly the H1 client authority shape it is certified with; tenantName is presentation-only.
	const h1 = ({ context, clientId }: InteractiveEmailAuthority) => ({ context, clientId });
	return {
		authority: clientId => resolveH1ClientAuthority(clientId, authority),
		start: (authorized, email) => authentication.start(h1(authorized), email),
		resend: (authorized, challengeId) => authentication.resend(h1(authorized), challengeId),
		async verify(authorized, challengeId, code) {
			const { authenticationResult } = await authentication.verify(h1(authorized), challengeId, code);
			return { authenticationResult };
		},
		consumeResult: (authorized, result) => authentication.consumeResult(h1(authorized), result)
	};
}
