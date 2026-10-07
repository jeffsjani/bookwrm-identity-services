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
import { VerificationError } from "../../email/VerificationChallenge.js";
import type { EmailOIDCHandoff } from "../../authentication/EmailOIDCHandoff.js";
import { registerEmailAuthenticationRoutes } from "../../routes/emailAuthentication.js";
import type { VerificationChallengeRepository } from "../../email/VerificationChallengeRepository.js";
import { normalizeEmail } from "../../email/EmailNormalizationService.js";
import { RegistrationError } from "../../registration/RegistrationTypes.js";
import type { RegistrationService } from "../../registration/RegistrationService.js";
import { identityRegistry, type IdentityRegistry } from "../../identity/IdentityRegistry.js";
import type { IdentitySubject } from "../../models/IdentitySubject.js";

export async function configureEmailVerification(app: FastifyInstance, env = process.env): Promise<ConfiguredEmailOIDCHandoff | undefined> {
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
	const registrationFlow: InteractiveEmailRegistration = {
		verification: service,
		challenges: repository,
		subjects: identityRegistry
	};
	return {
		async consume(request, result, clientId) {
			const authorized = await authorizeH1Client(request, authority);
			if (authorized.clientId !== clientId) throw new EmailAuthenticationError();
			return authentication.consumeResult(authorized, result);
		},
		configureRegistration(registration) {
			registrationFlow.registration = registration;
		},
		interactive: interactiveEmailAuthentication(authentication, authority, registrationFlow)
	};
}

export type ConfiguredEmailOIDCHandoff = EmailOIDCHandoff & {
	configureRegistration(registration?: RegistrationService): void;
};

export type InteractiveEmailRegistration = {
	verification: EmailVerificationService;
	challenges: Pick<VerificationChallengeRepository, "findById">;
	registration?: RegistrationService;
	subjects: Pick<IdentityRegistry, "findByEmail" | "findByOidcSubject" | "findByProvider">;
};

export function interactiveEmailAuthentication(authentication: EmailAuthenticationService,
	authority: H1ClientAuthority, registrationFlow?: InteractiveEmailRegistration): InteractiveEmailAuthentication {
	// H4 receives exactly the H1 client authority shape it is certified with; tenantName is presentation-only.
	const h1 = ({ context, clientId }: InteractiveEmailAuthority) => ({ context, clientId });
	return {
		authority: clientId => resolveH1ClientAuthority(clientId, authority),
		async start(authorized, email) {
			const normalizedEmail = normalizeEmail(email);
			let mode: "AUTHENTICATION" | "REGISTRATION" | "INELIGIBLE" = "AUTHENTICATION";
			if (registrationFlow?.registration) {
				const [byEmail, byProviderSubject] = await Promise.all([
					registrationFlow.subjects.findByEmail(normalizedEmail),
					registrationFlow.subjects.findByProvider("HAPI_EMAIL", normalizedEmail)
				]);
				const claimed = [...new Map([...byEmail, ...(byProviderSubject ? [byProviderSubject] : [])]
					.map(subject => [subject.id, subject])).values()];
				if (claimed.length === 0) {
					mode = "REGISTRATION";
				} else if (claimed.length !== 1 || !isEligibleEmailSubject(claimed[0], normalizedEmail, authorized.context.applicationId)) {
					mode = "INELIGIBLE";
				}
			}
			const started = mode === "REGISTRATION"
				? await registrationFlow!.verification.start(authorized.context, normalizedEmail, "REGISTRATION")
				: await authentication.start(h1(authorized), normalizedEmail);
			return { ...started, mode };
		},
		async resend(authorized, challengeId, mode) {
			if (mode === "REGISTRATION") {
				if (!registrationFlow?.registration) throw new EmailAuthenticationError();
				const challenge = await registrationFlow.challenges.findById(challengeId);
				if (!challenge || challenge.tenantId !== authorized.context.tenantId ||
					challenge.applicationId !== authorized.context.applicationId || challenge.channel !== "EMAIL" ||
					challenge.purpose !== "REGISTRATION") {
					throw new VerificationError("INVALID_CHALLENGE");
				}
				return registrationFlow.verification.resend(authorized.context, challengeId);
			}
			return authentication.resend(h1(authorized), challengeId);
		},
		async verify(authorized, challengeId, code, mode) {
			return verifyInteractiveEmail(authentication, authorized, challengeId, code, mode, registrationFlow);
		},
		consumeResult: (authorized, result) => authentication.consumeResult(h1(authorized), result)
	};
}

function isEligibleEmailSubject(subject: IdentitySubject | undefined,
	email: string, applicationId: string | null): subject is IdentitySubject {
	return Boolean(applicationId && subject && subject.primaryProvider === "HAPI_EMAIL" && subject.primaryProviderSubject === email &&
		subject.email === email && subject.status === "ACTIVE" && subject.emailVerified === true &&
		subject.applicationId === applicationId);
}

async function verifyInteractiveEmail(authentication: EmailAuthenticationService,
	authorized: InteractiveEmailAuthority, challengeId: string, code: string, mode: "AUTHENTICATION" | "REGISTRATION" | "INELIGIBLE",
	options?: InteractiveEmailRegistration) {
	const h1 = ({ context, clientId }: InteractiveEmailAuthority) => ({ context, clientId });
	if (mode === "REGISTRATION" && !options?.registration) throw new EmailAuthenticationError();
	if (mode === "REGISTRATION" && options?.registration) {
		const proof = await options.verification.verify(authorized.context, challengeId, code, "REGISTRATION");
		try {
			const outcome = await options.registration.complete({ context: authorized.context, verificationId: proof.verificationId });
			if (outcome.idempotentReplay) throw new EmailAuthenticationError();
			const subject = await options.subjects.findByOidcSubject(outcome.subject);
			if (!isEligibleEmailSubject(subject, outcome.email, authorized.context.applicationId)) throw new EmailAuthenticationError();
			return {
				mode: "REGISTRATION" as const,
				principal: {
					id: subject.id, sub: subject.oidcSubject, email: subject.email, emailVerified: true,
					authenticationMethod: "HAPI_EMAIL" as const, authenticatedAt: new Date().toISOString(),
					assurance: "email_otp" as const
				}
			};
		} catch (error) {
			if (error instanceof RegistrationError && error.code !== "REGISTRATION_UNAVAILABLE") {
				throw new EmailAuthenticationError();
			}
			throw error;
		}
	}
	if (mode === "INELIGIBLE" && options) {
		const proof = await options.verification.verify(authorized.context, challengeId, code, "AUTHENTICATION");
		const challenge = await options.challenges.findById(proof.verificationId);
		if (!challenge || challenge.tenantId !== authorized.context.tenantId ||
			challenge.applicationId !== authorized.context.applicationId || challenge.channel !== "EMAIL" ||
			challenge.purpose !== "AUTHENTICATION") {
			throw new EmailAuthenticationError();
		}
		await options.verification.consume(authorized.context, proof.verificationId,
			challenge.destinationNormalized, "AUTHENTICATION");
		throw new EmailAuthenticationError();
	}
	const { authenticationResult } = await authentication.verify(h1(authorized), challengeId, code);
	return { mode: "AUTHENTICATION" as const, authenticationResult };
}
