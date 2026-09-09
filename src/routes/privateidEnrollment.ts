import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { privateIDEnrollmentService } from "../identity/PrivateIDEnrollmentService.js";

function authorizationVerification(authorization: string | undefined): {
	authorizationHeaderPresent: boolean;
	bearerTokenExtracted: boolean;
	configuredKeyPresent: boolean;
	platformKeyMatches: boolean;
} {
	const authorizationHeaderPresent = Boolean(authorization);
	const bearerTokenExtracted = /^Bearer\s+\S+$/.test(authorization?.trim() ?? "");
	const configuredKeyPresent = Boolean(configuration.getHapiPlatformServiceKey()?.trim());
	const platformKeyMatches = configuredKeyPresent && bearerTokenExtracted && authorization?.trim() === `Bearer ${configuration.getHapiPlatformServiceKey()?.trim()}`;
	return { authorizationHeaderPresent, bearerTokenExtracted, configuredKeyPresent, platformKeyMatches };
}

function authenticatedUserId(userId: string | string[] | undefined): string | undefined {
	const value = Array.isArray(userId) ? userId[0] : userId;
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

// Internal-only: the service-authenticated Bookwrm caller attests the authenticated user in this header.
export async function registerPrivateIDEnrollmentRoutes(app: FastifyInstance): Promise<void> {
	app.post<{ Body: { provider?: string } }>("/internal/authenticators/enroll", async (request, reply) => {
		// TEMPORARY (Release C1.2): remove after certification. Booleans only, no sensitive values.
		const authorization = authorizationVerification(request.headers.authorization);
		const userId = authenticatedUserId(request.headers["x-bookwrm-user-id"]);
		request.log.info({
			event: "AUTHORIZATION_VERIFICATION",
			...authorization,
			bookwrmUserHeaderPresent: Boolean(request.headers["x-bookwrm-user-id"]),
			authenticatedPrincipalResolved: Boolean(userId)
		});

		if (!authorization.platformKeyMatches) {
			request.log.info({
				event: "AUTHORIZATION_REJECTED",
				reason: authorization.authorizationHeaderPresent ? "INVALID_PLATFORM_KEY" : "MISSING_AUTHORIZATION"
			});
			reply.code(401);
			return { error: "unauthorized" };
		}

		if (request.body?.provider !== "privateid") {
			request.log.info({ event: "AUTHORIZATION_REJECTED", reason: "INVALID_PROVIDER" });
			reply.code(400);
			return { error: "invalid_request", error_description: "provider must be privateid" };
		}

		if (!userId) {
			request.log.info({ event: "AUTHORIZATION_REJECTED", reason: "MISSING_USER_HEADER" });
			reply.code(400);
			return { error: "invalid_request", error_description: "authenticated user context is required" };
		}

		const { transaction, session } = await privateIDEnrollmentService.startEnrollment({ userId });
		return {
			transactionId: transaction.id,
			providerTransactionId: transaction.providerTransactionId,
			expiresAt: transaction.expiresAt,
			launchUrl: session.launchUrl
		};
	});
}