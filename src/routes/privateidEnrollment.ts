import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { privateIDEnrollmentService } from "../identity/PrivateIDEnrollmentService.js";

function isAuthorized(authorization: string | undefined): boolean {
	const expectedKey = configuration.getHapiPlatformServiceKey();
	if (!expectedKey || !authorization) {
		return false;
	}
	return authorization === `Bearer ${expectedKey}`;
}

function authenticatedUserId(userId: string | string[] | undefined): string | undefined {
	const value = Array.isArray(userId) ? userId[0] : userId;
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

// Internal-only: the service-authenticated Bookwrm caller attests the authenticated user in this header.
export async function registerPrivateIDEnrollmentRoutes(app: FastifyInstance): Promise<void> {
	app.post<{ Body: { provider?: string } }>("/internal/authenticators/enroll", async (request, reply) => {
		// TEMPORARY (Release Verification P4.9): remove after certification. Booleans only, no sensitive values.
		const platformKeyMatches = isAuthorized(request.headers.authorization);
		const userId = authenticatedUserId(request.headers["x-bookwrm-user-id"]);
		request.log.info({
			event: "ENROLL_REQUEST",
			authorizationHeaderPresent: Boolean(request.headers.authorization),
			platformKeyMatches,
			bookwrmUserHeaderPresent: Boolean(request.headers["x-bookwrm-user-id"]),
			authenticatedPrincipalResolved: Boolean(userId)
		});

		if (!platformKeyMatches) {
			request.log.info({ event: "ENROLL_REJECTED", reason: "INVALID_PLATFORM_KEY" });
			reply.code(401);
			return { error: "unauthorized" };
		}

		if (request.body?.provider !== "privateid") {
			request.log.info({ event: "ENROLL_REJECTED", reason: "INVALID_PROVIDER" });
			reply.code(400);
			return { error: "invalid_request", error_description: "provider must be privateid" };
		}

		if (!userId) {
			request.log.info({ event: "ENROLL_REJECTED", reason: "MISSING_USER_HEADER" });
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