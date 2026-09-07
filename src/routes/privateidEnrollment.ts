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

// Internal-only: the upstream Bookwrm service authenticates the caller and supplies its durable userId.
export async function registerPrivateIDEnrollmentRoutes(app: FastifyInstance): Promise<void> {
	app.post<{ Body: { userId?: string } }>("/internal/privateid/enrollment", async (request, reply) => {
		if (!isAuthorized(request.headers.authorization)) {
			reply.code(401);
			return { error: "unauthorized" };
		}

		const userId = request.body?.userId?.trim();
		if (!userId) {
			reply.code(400);
			return { error: "invalid_request", error_description: "userId is required" };
		}

		const { transaction, session } = await privateIDEnrollmentService.startEnrollment(userId);
		return {
			transactionId: transaction.id,
			providerTransactionId: transaction.providerTransactionId,
			expiresAt: transaction.expiresAt,
			launchUrl: session.launchUrl
		};
	});
}