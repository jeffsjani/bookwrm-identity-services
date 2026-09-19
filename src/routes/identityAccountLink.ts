import crypto from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { identityAccountLinkService, IdentityAccountLinkError } from "../identity/IdentityAccountLinkService.js";

type AccountLinkBody = {
		source?: unknown;
		externalUserId?: unknown;
		oidcSubject?: unknown;
		email?: unknown;
		emailVerified?: unknown;
};

function hasValidServiceCredential(request: FastifyRequest): boolean {
		const expectedKey = configuration.getHapiPlatformServiceKey();
		const authorization = request.headers.authorization;

		if (!expectedKey || typeof authorization !== "string") {
				return false;
		}

		const match = /^Bearer ([^\s]+)$/.exec(authorization);
		if (!match) {
				return false;
		}

		const suppliedKey = Buffer.from(match[1]);
		const expectedKeyBuffer = Buffer.from(expectedKey);
		return suppliedKey.length === expectedKeyBuffer.length
				&& crypto.timingSafeEqual(suppliedKey, expectedKeyBuffer);
}

function headerUserId(userId: string | string[] | undefined): string | undefined {
		const value = Array.isArray(userId) ? userId[0] : userId;
		return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function isNonEmptyString(value: unknown): value is string {
		return typeof value === "string" && value.trim().length > 0;
}

// Internal-only: the service-authenticated Bookwrm caller is the sole trusted supplier of email/emailVerified.
// PrivateID never calls this endpoint and must never become the source of email (Release C5.1).
export async function registerIdentityAccountLinkRoutes(app: FastifyInstance): Promise<void> {
		app.post<{ Body: AccountLinkBody }>("/internal/identity/account-link", async (request, reply) => {
				if (!hasValidServiceCredential(request)) {
						reply.code(401);
						return { error: "unauthorized" };
				}

				const body = request.body ?? {};
				if (body.source !== "bookwrm") {
						reply.code(400);
						return { error: "invalid_request", error_description: "source must be \"bookwrm\"" };
				}

				// externalUserId is derived from the trusted principal header, never trusted from the JSON body
				// alone -- a mismatched body value is rejected rather than silently overridden.
				const principalUserId = headerUserId(request.headers["x-bookwrm-user-id"]);
				if (!principalUserId) {
						reply.code(400);
						return { error: "invalid_request", error_description: "authenticated user context is required" };
				}

				if (body.externalUserId !== undefined && body.externalUserId !== principalUserId) {
						reply.code(400);
						return { error: "invalid_request", error_description: "externalUserId must match the authenticated principal" };
				}

				if (!isNonEmptyString(body.oidcSubject)) {
						reply.code(400);
						return { error: "invalid_request", error_description: "oidcSubject is required" };
				}

				if (body.email !== undefined && !isNonEmptyString(body.email)) {
						reply.code(400);
						return { error: "invalid_request", error_description: "email must be a non-empty string when provided" };
				}

				if (body.emailVerified !== undefined && typeof body.emailVerified !== "boolean") {
						reply.code(400);
						return { error: "invalid_request", error_description: "emailVerified must be a boolean when provided" };
				}

				try {
						const result = await identityAccountLinkService.linkAccount({
								externalUserId: principalUserId,
								oidcSubject: body.oidcSubject,
								email: body.email as string | undefined,
								emailVerified: body.emailVerified as boolean | undefined
						});

						reply.code(result.created ? 201 : 200);
						return {
								link: result.link,
								subject: result.subject,
								created: result.created
						};
				} catch (error) {
						if (error instanceof IdentityAccountLinkError) {
								reply.code(error.code === "ACCOUNT_LINK_CONFLICT" ? 409 : 404);
								return { error: error.code.toLowerCase(), error_description: error.message };
						}

						throw error;
				}
		});
}
