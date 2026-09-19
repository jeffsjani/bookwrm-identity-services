import crypto from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticatorProvider } from "../models/UserAuthenticator.js";
import { authenticatorStatusService, AuthenticatorStatusService } from "../identity/AuthenticatorStatusService.js";

const SUPPORTED_PROVIDERS: readonly AuthenticatorProvider[] = ["privateid"];

type AuthenticatorStatusBody = {
		provider?: unknown;
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

function isSupportedProvider(value: unknown): value is AuthenticatorProvider {
		return typeof value === "string" && (SUPPORTED_PROVIDERS as readonly string[]).includes(value);
}

// Internal-only: the single authoritative surface for "is this Bookwrm account enrolled" -- Base44
// consumes this rather than learning about IdentityAccountLink/IdentitySubject/UserAuthenticator (Release C5.2).
export async function registerAuthenticatorStatusRoutes(
		app: FastifyInstance,
		service: Pick<AuthenticatorStatusService, "getStatus"> = authenticatorStatusService
): Promise<void> {
		app.post<{ Body: AuthenticatorStatusBody }>("/internal/authenticators/status", async (request, reply) => {
				if (!hasValidServiceCredential(request)) {
						reply.code(401);
						return { error: "unauthorized" };
				}

				const externalUserId = headerUserId(request.headers["x-bookwrm-user-id"]);
				if (!externalUserId) {
						reply.code(400);
						return { error: "invalid_request", error_description: "x-bookwrm-user-id header is required" };
				}

				const provider = request.body?.provider;
				if (!isSupportedProvider(provider)) {
						reply.code(400);
						return { error: "invalid_request", error_description: "provider must be one of: " + SUPPORTED_PROVIDERS.join(", ") };
				}

				const result = await service.getStatus(externalUserId, provider);
				return result;
		});
}
