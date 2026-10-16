import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";

import { configuration } from "../config/ConfigurationService.js";

function digest(value: string): Buffer {
	return createHash("sha256").update(value, "utf8").digest();
}

export function constantTimeStringEqual(left: string, right: string): boolean {
	return timingSafeEqual(digest(left), digest(right));
}

export function hasValidBearerServiceCredential(
	authorization: string | undefined,
	expectedKey: string | undefined
): boolean {
	if (!expectedKey?.trim() || !authorization) {
		return false;
	}

	const match = /^Bearer ([^\s]+)$/i.exec(authorization);
	return Boolean(match && constantTimeStringEqual(match[1], expectedKey));
}

export function createServiceAuthenticationHook(
	getExpectedKey: () => string | undefined,
	description: string
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
	return async (request, reply) => {
		if (hasValidBearerServiceCredential(request.headers.authorization, getExpectedKey())) {
			return;
		}

		await reply
			.code(401)
			.header("www-authenticate", "Bearer")
			.header("cache-control", "no-store")
			.send({ error: "unauthorized", error_description: description });
	};
}

export const requireHapiPlatformServiceKey = createServiceAuthenticationHook(
	() => configuration.getHapiPlatformServiceKey(),
	"Administrative service credential required"
);
