import crypto from "node:crypto";

import type { FastifyInstance, FastifyRequest } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { IdentityService, identityService } from "../identity/IdentityService.js";
type HapiIdentityBridgeService = Pick<IdentityService, "getIdentityContext" | "resolveIdentity">;

type ContextRequestBody = {
		userId?: unknown;
};

type ResolveRequestBody = {
		privateIdUserId?: unknown;
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

function isNonEmptyString(value: unknown): value is string {
		return typeof value === "string" && value.trim().length > 0;
}

function sendSanitizedDownstreamError(error: unknown, reply: { code(statusCode: number): { send(payload: { error: string }): unknown } }): unknown {
		const statusCode = typeof error === "object"
				&& error !== null
				&& "statusCode" in error
				&& typeof error.statusCode === "number"
				? error.statusCode
				: 502;
		return reply.code(statusCode).send({ error: "Identity platform request failed" });
}

export async function registerHapiIdentityBridgeRoutes(
		app: FastifyInstance,
		service: HapiIdentityBridgeService = identityService
): Promise<void> {
		app.post<{ Body: ContextRequestBody }>("/internal/hapi/identity/context", async (request, reply) => {
				if (!hasValidServiceCredential(request)) {
					return reply.code(401).send({ error: "Unauthorized" });
				}

				if (!isNonEmptyString(request.body?.userId)) {
					return reply.code(400).send({ error: "Invalid request body" });
				}

				try {
					return await service.getIdentityContext(request.body.userId);
				} catch (error) {
					return sendSanitizedDownstreamError(error, reply);
				}
		});

		app.post<{ Body: ResolveRequestBody }>("/internal/hapi/identity/resolve", async (request, reply) => {
				if (!hasValidServiceCredential(request)) {
					return reply.code(401).send({ error: "Unauthorized" });
				}

				if (!isNonEmptyString(request.body?.privateIdUserId)) {
					return reply.code(400).send({ error: "Invalid request body" });
				}

				try {
					return await service.resolveIdentity(request.body.privateIdUserId);
				} catch (error) {
					return sendSanitizedDownstreamError(error, reply);
				}
		});
}