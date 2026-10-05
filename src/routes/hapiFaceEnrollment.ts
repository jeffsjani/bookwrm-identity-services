import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { FaceEnrollmentError } from "../authenticators/FaceEnrollmentTypes.js";
import type { HapiFaceEnrollmentService } from "../authenticators/HapiFaceEnrollmentService.js";
import type { RedisOIDCStore } from "../oidc/infrastructure/RedisOIDCStore.js";

export async function registerHapiFaceEnrollmentRoutes(app: FastifyInstance,
	service: Pick<HapiFaceEnrollmentService, "start">, tokens: Pick<RedisOIDCStore, "getAccessTokenRecord">): Promise<void> {
	app.post("/v1/authenticators/privateid/enroll", async (request, reply) => {
		reply.header("cache-control", "no-store");
		try {
			const authorization = request.headers.authorization;
			if (!authorization?.startsWith("Bearer ") || !authorization.slice(7).trim()) {
				throw new FaceEnrollmentError("UNAUTHORIZED", 401);
			}
			const token = await tokens.getAccessTokenRecord(authorization.slice(7));
			if (!token) throw new FaceEnrollmentError("UNAUTHORIZED", 401);
			const body = z.object({}).strict().safeParse(request.body ?? {});
			if (!body.success) throw new FaceEnrollmentError("INVALID_REQUEST", 400);
			return await service.start(token);
		} catch (error) {
			if (!(error instanceof FaceEnrollmentError)) {
				app.log.error({ event: "hapi_face_enrollment_failed" }, "HAPI Face enrollment failed");
				throw error;
			}
			app.log.warn({ event: "hapi_face_enrollment_rejected", code: error.code }, "HAPI Face enrollment rejected");
			reply.code(error.statusCode);
			return { error: error.code };
		}
	});
}
