import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { FaceEnrollmentError } from "../authenticators/FaceEnrollmentTypes.js";
import type { HapiFaceEnrollmentService } from "../authenticators/HapiFaceEnrollmentService.js";
import type { RedisOIDCStore } from "../oidc/infrastructure/RedisOIDCStore.js";
import { clearPrivateIDBrowserReturn, PRIVATEID_BROWSER_RETURN_COOKIE } from "../privateid/PrivateIDSessionStore.js";

export async function registerHapiFaceEnrollmentRoutes(app: FastifyInstance,
	service: Pick<HapiFaceEnrollmentService, "start" | "status">, tokens: Pick<RedisOIDCStore, "getAccessTokenRecord">): Promise<void> {
	app.get<{ Params: { enrollmentId: string } }>("/v1/authenticators/privateid/enroll/:enrollmentId/status", async (request, reply) => {
		reply.header("cache-control", "no-store");
		try {
			const authorization = request.headers.authorization;
			if (!authorization?.startsWith("Bearer ") || !authorization.slice(7).trim()) throw new FaceEnrollmentError("UNAUTHORIZED", 401);
			const token = await tokens.getAccessTokenRecord(authorization.slice(7).trim());
			if (!token) throw new FaceEnrollmentError("UNAUTHORIZED", 401);
			if (!z.string().uuid().safeParse(request.params.enrollmentId).success ||
				!z.object({}).strict().safeParse(request.query).success) throw new FaceEnrollmentError("INVALID_REQUEST", 400);
			const result = await service.status(request.params.enrollmentId, token);
			return reply.code(result.statusCode).send(result.body);
		} catch (error) {
			if (!(error instanceof FaceEnrollmentError)) {
				app.log.error({ event: "hapi_face_enrollment_status_failed" }, "HAPI Face enrollment status unavailable");
				return reply.code(503).send({ error: "ENROLLMENT_STATUS_UNAVAILABLE" });
			}
			return reply.code(error.statusCode).send({ error: error.code });
		}
	});
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
			const result = await service.start(token);
			clearPrivateIDBrowserReturn(request.headers.cookie);
			reply.header("Set-Cookie", `${PRIVATEID_BROWSER_RETURN_COOKIE}=; Path=/privateid/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
			return result;
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
