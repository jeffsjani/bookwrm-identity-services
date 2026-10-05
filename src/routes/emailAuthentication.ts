import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { authorizeH1Client, type H1ClientAuthority } from "../identity/H1ClientAuthority.js";
import { VerificationError } from "../email/VerificationChallenge.js";
import type { EmailAuthenticationService } from "../authentication/email/EmailAuthenticationService.js";
import { EmailAuthenticationError } from "../authentication/email/EmailAuthenticationTypes.js";

const startSchema = z.object({ email: z.string().max(320) }).strict();
const resendSchema = z.object({ challengeId: z.string().uuid() }).strict();
const verifySchema = z.object({ challengeId: z.string().uuid(), code: z.string().max(128) }).strict();

export async function registerEmailAuthenticationRoutes(app: FastifyInstance,
	service: EmailAuthenticationService, authority: H1ClientAuthority): Promise<void> {
	await app.register(async scoped => {
		scoped.setErrorHandler((error, request, reply) => {
			reply.header("Cache-Control", "no-store");
			const statusCode = error instanceof Error && "statusCode" in error ? error.statusCode : undefined;
			const status = typeof statusCode === "number" && statusCode >= 400 && statusCode < 500
				? statusCode : 503;
			if (status === 503) request.log.error({ event: "EMAIL_AUTHENTICATION_UNAVAILABLE" }, "Email authentication failed");
			return reply.code(status).send({ error: "INVALID_REQUEST" });
		});
		for (const operation of ["start", "resend", "verify"] as const) {
			scoped.post(`/v1/authentication/email/${operation}`, { bodyLimit: 4096 }, async (request, reply) => {
				reply.header("Cache-Control", "no-store");
				try {
					const context = await authorizeH1Client(request, authority);
					if (operation === "start") return await service.start(context, startSchema.parse(request.body).email);
					if (operation === "resend") return await service.resend(context, resendSchema.parse(request.body).challengeId);
					const body = verifySchema.parse(request.body);
					return await service.verify(context, body.challengeId, body.code);
				} catch (error) {
					if (error instanceof VerificationError || error instanceof EmailAuthenticationError) {
						return reply.code(error.statusCode).send({ error: error.code });
					}
					if (error instanceof z.ZodError) return reply.code(400).send({ error: "INVALID_REQUEST" });
					request.log.error({ event: "EMAIL_AUTHENTICATION_UNAVAILABLE" }, "Email authentication failed");
					return reply.code(503).send({ error: "AUTHENTICATION_UNAVAILABLE" });
				}
			});
		}
	});
}
