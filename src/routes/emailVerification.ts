import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { authorizeH1Client, type H1ClientAuthority } from "../identity/H1ClientAuthority.js";
import type { EmailVerificationService } from "../email/EmailVerificationService.js";
import { VerificationError, verificationPurposes } from "../email/VerificationChallenge.js";

export type EmailClientAuthority = H1ClientAuthority;

const startSchema = z.object({ email: z.string().max(320), purpose: z.enum(verificationPurposes), applicationId: z.string().uuid().optional() }).strict();
const resendSchema = z.object({ challengeId: z.string().uuid() }).strict();
const verifySchema = z.object({ challengeId: z.string().uuid(), code: z.string().max(128), purpose: z.enum(verificationPurposes).optional() }).strict();

export async function registerEmailVerificationRoutes(app: FastifyInstance, service: EmailVerificationService, authority: EmailClientAuthority): Promise<void> {
	await app.register(async scoped => {
		scoped.setErrorHandler((error, _request, reply) => {
			const statusCode = error instanceof Error && "statusCode" in error ? error.statusCode : undefined;
			const status = typeof statusCode === "number" && statusCode >= 400 && statusCode < 500 ? statusCode : 503;
			return reply.code(status).send({ error: "INVALID_REQUEST" });
		});
		for (const operation of ["start", "resend", "verify"] as const) {
			scoped.post(`/v1/identity/email/${operation}`, { bodyLimit: 4096 }, async (request, reply) => {
				reply.header("Cache-Control", "no-store");
				try {
					const { context } = await authorizeH1Client(request, authority);
					if (operation === "start") {
						const body = startSchema.parse(request.body);
						if (body.applicationId && body.applicationId !== context.applicationId) throw new VerificationError("INVALID_APPLICATION", 403);
						return await service.start(context, body.email, body.purpose);
					}
					if (operation === "resend") return await service.resend(context, resendSchema.parse(request.body).challengeId);
					const body = verifySchema.parse(request.body);
					return await service.verify(context, body.challengeId, body.code, body.purpose);
				} catch (error) {
					if (error instanceof VerificationError) return reply.code(error.statusCode).send({ error: error.code });
					if (error instanceof z.ZodError) return reply.code(400).send({ error: "INVALID_REQUEST" });
					return reply.code(503).send({ error: "VERIFICATION_UNAVAILABLE" });
				}
			});
		}
	});
}