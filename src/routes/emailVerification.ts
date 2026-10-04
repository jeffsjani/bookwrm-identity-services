import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { ApplicationRepository } from "../identity/ApplicationRepository.js";
import type { OIDCClientRepository } from "../identity/OIDCClientRepository.js";
import type { TenantRepository } from "../identity/TenantRepository.js";
import type { EmailVerificationService } from "../email/EmailVerificationService.js";
import { VerificationError, verificationPurposes, type VerificationContext } from "../email/VerificationChallenge.js";

export interface EmailClientAuthority {
	clients: Pick<OIDCClientRepository, "findByClientId">;
	applications: Pick<ApplicationRepository, "findById">;
	tenants: Pick<TenantRepository, "findById">;
}

async function authorize(request: FastifyRequest, authority: EmailClientAuthority): Promise<VerificationContext> {
	const header = request.headers.authorization;
	if (!header?.startsWith("Basic ")) throw new VerificationError("UNAUTHORIZED", 401);
	const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
	const separator = decoded.indexOf(":");
	if (separator < 1) throw new VerificationError("UNAUTHORIZED", 401);
	let clientId: string;
	let secret: string;
	try {
		clientId = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, " "));
		secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, " "));
	} catch { throw new VerificationError("UNAUTHORIZED", 401); }
	const client = await authority.clients.findByClientId(clientId);
	const hash = (value: string) => createHash("sha256").update(value).digest();
	const matches = timingSafeEqual(hash(secret), hash(client?.clientSecret ?? ""));
	if (!client || !client.clientSecret || client.tokenEndpointAuthMethod === "none" || !matches) throw new VerificationError("UNAUTHORIZED", 401);
	const application = await authority.applications.findById(client.applicationId);
	const tenant = application ? await authority.tenants.findById(application.tenantId) : undefined;
	if (!application || application.status !== "active" || !tenant || tenant.status !== "active") throw new VerificationError("UNAUTHORIZED", 401);
	return { tenantId: tenant.id, applicationId: application.id };
}

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
					const context = await authorize(request, authority);
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