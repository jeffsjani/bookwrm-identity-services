import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { ApplicationRepository } from "../identity/ApplicationRepository.js";
import type { OIDCClientRepository } from "../identity/OIDCClientRepository.js";
import type { TenantRepository } from "../identity/TenantRepository.js";
import type { RegistrationContext } from "../registration/RegistrationTypes.js";
import { RegistrationError } from "../registration/RegistrationTypes.js";
import type { RegistrationService } from "../registration/RegistrationService.js";

// Keeps H3's certified authorization policy unchanged; H2/H4 use the equivalent shared H1 helper.
export interface H1ClientAuthority {
	clients: Pick<OIDCClientRepository, "findByClientId">;
	applications: Pick<ApplicationRepository, "findById">;
	tenants: Pick<TenantRepository, "findById">;
}

async function authorize(request: FastifyRequest, authority: H1ClientAuthority): Promise<RegistrationContext> {
	const header = request.headers.authorization;
	if (!header?.startsWith("Basic ")) throw new RegistrationError("UNAUTHORIZED", 401);
	const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
	const separator = decoded.indexOf(":");
	if (separator < 1) throw new RegistrationError("UNAUTHORIZED", 401);
	let clientId: string;
	let secret: string;
	try {
		clientId = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, " "));
		secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, " "));
	} catch { throw new RegistrationError("UNAUTHORIZED", 401); }
	const client = await authority.clients.findByClientId(clientId);
	const hash = (value: string) => createHash("sha256").update(value).digest();
	const matches = timingSafeEqual(hash(secret), hash(client?.clientSecret ?? ""));
	if (!client || !client.clientSecret || client.tokenEndpointAuthMethod === "none" || !matches) throw new RegistrationError("UNAUTHORIZED", 401);
	const application = await authority.applications.findById(client.applicationId);
	const tenant = application ? await authority.tenants.findById(application.tenantId) : undefined;
	if (!application || application.status !== "active" || !tenant || tenant.status !== "active") throw new RegistrationError("UNAUTHORIZED", 401);
	return { tenantId: tenant.id, applicationId: application.id };
}

// Task 3: the request contains only the opaque verification reference -- never email/tenantId/
// emailVerified/claimSource/oidcSubject, all of which must be derived server-side from H2 evidence.
const completeSchema = z.object({ verificationId: z.string().uuid() }).strict();

export async function registerRegistrationRoutes(app: FastifyInstance, service: RegistrationService, authority: H1ClientAuthority): Promise<void> {
	await app.register(async scoped => {
		scoped.setErrorHandler((error, _request, reply) => {
			const statusCode = error instanceof Error && "statusCode" in error ? error.statusCode : undefined;
			const status = typeof statusCode === "number" && statusCode >= 400 && statusCode < 500 ? statusCode : 503;
			return reply.code(status).send({ error: "INVALID_REQUEST" });
		});
		scoped.post("/v1/registration/complete", { bodyLimit: 4096 }, async (request, reply) => {
			reply.header("Cache-Control", "no-store");
			try {
				const context = await authorize(request, authority);
				const body = completeSchema.parse(request.body);
				const outcome = await service.complete({ context, verificationId: body.verificationId });
				return { registered: outcome.registered, subject: outcome.subject, email: outcome.email, emailVerified: outcome.emailVerified };
			} catch (error) {
				if (error instanceof RegistrationError) return reply.code(error.statusCode).send({ error: error.code });
				if (error instanceof z.ZodError) return reply.code(400).send({ error: "INVALID_REQUEST" });
				return reply.code(503).send({ error: "REGISTRATION_UNAVAILABLE" });
			}
		});
	});
}
