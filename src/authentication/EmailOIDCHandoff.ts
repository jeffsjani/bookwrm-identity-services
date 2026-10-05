import type { FastifyRequest } from "fastify";
import type { EmailPrincipal } from "./email/EmailAuthenticationTypes.js";

export interface EmailOIDCHandoff {
	consume(request: FastifyRequest, result: string, clientId: string): Promise<EmailPrincipal>;
}
