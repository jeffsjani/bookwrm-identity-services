import type { FastifyRequest } from "fastify";
import type { EmailPrincipal } from "./email/EmailAuthenticationTypes.js";
import type { InteractiveEmailAuthentication } from "./InteractiveEmailAuthentication.js";

export interface EmailOIDCHandoff {
	consume(request: FastifyRequest, result: string, clientId: string): Promise<EmailPrincipal>;
	// H6 Universal Login: optional server-side use of the same H4 engine; absent leaves POST /authorize unchanged.
	interactive?: InteractiveEmailAuthentication;
}
