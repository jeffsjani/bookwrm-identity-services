import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyRequest } from "fastify";
import type { ApplicationRepository } from "./ApplicationRepository.js";
import type { OIDCClientRepository } from "./OIDCClientRepository.js";
import type { TenantRepository } from "./TenantRepository.js";
import { VerificationError, type VerificationContext } from "../email/VerificationChallenge.js";

export interface H1ClientAuthority {
	clients: Pick<OIDCClientRepository, "findByClientId">;
	applications: Pick<ApplicationRepository, "findById">;
	tenants: Pick<TenantRepository, "findById">;
}

export interface AuthorizedH1Client {
	context: VerificationContext;
	clientId: string;
}

export async function authorizeH1Client(request: FastifyRequest, authority: H1ClientAuthority): Promise<AuthorizedH1Client> {
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
	return { context: { tenantId: tenant.id, applicationId: application.id }, clientId };
}
