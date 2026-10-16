import cors from "@fastify/cors";
import type { FastifyInstance } from "fastify";

export const PRODUCTION_CORS_ORIGINS = new Set([
	"https://bookwrm.com",
	"https://www.bookwrm.com",
	"https://app.base44.com",
	"https://identity.bookwrm.com"
]);

export async function registerCorsPolicy(app: FastifyInstance): Promise<void> {
	await app.register(cors, {
		origin: (origin, callback) => {
			callback(null, origin !== undefined && PRODUCTION_CORS_ORIGINS.has(origin));
		},
		credentials: true
	});
}
