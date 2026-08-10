import type { FastifyInstance } from "fastify";

export async function registerHealthRoutes(app: FastifyInstance): Promise<void> {
		app.get("/health", async () => {
				return {
						status: "healthy",
						service: "Bookwrm Identity Services",
						version: "6A.1",
						timestamp: new Date().toISOString(),
						uptime: process.uptime()
				};
		});
}