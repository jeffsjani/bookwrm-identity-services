import type { FastifyInstance } from "fastify";

import { IdentityService, identityService } from "../identity/IdentityService.js";

type PublicIdentityService = Pick<
		IdentityService,
		"health" | "getIdentityContext" | "resolveIdentity" | "reverify" | "getSecurityContext" | "getPolicies" | "getTimeline" | "getNotifications" | "getTrustedDevices"
>;

export async function registerIdentityRoutes(app: FastifyInstance, service: PublicIdentityService = identityService): Promise<void> {
		app.get("/identity/health", async () => {
				return service.health();
		});

		app.get("/identity/context", async () => {
				return service.getIdentityContext();
		});

		app.post("/identity/resolve", async () => {
				return service.resolveIdentity();
		});

		app.post("/identity/reverify", async () => {
				return service.reverify();
		});

		app.get("/identity/security-context", async () => {
				return service.getSecurityContext();
		});

		app.get("/identity/policies", async () => {
				return service.getPolicies();
		});

		app.get("/identity/timeline", async () => {
				return service.getTimeline();
		});

		app.get("/identity/notifications", async () => {
				return service.getNotifications();
		});

		app.get("/identity/trusted-devices", async () => {
				return service.getTrustedDevices();
		});
}