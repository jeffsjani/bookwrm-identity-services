import type { FastifyInstance } from "fastify";

import { identityService } from "../identity/IdentityService.js";

export async function registerIdentityRoutes(app: FastifyInstance): Promise<void> {
		app.get("/identity/health", async () => {
				return identityService.health();
		});

		app.get("/identity/context", async () => {
				return identityService.getIdentityContext();
		});

		app.post("/identity/resolve", async () => {
				return identityService.resolveIdentity();
		});

		app.post("/identity/reverify", async () => {
				return identityService.reverify();
		});

		app.get("/identity/security-context", async () => {
				return identityService.getSecurityContext();
		});

		app.get("/identity/policies", async () => {
				return identityService.getPolicies();
		});

		app.get("/identity/timeline", async () => {
				return identityService.getTimeline();
		});

		app.get("/identity/notifications", async () => {
				return identityService.getNotifications();
		});

		app.get("/identity/trusted-devices", async () => {
				return identityService.getTrustedDevices();
		});
}