import type { FastifyInstance } from "fastify";

import { IdentityService, identityService } from "../identity/IdentityService.js";
import { requireHapiPlatformServiceKey } from "../security/ServiceAuthentication.js";

const identityRouteOptions = { onRequest: requireHapiPlatformServiceKey };

type PublicIdentityService = Pick<
		IdentityService,
		"health" | "getIdentityContext" | "resolveIdentity" | "reverify" | "getSecurityContext" | "getPolicies" | "getTimeline" | "getNotifications" | "getTrustedDevices"
>;

export async function registerIdentityRoutes(app: FastifyInstance, service: PublicIdentityService = identityService): Promise<void> {
		app.get("/identity/health", identityRouteOptions, async () => {
				return service.health();
		});

		app.get("/identity/context", identityRouteOptions, async () => {
				return service.getIdentityContext();
		});

		app.post("/identity/resolve", identityRouteOptions, async () => {
				return service.resolveIdentity();
		});

		app.post("/identity/reverify", identityRouteOptions, async () => {
				return service.reverify();
		});

		app.get("/identity/security-context", identityRouteOptions, async () => {
				return service.getSecurityContext();
		});

		app.get("/identity/policies", identityRouteOptions, async () => {
				return service.getPolicies();
		});

		app.get("/identity/timeline", identityRouteOptions, async () => {
				return service.getTimeline();
		});

		app.get("/identity/notifications", identityRouteOptions, async () => {
				return service.getNotifications();
		});

		app.get("/identity/trusted-devices", identityRouteOptions, async () => {
				return service.getTrustedDevices();
		});
}