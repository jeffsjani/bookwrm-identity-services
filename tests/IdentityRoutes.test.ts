import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";

import { registerIdentityRoutes } from "../src/routes/identity.js";

describe("public identity routes", () => {
		it("continues to delegate each existing route without bridge authentication", async () => {
			const envelope = { success: true, requestId: "public-route-1", version: "v1", data: {} };
			const service = {
					health: vi.fn().mockResolvedValue(envelope),
					getIdentityContext: vi.fn().mockResolvedValue(envelope),
					resolveIdentity: vi.fn().mockResolvedValue(envelope),
					reverify: vi.fn().mockResolvedValue(envelope),
					getSecurityContext: vi.fn().mockResolvedValue(envelope),
					getPolicies: vi.fn().mockResolvedValue(envelope),
					getTimeline: vi.fn().mockResolvedValue(envelope),
					getNotifications: vi.fn().mockResolvedValue(envelope),
					getTrustedDevices: vi.fn().mockResolvedValue(envelope)
			};
			const app = Fastify();
			await registerIdentityRoutes(app, service);
			await app.ready();

			for (const [method, url, serviceMethod] of [
					["GET", "/identity/health", "health"],
					["GET", "/identity/context", "getIdentityContext"],
					["POST", "/identity/resolve", "resolveIdentity"],
					["POST", "/identity/reverify", "reverify"],
					["GET", "/identity/security-context", "getSecurityContext"],
					["GET", "/identity/policies", "getPolicies"],
					["GET", "/identity/timeline", "getTimeline"],
					["GET", "/identity/notifications", "getNotifications"],
					["GET", "/identity/trusted-devices", "getTrustedDevices"]
			] as const) {
				const response = await app.inject({ method, url });
				expect(response.statusCode).toBe(200);
				expect(response.json()).toEqual(envelope);
				expect(service[serviceMethod]).toHaveBeenCalledOnce();
			}

			await app.close();
		});
});