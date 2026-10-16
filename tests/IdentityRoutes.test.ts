import Fastify from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { registerIdentityRoutes } from "../src/routes/identity.js";

const SERVICE_KEY = "identity-route-test-service-key";

describe("legacy identity routes", () => {
		const previousServiceKey = process.env.HAPI_PLATFORM_SERVICE_KEY;

		afterEach(() => {
				if (previousServiceKey === undefined) delete process.env.HAPI_PLATFORM_SERVICE_KEY;
				else process.env.HAPI_PLATFORM_SERVICE_KEY = previousServiceKey;
				configuration.reload();
		});

		it("requires the platform service key before delegating to the identity service", async () => {
			process.env.HAPI_PLATFORM_SERVICE_KEY = SERVICE_KEY;
			configuration.reload();
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
				const unauthorized = await app.inject({ method, url });
				expect(unauthorized.statusCode).toBe(401);
				expect(service[serviceMethod]).not.toHaveBeenCalled();

				const authorized = await app.inject({
					method,
					url,
					headers: { authorization: `Bearer ${SERVICE_KEY}` }
				});
				expect(authorized.statusCode).toBe(200);
				expect(authorized.json()).toEqual(envelope);
				expect(service[serviceMethod]).toHaveBeenCalledOnce();
			}

			await app.close();
		});

		it("fails closed if the platform service key is unset", async () => {
			delete process.env.HAPI_PLATFORM_SERVICE_KEY;
			configuration.reload();
			const service = {
				health: vi.fn().mockResolvedValue({}),
				getIdentityContext: vi.fn().mockResolvedValue({}),
				resolveIdentity: vi.fn().mockResolvedValue({}),
				reverify: vi.fn().mockResolvedValue({}),
				getSecurityContext: vi.fn().mockResolvedValue({}),
				getPolicies: vi.fn().mockResolvedValue({}),
				getTimeline: vi.fn().mockResolvedValue({}),
				getNotifications: vi.fn().mockResolvedValue({}),
				getTrustedDevices: vi.fn().mockResolvedValue({})
			};
			const app = Fastify();
			await registerIdentityRoutes(app, service);
			await app.ready();

			const response = await app.inject({
				method: "GET",
				url: "/identity/context",
				headers: { authorization: "Bearer " }
			});

			expect(response.statusCode).toBe(401);
			expect(service.getIdentityContext).not.toHaveBeenCalled();
			await app.close();
		});
});