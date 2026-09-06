import Fastify from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../src/utils/ApiError.js";

const serviceKey = "hapi-service-key";

async function buildApp(service: {
		getIdentityContext: ReturnType<typeof vi.fn>;
		resolveIdentity: ReturnType<typeof vi.fn>;
}) {
		vi.resetModules();
		process.env.HAPI_PLATFORM_SERVICE_KEY = serviceKey;
		process.env.BOOKWRM_IDENTITY_API_KEY = "identity-platform-api-key";
		const { registerHapiIdentityBridgeRoutes } = await import("../src/routes/hapiIdentityBridge.js");
		const app = Fastify();
		await registerHapiIdentityBridgeRoutes(app, service);
		await app.ready();
		return app;
}

function authorizedHeaders() {
		return { authorization: `Bearer ${serviceKey}` };
}

afterEach(() => {
		delete process.env.HAPI_PLATFORM_SERVICE_KEY;
		delete process.env.BOOKWRM_IDENTITY_API_KEY;
		vi.restoreAllMocks();
});

describe("HAPI identity bridge routes", () => {
		it("rejects missing, malformed, and invalid service credentials with the same 401 response", async () => {
			const service = { getIdentityContext: vi.fn(), resolveIdentity: vi.fn() };
			const app = await buildApp(service);

			for (const authorization of [undefined, "Basic hapi-service-key", "Bearer wrong-key", "Bearer identity-platform-api-key"]) {
				const response = await app.inject({
						method: "POST",
						url: "/internal/hapi/identity/context",
						headers: authorization ? { authorization } : {},
						payload: { userId: "opaque-user" }
				});
				expect(response.statusCode).toBe(401);
				expect(response.json()).toEqual({ error: "Unauthorized" });
				expect(response.body).not.toContain(serviceKey);
				expect(response.body).not.toContain("identity-platform-api-key");
			}

			expect(service.getIdentityContext).not.toHaveBeenCalled();
			await app.close();
		});

		it("requires non-empty bridge request identifiers", async () => {
			const service = { getIdentityContext: vi.fn(), resolveIdentity: vi.fn() };
			const app = await buildApp(service);

			for (const [url, payload] of [
					["/internal/hapi/identity/context", {}],
					["/internal/hapi/identity/context", { userId: "  " }],
					["/internal/hapi/identity/resolve", {}],
					["/internal/hapi/identity/resolve", { privateIdUserId: "  " }]
			] as const) {
				const response = await app.inject({ method: "POST", url, headers: authorizedHeaders(), payload });
				expect(response.statusCode).toBe(400);
				expect(response.json()).toEqual({ error: "Invalid request body" });
			}

			expect(service.getIdentityContext).not.toHaveBeenCalled();
			expect(service.resolveIdentity).not.toHaveBeenCalled();
			await app.close();
		});

		it("passes an opaque userId through and returns the context envelope unchanged", async () => {
			const envelope = { success: true, requestId: "upstream-context-1", version: "v1", data: { identity: "context" } };
			const service = { getIdentityContext: vi.fn().mockResolvedValue(envelope), resolveIdentity: vi.fn() };
			const app = await buildApp(service);
			const userId = "  external/hapi:user  ";

			const response = await app.inject({
					method: "POST", url: "/internal/hapi/identity/context", headers: authorizedHeaders(), payload: { userId }
			});

			expect(response.statusCode).toBe(200);
			expect(response.json()).toEqual(envelope);
			expect(service.getIdentityContext).toHaveBeenCalledWith(userId);
			await app.close();
		});

		it("passes a PrivateID user ID through and returns the resolution envelope unchanged", async () => {
			const envelope = { success: true, requestId: "upstream-resolve-1", version: "v1", data: { identity: "resolved" } };
			const service = { getIdentityContext: vi.fn(), resolveIdentity: vi.fn().mockResolvedValue(envelope) };
			const app = await buildApp(service);
			const privateIdUserId = "privateid-user-123";

			const response = await app.inject({
					method: "POST", url: "/internal/hapi/identity/resolve", headers: authorizedHeaders(), payload: { privateIdUserId }
			});

			expect(response.statusCode).toBe(200);
			expect(response.json()).toEqual(envelope);
			expect(service.resolveIdentity).toHaveBeenCalledWith(privateIdUserId);
			await app.close();
		});

		it("sanitizes downstream errors without exposing request details or service secrets", async () => {
			const service = {
					getIdentityContext: vi.fn().mockRejectedValue(new ApiError(503, "upstream hapi-service-key failure", { secret: serviceKey })),
					resolveIdentity: vi.fn()
			};
			const app = await buildApp(service);

			const response = await app.inject({
					method: "POST", url: "/internal/hapi/identity/context", headers: authorizedHeaders(), payload: { userId: "opaque-user" }
			});

			expect(response.statusCode).toBe(503);
			expect(response.json()).toEqual({ error: "Identity platform request failed" });
			expect(response.body).not.toContain(serviceKey);
			expect(response.body).not.toContain("upstream");
			await app.close();
		});
});