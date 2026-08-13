import { describe, expect, it, vi } from "vitest";

import { identityService } from "../src/identity/IdentityService.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";

describe("Diagnostics routes", () => {
		it("routes /diagnostics/identityapi through identityService.health()", async () => {
			const originalFetch = global.fetch;
			const fetchMock = vi.fn().mockResolvedValue(new Response(
				JSON.stringify({
					success: true,
					requestId: "req-123",
					version: "v1",
					data: { status: "ok" }
				}),
				{
					status: 200,
					headers: { "content-type": "application/json" }
				}
			));
			global.fetch = fetchMock as typeof fetch;
			const healthSpy = vi.spyOn(identityService, "health").mockResolvedValue({
				success: true,
				requestId: "req-123",
				version: "v1",
				data: { status: "ok" }
			});

			const { app } = await buildOidcTestApp();
			try {
				const response = await app.inject({
					method: "GET",
					url: "/diagnostics/identityapi"
				});

				expect(response.statusCode).toBe(200);
				expect(healthSpy).toHaveBeenCalledTimes(1);
				expect(fetchMock).not.toHaveBeenCalled();
				expect(response.json()).toMatchObject({
					configured: true,
					authenticated: true,
					identityApiReachable: true,
					response: {
						success: true,
						data: { status: "ok" }
					}
				});
			} finally {
				healthSpy.mockRestore();
				global.fetch = originalFetch;
				await app.close();
			}
		});

		it("queries the Base44 identity API health endpoint with the configured API key", async () => {
			const originalFetch = global.fetch;
			const fetchMock = vi.fn().mockResolvedValue(new Response(
				JSON.stringify({
					success: true,
					requestId: "req-123",
					version: "v1",
					data: { status: "ok" }
				}),
				{
					status: 200,
					headers: { "content-type": "application/json" }
				}
			));
			global.fetch = fetchMock as typeof fetch;

			const { app } = await buildOidcTestApp();
			try {
				const response = await app.inject({
					method: "GET",
					url: "/diagnostics/identityapi"
				});

				expect(response.statusCode).toBe(200);
				expect(fetchMock).toHaveBeenCalledWith(
					"https://identity.example.com/api/identity",
					expect.objectContaining({
						method: "POST",
						headers: expect.objectContaining({
							Authorization: "Bearer test-key",
							"Content-Type": "application/json"
						}),
						body: JSON.stringify({ version: "v1", action: "health" })
					})
				);
				expect(response.json()).toMatchObject({
					configured: true,
					authenticated: true,
					identityApiReachable: true,
					response: {
						success: true,
						data: { status: "ok" }
					}
				});
			} finally {
				global.fetch = originalFetch;
				await app.close();
			}
		});

		it("returns the upstream authentication failure body and status without wrapping it", async () => {
			const originalFetch = global.fetch;
			const body = JSON.stringify({
				error: "Unauthorized",
				message: "Invalid identity API key"
			});
			global.fetch = vi.fn().mockResolvedValue(new Response(body, {
				status: 401,
				headers: { "content-type": "application/json" }
			})) as typeof fetch;

			const { app } = await buildOidcTestApp();
			try {
				const response = await app.inject({
					method: "GET",
					url: "/diagnostics/identityapi"
				});

				expect(response.statusCode).toBe(401);
				expect(response.json()).toMatchObject({
					configured: true,
					authenticated: false,
					identityApiReachable: false,
					response: {
						error: "Unauthorized",
						details: {
							statusCode: 401
						}
					}
				});
			} finally {
				global.fetch = originalFetch;
				await app.close();
			}
		});
		it("exposes the diagnostics and OIDC route catalog", async () => {
				const { app } = await buildOidcTestApp();
				try {
						const response = await app.inject({
								method: "GET",
								url: "/diagnostics/routes"
						});

					expect(response.statusCode).toBe(200);

					const body = response.json() as Record<string, unknown>;
					expect(body).toMatchObject({
								diagnostics: expect.arrayContaining(["/diagnostics/oidc", "/diagnostics/privateid", "/diagnostics/routes"]),
								oidc: expect.arrayContaining(["/.well-known/openid-configuration", "/authorize", "/jwks", "/userinfo", "/token"]),
								privateid: expect.arrayContaining(["/privateid/webhook", "/privateid/callback"])
					});
				} finally {
						await app.close();
				}
		});

		it("returns the PrivateID diagnostics probe", async () => {
				const { app } = await buildOidcTestApp();
				try {
						const response = await app.inject({
								method: "GET",
								url: "/diagnostics/privateid"
						});

						expect(response.statusCode).toBe(200);

						const body = response.json() as Record<string, unknown>;
						expect(body).toMatchObject({
								configuration: {
											configured: true,
											authApiConfigured: true,
											baseUrlConfigured: true,
											redirectUrlConfigured: true,
											callbackUrlConfigured: true,
											redirectOriginsConfigured: true,
											mockMode: true
								},
								privateIdReachable: true,
								authenticationSessionCreated: true,
								launchUrlReturned: true,
								launchUrl: "https://privateid.example.com/launch"
						});
				} finally {
						await app.close();
				}
		});
});
