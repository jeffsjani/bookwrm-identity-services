import { describe, expect, it, vi } from "vitest";

import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { identityService } from "../src/identity/IdentityService.js";
import { oidcService } from "../src/oidc/OIDCService.js";
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
								diagnostics: expect.arrayContaining(["/diagnostics/oidc/dashboard", "/diagnostics/privateid", "/diagnostics/routes"]),
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

		it("resolves claims diagnostics by provider subject", async () => {
			const identitySubject = {
				id: "identity-id",
				oidcSubject: "oidc-subject",
				primaryProvider: "PrivateID" as const,
				primaryProviderSubject: "puid-123",
				email: "user@example.com",
				emailVerified: true,
				displayName: "Example User",
				status: "ACTIVE" as const,
				createdAt: "2026-01-01T00:00:00.000Z",
				updatedAt: "2026-01-01T00:00:00.000Z"
			};
			const findByProviderSpy = vi.spyOn(identityRegistry, "findByProvider").mockResolvedValue(identitySubject);
			const findByOidcSubjectSpy = vi.spyOn(identityRegistry, "findByOidcSubject").mockResolvedValue(identitySubject);
			const claimsSnapshot = {
				identityRegistry: { sub: "oidc-subject", primaryProviderSubject: "puid-123", email: "user@example.com", emailVerified: true },
				idTokenClaims: { sub: "oidc-subject", email: "user@example.com", email_verified: true },
				userInfoClaims: { sub: "oidc-subject", email: "user@example.com", email_verified: true }
			};
			const claimsSnapshotSpy = vi.spyOn(oidcService, "getClaimsSnapshot").mockResolvedValue(claimsSnapshot);

			const { app } = await buildOidcTestApp();
			try {
				const response = await app.inject({
					method: "POST",
					url: "/diagnostics/claims",
					headers: { authorization: "Bearer test-key" },
					payload: { provider: "PrivateID", providerSubject: "puid-123" }
				});

				expect(response.statusCode).toBe(200);
				expect(findByProviderSpy).toHaveBeenCalledWith("PrivateID", "puid-123");
				expect(claimsSnapshotSpy).toHaveBeenCalledWith("oidc-subject");
				expect(response.json()).toEqual(claimsSnapshot);
			} finally {
				findByProviderSpy.mockRestore();
				findByOidcSubjectSpy.mockRestore();
				claimsSnapshotSpy.mockRestore();
				await app.close();
			}
		});
});
