import { describe, expect, it } from "vitest";

import { buildOidcTestApp } from "./oidcTestHarness.js";

describe("Diagnostics routes", () => {
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
							oidc: expect.arrayContaining(["/.well-known/openid-configuration", "/authorize", "/jwks", "/userinfo", "/token"])
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
											redirectUrlConfigured: false,
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
