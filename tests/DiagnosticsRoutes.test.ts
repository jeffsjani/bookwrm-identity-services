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
							diagnostics: expect.arrayContaining(["/diagnostics/oidc", "/diagnostics/routes"]),
							oidc: expect.arrayContaining(["/.well-known/openid-configuration", "/authorize", "/jwks", "/userinfo", "/token"])
					});
				} finally {
						await app.close();
				}
		});
});
