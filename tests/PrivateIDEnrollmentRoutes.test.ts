import Fastify from "fastify";
import { describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { registerPrivateIDEnrollmentRoutes } from "../src/routes/privateidEnrollment.js";

describe("PrivateID enrollment route", () => {
	it("rejects enrollment requests that are not from the authenticated internal caller", async () => {
		process.env.HAPI_PLATFORM_SERVICE_KEY = "enrollment-service-key";
		configuration.reload();
		const app = Fastify();
		await registerPrivateIDEnrollmentRoutes(app);

		const response = await app.inject({
			method: "POST",
			url: "/internal/authenticators/enroll",
			payload: { provider: "privateid" }
		});

		expect(response.statusCode).toBe(401);
		await app.close();
	});

	it("accepts only the privateid provider request body", async () => {
		process.env.HAPI_PLATFORM_SERVICE_KEY = "enrollment-service-key";
		configuration.reload();
		const app = Fastify();
		await registerPrivateIDEnrollmentRoutes(app);

		const response = await app.inject({
			method: "POST",
			url: "/internal/authenticators/enroll",
			headers: { authorization: "Bearer enrollment-service-key", "x-bookwrm-user-id": "user-123" },
			payload: { provider: "unsupported" }
		});

		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error_description: "provider must be privateid" });
		await app.close();
	});
});
