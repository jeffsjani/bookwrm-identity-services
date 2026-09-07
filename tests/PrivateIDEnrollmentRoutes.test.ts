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
			url: "/internal/privateid/enrollment",
			payload: { userId: "not-trusted-without-service-auth" }
		});

		expect(response.statusCode).toBe(401);
		await app.close();
	});
});