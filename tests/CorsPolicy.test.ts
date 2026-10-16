import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";

import { PRODUCTION_CORS_ORIGINS, registerCorsPolicy } from "../src/security/CorsPolicy.js";

describe("CORS production origin policy", () => {
	let app: ReturnType<typeof Fastify>;

	afterEach(async () => {
		await app.close();
	});

	it("allows the configured Bookwrm, Base44, and HAPI origins with credentials", async () => {
		app = Fastify();
		await registerCorsPolicy(app);
		app.get("/probe", async () => ({ status: "ok" }));
		await app.ready();

		for (const origin of [
			"https://bookwrm.com",
			"https://www.bookwrm.com",
			"https://app.base44.com",
			"https://identity.bookwrm.com"
		]) {
			expect(PRODUCTION_CORS_ORIGINS.has(origin)).toBe(true);
			const response = await app.inject({ method: "GET", url: "/probe", headers: { origin } });
			expect(response.headers["access-control-allow-origin"]).toBe(origin);
			expect(response.headers["access-control-allow-credentials"]).toBe("true");
		}
	});

	it("does not grant credentialed CORS access to unknown origins or requests without Origin", async () => {
		app = Fastify();
		await registerCorsPolicy(app);
		app.get("/probe", async () => ({ status: "ok" }));
		await app.ready();

		const unknownOrigin = await app.inject({
			method: "GET",
			url: "/probe",
			headers: { origin: "https://attacker.example" }
		});
		expect(unknownOrigin.headers["access-control-allow-origin"]).toBeUndefined();
		expect(unknownOrigin.headers["access-control-allow-credentials"]).toBeUndefined();

		const noOrigin = await app.inject({ method: "GET", url: "/probe" });
		expect(noOrigin.headers["access-control-allow-origin"]).toBeUndefined();
		expect(noOrigin.headers["access-control-allow-credentials"]).toBeUndefined();
	});
});
