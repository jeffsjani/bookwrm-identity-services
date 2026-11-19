import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { PRODUCTION_CORS_ORIGINS, registerCorsPolicy, resolveTrustedCorsOrigins } from "../src/security/CorsPolicy.js";

describe("CORS production origin policy", () => {
	let app: ReturnType<typeof Fastify>;

	afterEach(async () => {
		delete process.env.CORS_TRUSTED_ORIGINS;
		delete process.env.OIDC_ISSUER;
		configuration.reload();
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

	// HAPI ID V2-E Stage 0: environment-configured allowlists per issuer environment.
	it("uses an explicit CORS_TRUSTED_ORIGINS allowlist that replaces, never extends, the default list", async () => {
		process.env.CORS_TRUSTED_ORIGINS = "https://id-staging.hapiinc.com,https://staging-app.hapiinc.com";
		configuration.reload();
		app = Fastify();
		await registerCorsPolicy(app);
		app.get("/probe", async () => ({ status: "ok" }));
		await app.ready();

		for (const origin of ["https://id-staging.hapiinc.com", "https://staging-app.hapiinc.com"]) {
			const response = await app.inject({ method: "GET", url: "/probe", headers: { origin } });
			expect(response.headers["access-control-allow-origin"]).toBe(origin);
			expect(response.headers["access-control-allow-credentials"]).toBe("true");
		}

		// No silent expansion: default production origins are NOT trusted unless explicitly listed.
		for (const origin of ["https://bookwrm.com", "https://identity.bookwrm.com", "https://id.hapiinc.com"]) {
			const response = await app.inject({ method: "GET", url: "/probe", headers: { origin } });
			expect(response.headers["access-control-allow-origin"], origin).toBeUndefined();
		}
	});

	it("never trusts a browser origin solely because it matches the configured issuer hostname", async () => {
		process.env.OIDC_ISSUER = "https://id-staging.hapiinc.com";
		configuration.reload();
		app = Fastify();
		await registerCorsPolicy(app);
		app.get("/probe", async () => ({ status: "ok" }));
		await app.ready();

		const response = await app.inject({
			method: "GET",
			url: "/probe",
			headers: { origin: "https://id-staging.hapiinc.com" }
		});
		expect(response.headers["access-control-allow-origin"]).toBeUndefined();
		expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
	});

	it("fails closed on wildcard, non-https, malformed, decorated, or empty configured origins", async () => {
		app = Fastify();
		for (const bad of [
			"*",
			"https://*.hapiinc.com",
			"http://id-staging.hapiinc.com",
			"not-a-url",
			"https://id-staging.hapiinc.com/path",
			"https://id-staging.hapiinc.com/",
			"https://user:pass@id-staging.hapiinc.com",
			"",
			"  ,  "
		]) {
			process.env.CORS_TRUSTED_ORIGINS = bad;
			configuration.reload();
			expect(() => resolveTrustedCorsOrigins(), JSON.stringify(bad)).toThrow();
			await expect(registerCorsPolicy(Fastify()), JSON.stringify(bad)).rejects.toThrow();
		}
	});

	it("keeps the default Bookwrm allowlist byte-identical when CORS_TRUSTED_ORIGINS is unset", () => {
		expect(resolveTrustedCorsOrigins()).toBe(PRODUCTION_CORS_ORIGINS);
		expect([...PRODUCTION_CORS_ORIGINS].sort()).toEqual([
			"https://app.base44.com",
			"https://bookwrm.com",
			"https://identity.bookwrm.com",
			"https://www.bookwrm.com"
		]);
	});
});
