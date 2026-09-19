import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { describe, expect, it, beforeAll } from "vitest";

import { registerAuthenticatorStatusRoutes } from "../src/routes/authenticatorStatus.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import { identityAccountLinkService } from "../src/identity/IdentityAccountLinkService.js";
import { configuration } from "../src/config/ConfigurationService.js";

const SERVICE_KEY = "hapi-platform-service-key";

async function buildApp() {
		process.env.HAPI_PLATFORM_SERVICE_KEY = SERVICE_KEY;
		process.env.IDENTITY_REGISTRY_DRIVER = "memory";
		configuration.reload();

		const app = Fastify();
		await registerAuthenticatorStatusRoutes(app);
		await app.ready();
		return app;
}

describe("Release C5.2: POST /internal/authenticators/status", () => {
		beforeAll(() => {
				process.env.HAPI_PLATFORM_SERVICE_KEY = SERVICE_KEY;
				process.env.IDENTITY_REGISTRY_DRIVER = "memory";
				configuration.reload();
		});

		it("returns enrolled=true/active for a Bookwrm account linked to an active privateid authenticator", async () => {
				const app = await buildApp();
				const externalUserId = `bookwrm-${randomUUID()}`;
				const providerSubject = `puid-${randomUUID()}`;

				const subject = await identityRegistry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject
				});
				await inMemoryUserAuthenticatorRepository.create({
						id: randomUUID(),
						userId: subject.id,
						provider: "privateid",
						providerSubject,
						authenticatorType: "face",
						status: "active"
				});
				await identityAccountLinkService.linkAccount({
						externalUserId,
						oidcSubject: subject.oidcSubject
				});

				const response = await app.inject({
						method: "POST",
						url: "/internal/authenticators/status",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload: { provider: "privateid" }
				});

				expect(response.statusCode).toBe(200);
				expect(response.json()).toEqual({ provider: "privateid", enrolled: true, status: "active" });
		});

		it("returns enrolled=false when no IdentityAccountLink exists for the Bookwrm account", async () => {
				const app = await buildApp();

				const response = await app.inject({
						method: "POST",
						url: "/internal/authenticators/status",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": `bookwrm-${randomUUID()}` },
						payload: { provider: "privateid" }
				});

				expect(response.statusCode).toBe(200);
				expect(response.json()).toEqual({ provider: "privateid", enrolled: false, status: "not_enrolled" });
		});

		it("returns enrolled=false when the authenticator was revoked", async () => {
				const app = await buildApp();
				const externalUserId = `bookwrm-${randomUUID()}`;
				const providerSubject = `puid-${randomUUID()}`;

				const subject = await identityRegistry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject
				});
				const authenticator = await inMemoryUserAuthenticatorRepository.create({
						id: randomUUID(),
						userId: subject.id,
						provider: "privateid",
						providerSubject,
						authenticatorType: "face",
						status: "active"
				});
				await inMemoryUserAuthenticatorRepository.revoke(authenticator.id);
				await identityAccountLinkService.linkAccount({
						externalUserId,
						oidcSubject: subject.oidcSubject
				});

				const response = await app.inject({
						method: "POST",
						url: "/internal/authenticators/status",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload: { provider: "privateid" }
				});

				expect(response.statusCode).toBe(200);
				expect(response.json()).toEqual({ provider: "privateid", enrolled: false, status: "revoked" });
		});

		it("rejects requests without a valid service credential", async () => {
				const app = await buildApp();

				const response = await app.inject({
						method: "POST",
						url: "/internal/authenticators/status",
						headers: { "x-bookwrm-user-id": "bookwrm-user" },
						payload: { provider: "privateid" }
				});

				expect(response.statusCode).toBe(401);
		});

		it("rejects unsupported providers", async () => {
				const app = await buildApp();

				const response = await app.inject({
						method: "POST",
						url: "/internal/authenticators/status",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": "bookwrm-user" },
						payload: { provider: "not-a-real-provider" }
				});

				expect(response.statusCode).toBe(400);
		});
});
