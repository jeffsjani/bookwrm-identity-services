import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";

import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { identityClaimResolver } from "../src/identity/IdentityClaimResolver.js";
import { identityAdministrationService } from "../src/identity/IdentityAdministrationService.js";
import { registerIdentityAdminRoutes } from "../src/routes/identityAdmin.js";

async function createTestSubject(email: string) {
		return identityRegistry.resolveOrCreate({
				provider: "PrivateID",
				providerSubject: `admin-api-${randomUUID()}`,
				email,
				emailVerified: true,
				displayName: "Admin API User"
		});
}

describe("IdentityAdministrationService (Phase 4)", () => {
		it("looks up a subject by oidcSubject, provider identity, and email", async () => {
				const subject = await createTestSubject(`lookup-${randomUUID()}@example.com`);

				const byId = await identityAdministrationService.getSubject(subject.oidcSubject);
				const byProvider = await identityAdministrationService.getByProvider(subject.primaryProvider, subject.primaryProviderSubject);
				const byEmail = await identityAdministrationService.getByEmail(subject.email);

				expect(byId?.oidcSubject).toBe(subject.oidcSubject);
				expect(byProvider?.oidcSubject).toBe(subject.oidcSubject);
				expect(byEmail.some((candidate) => candidate.oidcSubject === subject.oidcSubject)).toBe(true);
		});

		it("exposes identity history fields", async () => {
				const subject = await createTestSubject(`history-${randomUUID()}@example.com`);

				const history = identityAdministrationService.getHistory(subject);

				expect(history).toMatchObject({
						created: subject.createdAt,
						updated: subject.updatedAt,
						lastAuthenticated: subject.lastAuthenticatedAt,
						status: "ACTIVE"
				});
		});

		it("exposes claim audit entries read-only", async () => {
				const subject = await createTestSubject(`audit-${randomUUID()}@example.com`);
				await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", { displayName: "Audited Name" });

				const audit = identityAdministrationService.getAudit(subject.oidcSubject);

				expect(audit.claims.some((entry) => entry.claim === "displayName" && entry.newValue === "Audited Name")).toBe(true);
				expect(audit.identity.some((entry) => entry.type === "IDENTITY_CREATED")).toBe(true);
		});

		it("produces an ordered identity timeline: created, linked, claims updated, last login", async () => {
				const subject = await createTestSubject(`timeline-${randomUUID()}@example.com`);
				await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", { displayName: "Timeline Name" });
				const touched = await identityRegistry.touchAuthentication(subject.oidcSubject);

				const timeline = identityAdministrationService.getTimeline(touched ?? subject);
				const types = timeline.map((event) => event.type);

				expect(types[0]).toBe("IDENTITY_CREATED");
				expect(types).toContain("AUTHENTICATOR_LINKED");
				expect(types).toContain("CLAIMS_UPDATED");
				expect(types[types.length - 1]).toBe("LAST_LOGIN");
		});
});

describe("Identity Administration API routes", () => {
		async function buildApp() {
				const app = Fastify();
				await registerIdentityAdminRoutes(app);
				await app.ready();
				return app;
		}

		it("GET /identity/admin/subject/:id returns subject + history + authenticators + timeline", async () => {
				const subject = await createTestSubject(`route-${randomUUID()}@example.com`);
				const app = await buildApp();

				const response = await app.inject({ method: "GET", url: `/identity/admin/subject/${subject.oidcSubject}` });
				expect(response.statusCode).toBe(200);

				const payload = response.json() as Record<string, unknown>;
				expect(payload.subject).toMatchObject({ oidcSubject: subject.oidcSubject });
				expect(payload).toHaveProperty("history");
				expect(payload).toHaveProperty("authenticators");
				expect(payload).toHaveProperty("timeline");

				await app.close();
		});

		it("GET /identity/admin/subject/:id returns 404 for an unknown subject", async () => {
				const app = await buildApp();

				const response = await app.inject({ method: "GET", url: "/identity/admin/subject/does-not-exist" });
				expect(response.statusCode).toBe(404);

				await app.close();
		});

		it("GET /identity/admin/provider/:provider/:subject resolves by provider identity", async () => {
				const subject = await createTestSubject(`provider-route-${randomUUID()}@example.com`);
				const app = await buildApp();

				const response = await app.inject({
						method: "GET",
						url: `/identity/admin/provider/${subject.primaryProvider}/${subject.primaryProviderSubject}`
				});
				expect(response.statusCode).toBe(200);
				expect((response.json() as Record<string, unknown>).subject).toMatchObject({ oidcSubject: subject.oidcSubject });

				await app.close();
		});

		it("GET /identity/admin/email/:email resolves by email", async () => {
				const email = `email-route-${randomUUID()}@example.com`;
				const subject = await createTestSubject(email);
				const app = await buildApp();

				const response = await app.inject({ method: "GET", url: `/identity/admin/email/${encodeURIComponent(email)}` });
				expect(response.statusCode).toBe(200);
				const payload = response.json() as { subjects: Array<{ subject: { oidcSubject: string } }> };
				expect(payload.subjects.some((entry) => entry.subject.oidcSubject === subject.oidcSubject)).toBe(true);

				await app.close();
		});

		it("GET /identity/admin/subject/:id/audit exposes claim audit read-only", async () => {
				const subject = await createTestSubject(`audit-route-${randomUUID()}@example.com`);
				await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", { displayName: "Route Audited Name" });
				const app = await buildApp();

				const response = await app.inject({ method: "GET", url: `/identity/admin/subject/${subject.oidcSubject}/audit` });
				expect(response.statusCode).toBe(200);
				const payload = response.json() as { audit: { claims: Array<{ claim: string; newValue: string }>; identity: Array<{ type: string }> } };
				expect(payload.audit.claims.some((entry) => entry.claim === "displayName" && entry.newValue === "Route Audited Name")).toBe(true);
				expect(payload.audit.identity.some((entry) => entry.type === "IDENTITY_CREATED")).toBe(true);

				await app.close();
		});

		it("GET /identity/admin/health reports component status", async () => {
				const app = await buildApp();

				const response = await app.inject({ method: "GET", url: "/identity/admin/health" });
				const payload = response.json() as Record<string, { status: string }>;

				expect(payload).toHaveProperty("registry");
				expect(payload).toHaveProperty("redis");
				expect(payload).toHaveProperty("postgresql");
				expect(payload).toHaveProperty("oidc");
				expect(payload).toHaveProperty("privateId");

				await app.close();
		});
});
