import { randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import { inMemoryIdentityAccountLinkRepository } from "../src/identity/InMemoryIdentityAccountLinkRepository.js";
import { registerIdentityAdminRoutes } from "../src/routes/identityAdmin.js";

const ADMIN_KEY = "admin-guard-correct-service-key-0123456789";
const WRONG_KEY = "admin-guard-wrong-service-key-9876543210";

type AdminRoute = { method: "GET" | "POST"; url: string; payload?: Record<string, unknown> };

async function createSubject(label: string) {
		return identityRegistry.resolveOrCreate({
				provider: "PrivateID",
				providerSubject: `admin-guard-${label}-${randomUUID()}`,
				email: `admin-guard-${label}-${randomUUID()}@example.com`,
				emailVerified: true,
				displayName: `Admin Guard ${label}`
		});
}

// Fixture: survivor + loser subjects, a Face authenticator owned by the loser, and an account link to the loser.
async function createFixture() {
		const survivor = await createSubject("survivor");
		const loser = await createSubject("loser");
		const faceAuthenticator = await inMemoryUserAuthenticatorRepository.create({
				id: randomUUID(),
				userId: loser.id,
				provider: "privateid",
				providerSubject: `admin-guard-face-${randomUUID()}`,
				authenticatorType: "face",
				status: "active"
		});
		const accountLink = await inMemoryIdentityAccountLinkRepository.create({
				id: randomUUID(),
				source: "bookwrm",
				externalUserId: `admin-guard-bookwrm-${randomUUID()}`,
				identitySubjectId: loser.id,
				status: "active"
		});
		return { survivor, loser, faceAuthenticator, accountLink };
}

async function snapshotState(fixture: Awaited<ReturnType<typeof createFixture>>) {
		return {
				survivor: await identityRegistry.findByOidcSubject(fixture.survivor.oidcSubject),
				loser: await identityRegistry.findByOidcSubject(fixture.loser.oidcSubject),
				face: await inMemoryUserAuthenticatorRepository.findByProviderSubject("privateid", fixture.faceAuthenticator.providerSubject),
				survivorAuthenticators: await inMemoryUserAuthenticatorRepository.findByUser(fixture.survivor.id),
				loserAuthenticators: await inMemoryUserAuthenticatorRepository.findByUser(fixture.loser.id),
				accountLink: await inMemoryIdentityAccountLinkRepository.findByExternalUserId("bookwrm", fixture.accountLink.externalUserId)
		};
}

function allAdminRoutes(fixture: Awaited<ReturnType<typeof createFixture>>): AdminRoute[] {
		return [
				{ method: "GET", url: "/identity/admin/subjects" },
				{ method: "GET", url: `/identity/admin/subject/${fixture.loser.oidcSubject}` },
				{ method: "GET", url: `/identity/admin/subject/${fixture.loser.oidcSubject}/audit` },
				{ method: "GET", url: `/identity/admin/provider/PrivateID/${fixture.loser.primaryProviderSubject}` },
				{ method: "GET", url: `/identity/admin/email/${encodeURIComponent(fixture.loser.email)}` },
				{ method: "GET", url: "/identity/admin/health" },
				{
						method: "POST",
						url: `/identity/admin/subject/${fixture.loser.oidcSubject}/recover`,
						payload: { newPrivateIdUserId: `admin-guard-recover-${randomUUID()}`, adminApproved: true, reason: "guard test" }
				},
				{
						method: "POST",
						url: "/identity/admin/merge",
						payload: { survivorOidcSubject: fixture.survivor.oidcSubject, loserOidcSubject: fixture.loser.oidcSubject, reason: "guard test" }
				}
		];
}

const UNAUTHORIZED_CREDENTIALS: Array<{ name: string; headers: Record<string, string>; query?: string }> = [
		{ name: "no credential", headers: {} },
		{ name: "wrong bearer key", headers: { authorization: `Bearer ${WRONG_KEY}` } },
		{ name: "correct key with wrong scheme", headers: { authorization: `Basic ${ADMIN_KEY}` } },
		{ name: "correct key without scheme", headers: { authorization: ADMIN_KEY } },
		{ name: "key prefix only", headers: { authorization: `Bearer ${ADMIN_KEY.slice(0, -1)}` } },
		{ name: "key with trailing data", headers: { authorization: `Bearer ${ADMIN_KEY}x` } },
		{ name: "empty bearer", headers: { authorization: "Bearer " } },
		{ name: "key in custom header", headers: { "x-hapi-platform-service-key": ADMIN_KEY, "x-api-key": ADMIN_KEY } },
		{ name: "key in query string", headers: {}, query: `key=${ADMIN_KEY}&access_token=${ADMIN_KEY}&HAPI_PLATFORM_SERVICE_KEY=${ADMIN_KEY}` }
];

describe("/identity/admin/* service-credential guard", () => {
		let previousKey: string | undefined;
		let app: FastifyInstance;
		let logLines: string[];
		let registeredRoutes: Array<{ method: string; url: string; guarded: boolean }>;

		beforeAll(() => {
				previousKey = process.env.HAPI_PLATFORM_SERVICE_KEY;
		});

		afterAll(() => {
				if (previousKey === undefined) delete process.env.HAPI_PLATFORM_SERVICE_KEY;
				else process.env.HAPI_PLATFORM_SERVICE_KEY = previousKey;
				configuration.reload();
		});

		beforeEach(async () => {
				process.env.HAPI_PLATFORM_SERVICE_KEY = ADMIN_KEY;
				configuration.reload();
				logLines = [];
				const stream = new Writable({
						write(chunk, _encoding, callback) {
								logLines.push(chunk.toString());
								callback();
						}
				});
				app = Fastify({ logger: { level: "trace", stream } });
				registeredRoutes = [];
				app.addHook("onRoute", (route) => {
						const hooks = [route.onRequest].flat().filter(Boolean);
						for (const method of [route.method].flat()) {
								registeredRoutes.push({ method, url: route.url, guarded: hooks.length > 0 });
						}
				});
				await registerIdentityAdminRoutes(app);
				await app.ready();
		});

		afterEach(async () => {
				await app.close();
		});

		it("guards every registered /identity/admin/* route (including implicit HEAD routes)", async () => {
				const adminRoutes = registeredRoutes.filter((route) => route.url.startsWith("/identity/admin"));
				expect(adminRoutes.filter((route) => route.method !== "HEAD")).toHaveLength(8);
				expect(adminRoutes.every((route) => route.guarded)).toBe(true);

				const fixture = await createFixture();
				for (const route of allAdminRoutes(fixture).filter((candidate) => candidate.method === "GET")) {
						const head = await app.inject({ method: "HEAD", url: route.url });
						expect(head.statusCode, `HEAD ${route.url}`).toBe(401);
				}
		});

		for (const credential of UNAUTHORIZED_CREDENTIALS) {
				it(`denies every admin route with ${credential.name} and mutates nothing`, async () => {
						const fixture = await createFixture();
						const before = await snapshotState(fixture);

						for (const route of allAdminRoutes(fixture)) {
								const separator = route.url.includes("?") ? "&" : "?";
								const response = await app.inject({
										method: route.method,
										url: credential.query ? `${route.url}${separator}${credential.query}` : route.url,
										headers: credential.headers,
										...(route.payload ? { payload: route.payload } : {})
								});

								expect(response.statusCode, `${route.method} ${route.url}`).toBe(401);
								expect(response.headers["www-authenticate"]).toBe("Bearer");
								expect(response.json()).toEqual({ error: "unauthorized", error_description: "Administrative service credential required" });
								expect(response.body).not.toContain(fixture.loser.oidcSubject);
								expect(response.body).not.toContain(fixture.loser.email);
						}

						expect(await snapshotState(fixture)).toEqual(before);
						expect((await snapshotState(fixture)).face?.userId).toBe(fixture.loser.id);
						expect((await snapshotState(fixture)).loser?.status).toBe("ACTIVE");
				});
		}

		it("fails closed when HAPI_PLATFORM_SERVICE_KEY is not configured, even for an empty bearer", async () => {
				delete process.env.HAPI_PLATFORM_SERVICE_KEY;
				configuration.reload();
				const fixture = await createFixture();
				const before = await snapshotState(fixture);

				for (const route of allAdminRoutes(fixture)) {
						for (const headers of [{}, { authorization: "Bearer " }, { authorization: "Bearer undefined" }, { authorization: `Bearer ${ADMIN_KEY}` }]) {
								const response = await app.inject({ method: route.method, url: route.url, headers, ...(route.payload ? { payload: route.payload } : {}) });
								expect(response.statusCode, `${route.method} ${route.url}`).toBe(401);
						}
				}

				expect(await snapshotState(fixture)).toEqual(before);
		});

		it("denies an unauthorized merge before body validation (invalid body still 401, not 400)", async () => {
				const response = await app.inject({ method: "POST", url: "/identity/admin/merge", payload: {} });
				expect(response.statusCode).toBe(401);

				const malformedBody = await app.inject({
					method: "POST",
					url: "/identity/admin/merge",
					headers: { "content-type": "application/json" },
					payload: "{"
				});
				expect(malformedBody.statusCode).toBe(401);
		});

		it("preserves existing read behavior with the correct key", async () => {
				const fixture = await createFixture();
				const authorization = `Bearer ${ADMIN_KEY}`;

				const subject = await app.inject({ method: "GET", url: `/identity/admin/subject/${fixture.loser.oidcSubject}`, headers: { authorization } });
				expect(subject.statusCode).toBe(200);
				expect((subject.json() as { subject: { oidcSubject: string } }).subject.oidcSubject).toBe(fixture.loser.oidcSubject);

				const unknown = await app.inject({ method: "GET", url: "/identity/admin/subject/00000000-0000-4000-8000-0000000000ff", headers: { authorization } });
				expect(unknown.statusCode).toBe(404);

				const health = await app.inject({ method: "GET", url: "/identity/admin/health", headers: { authorization } });
				expect([200, 503]).toContain(health.statusCode);
				expect(health.json()).toHaveProperty("registry");

				const invalidMerge = await app.inject({ method: "POST", url: "/identity/admin/merge", headers: { authorization }, payload: {} });
				expect(invalidMerge.statusCode).toBe(400);
		});

		it("preserves existing merge semantics with the correct key (Face authenticator reassigned to survivor)", async () => {
				const fixture = await createFixture();

				const response = await app.inject({
						method: "POST",
						url: "/identity/admin/merge",
						headers: { authorization: `Bearer ${ADMIN_KEY}` },
						payload: { survivorOidcSubject: fixture.survivor.oidcSubject, loserOidcSubject: fixture.loser.oidcSubject, reason: "authorized guard test" }
				});

				expect(response.statusCode).toBe(200);
				const after = await snapshotState(fixture);
				expect(after.loser?.status).toBe("DISABLED");
				expect(after.face?.userId).toBe(fixture.survivor.id);
		});

		it("preserves existing recover semantics with the correct key", async () => {
				const fixture = await createFixture();
				const newPrivateIdUserId = `admin-guard-recovered-${randomUUID()}`;

				const refused = await app.inject({
						method: "POST",
						url: `/identity/admin/subject/${fixture.loser.oidcSubject}/recover`,
						headers: { authorization: `Bearer ${ADMIN_KEY}` },
						payload: { newPrivateIdUserId, adminApproved: false, reason: "authorized guard test" }
				});
				expect(refused.statusCode).toBe(409);

				const recovered = await app.inject({
						method: "POST",
						url: `/identity/admin/subject/${fixture.loser.oidcSubject}/recover`,
						headers: { authorization: `Bearer ${ADMIN_KEY}` },
						payload: { newPrivateIdUserId, adminApproved: true, reason: "authorized guard test" }
				});
				expect(recovered.statusCode).toBe(200);
				expect((await identityRegistry.findByOidcSubject(fixture.loser.oidcSubject))?.primaryProviderSubject).toBe(newPrivateIdUserId);
		});

		it("never writes the service key or authorization header to logs", async () => {
				const fixture = await createFixture();
				for (const headers of [{ authorization: `Bearer ${ADMIN_KEY}` }, { authorization: `Bearer ${WRONG_KEY}` }]) {
						for (const route of allAdminRoutes(fixture)) {
								await app.inject({ method: route.method, url: route.url, headers, ...(route.payload ? { payload: route.payload } : {}) });
						}
				}

				const logs = logLines.join("\n");
				expect(logLines.length).toBeGreaterThan(0);
				expect(logs).not.toContain(ADMIN_KEY);
				expect(logs).not.toContain(WRONG_KEY);
				expect(logs.toLowerCase()).not.toContain("authorization");
		});
});
