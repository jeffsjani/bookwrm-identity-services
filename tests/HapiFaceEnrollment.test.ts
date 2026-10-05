import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { HapiFaceEnrollmentService } from "../src/authenticators/HapiFaceEnrollmentService.js";
import { FACE_ENROLLMENT_FRESHNESS_MS, requireRecentEmailAuthority,
	type FaceEnrollmentAuthority, type FaceEnrollmentRepository } from "../src/authenticators/FaceEnrollmentTypes.js";
import { registerHapiFaceEnrollmentRoutes } from "../src/routes/hapiFaceEnrollment.js";
import { configureFaceEnrollment } from "../src/authenticators/FaceEnrollmentComposition.js";

function authority(overrides: Partial<FaceEnrollmentAuthority> = {}): FaceEnrollmentAuthority {
	return { sub: randomUUID(), clientId: "fixture-client", scope: "openid email",
		authenticationMethod: "HAPI_EMAIL", authenticatedAt: new Date().toISOString(),
		expiresAt: Date.now() + 600_000, ...overrides };
}

function fixture() {
	const reservation = { alreadyEnrolled: false as const, transactionId: randomUUID(), providerTransactionId: randomUUID() };
	const repository: FaceEnrollmentRepository = {
		reserve: vi.fn(async () => reservation), bind: vi.fn(async () => new Date(Date.now() + 300_000).toISOString()),
		fail: vi.fn(async () => {}), webhook: vi.fn(async () => undefined), callback: vi.fn(async () => undefined)
	};
	const createSession = vi.fn(async (transactionId: string) => ({
		sessionId: randomUUID(), transactionId, status: "created" as const,
		launchUrl: "https://privateid.example.test/launch", expires: Date.now() + 300_000, created: Date.now()
	}));
	return { repository, createSession, reservation, service: new HapiFaceEnrollmentService(repository, createSession) };
}

describe("H5 recent HAPI authority and provider orchestration", () => {
	it("accepts recent email authority including the exact approved 5-minute boundary", () => {
		const now = Date.now();
		expect(() => requireRecentEmailAuthority(authority({ authenticatedAt: new Date(now - FACE_ENROLLMENT_FRESHNESS_MS).toISOString() }), now)).not.toThrow();
	});
	it.each([
		{ authenticationMethod: undefined }, { authenticationMethod: "PRIVATEID_FACE" as const },
		{ authenticatedAt: undefined }, { authenticatedAt: "invalid" },
		{ authenticatedAt: new Date(Date.now() - 300_001).toISOString() },
		{ authenticatedAt: new Date(Date.now() + 60_000).toISOString() },
		{ expiresAt: Date.now() - 1 }, { expiresAt: NaN }, { scope: "email" }
	])("rejects insufficient authority before contacting PostgreSQL or PrivateID: %j", async overrides => {
		const { service, repository, createSession } = fixture();
		await expect(service.start(authority(overrides))).rejects.toMatchObject({ statusCode: 401 });
		expect(repository.reserve).not.toHaveBeenCalled();
		expect(createSession).not.toHaveBeenCalled();
	});
	it("reserves before launching and returns only ceremony fields, not canonical internal identifiers", async () => {
		const { service, repository, createSession, reservation } = fixture();
		const result = await service.start(authority());
		expect(Object.keys(result).sort()).toEqual(["enrolled", "enrollmentId", "expiresAt", "launchUrl"]);
		expect(result.enrollmentId).toBe(reservation.providerTransactionId);
		expect(createSession).toHaveBeenCalledWith(reservation.providerTransactionId);
		expect(repository.bind).toHaveBeenCalledOnce();
	});
	it("does not call the provider for an already active authenticator", async () => {
		const { repository, createSession } = fixture();
		repository.reserve = vi.fn(async () => ({ alreadyEnrolled: true }));
		const service = new HapiFaceEnrollmentService(repository, createSession);
		expect(await service.start(authority())).toEqual({ enrolled: true, alreadyEnrolled: true });
		expect(createSession).not.toHaveBeenCalled();
	});
	it("fails the reserved transaction explicitly when the provider is unavailable", async () => {
		const { repository, reservation } = fixture();
		const failure = new Error("provider unavailable: raw-secret-or-biometric-response");
		const service = new HapiFaceEnrollmentService(repository, vi.fn(async () => { throw failure; }));
		await expect(service.start(authority())).rejects.toMatchObject({ code: "PROVIDER_SESSION_FAILED", statusCode: 502 });
		expect(repository.fail).toHaveBeenCalledWith(reservation.providerTransactionId);
		expect(repository.bind).not.toHaveBeenCalled();
	});
	it.each(["http://privateid.example.test/launch", "not a URL"])("rejects an invalid launch URL %s", async launchUrl => {
		const { repository, createSession } = fixture();
		const valid = await createSession(randomUUID());
		const service = new HapiFaceEnrollmentService(repository, async transactionId => ({ ...valid, transactionId, launchUrl }));
		await expect(service.start(authority())).rejects.toMatchObject({ code: "INVALID_PROVIDER_SESSION" });
		expect(repository.fail).toHaveBeenCalledOnce();
	});
	it("rejects a session bound to a different provider transaction", async () => {
		const { repository, createSession } = fixture();
		const valid = await createSession(randomUUID());
		const service = new HapiFaceEnrollmentService(repository, async () => valid);
		await expect(service.start(authority())).rejects.toMatchObject({ code: "INVALID_PROVIDER_SESSION" });
		expect(repository.bind).not.toHaveBeenCalled();
	});
	it("keeps callbacks identifiable while disabled, but explicitly rejects enrollment", async () => {
		const { repository, createSession } = fixture();
		const service = new HapiFaceEnrollmentService(repository, createSession, false);
		await expect(service.start(authority())).rejects.toMatchObject({ statusCode: 404 });
		await service.webhook("transaction", "session", "SUCCESS", "puid");
		expect(repository.webhook).toHaveBeenCalledWith("transaction", "session", "SUCCESS", "puid", false);
		expect(createSession).not.toHaveBeenCalled();
	});
});

describe("H5 application-neutral route", () => {
	it("requires an existing bearer token, not legacy product headers or client credentials", async () => {
		const { service, createSession } = fixture();
		const app = Fastify();
		await registerHapiFaceEnrollmentRoutes(app, service, { getAccessTokenRecord: async () => null });
		try {
			for (const headers of [{}, { authorization: "Basic legacy", "x-bookwrm-user-id": "attacker" }, { authorization: "Bearer missing" }]) {
				expect((await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll", headers, payload: {} })).statusCode).toBe(401);
			}
			expect(createSession).not.toHaveBeenCalled();
		} finally { await app.close(); }
	});
	it("rejects all browser-supplied authority and PUID fields", async () => {
		const { service, createSession } = fixture();
		const app = Fastify();
		await registerHapiFaceEnrollmentRoutes(app, service, { getAccessTokenRecord: async () => ({ ...authority(), nonce: "nonce" }) });
		try {
			for (const field of ["id", "identitySubjectId", "oidcSubject", "email", "puid", "tenantId", "applicationId", "clientId"]) {
				expect((await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll",
					headers: { authorization: "Bearer fixture" }, payload: { [field]: "untrusted" } })).statusCode).toBe(400);
			}
			expect(createSession).not.toHaveBeenCalled();
		} finally { await app.close(); }
	});
	it("derives authority only from the server-side OIDC token record without product headers", async () => {
		const { service, repository } = fixture();
		const token = { ...authority(), nonce: "nonce" };
		const app = Fastify();
		await registerHapiFaceEnrollmentRoutes(app, service, { getAccessTokenRecord: async () => token });
		try {
			const response = await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll",
				headers: { authorization: "Bearer fixture" }, payload: {} });
			expect(response.statusCode).toBe(200);
			expect(repository.reserve).toHaveBeenCalledWith(token);
		} finally { await app.close(); }
	});
	it("validates configuration, requires PostgreSQL, and defaults disabled", async () => {
		const app = Fastify();
		try {
			expect(await configureFaceEnrollment(app, { IDENTITY_REGISTRY_DRIVER: "memory" })).toBeUndefined();
			expect((await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll" })).statusCode).toBe(404);
			await expect(configureFaceEnrollment(app, { HAPI_FACE_ENROLLMENT_ENABLED: "invalid" })).rejects.toThrow("true or false");
			await expect(configureFaceEnrollment(app, { IDENTITY_REGISTRY_DRIVER: "memory", HAPI_FACE_ENROLLMENT_ENABLED: "true" })).rejects.toThrow("PostgreSQL");
			await expect(configureFaceEnrollment(app, { HAPI_FACE_ENROLLMENT_ENABLED: "true" })).rejects.toThrow("H4");
		} finally { await app.close(); }
	});
});
