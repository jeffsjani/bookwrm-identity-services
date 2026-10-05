import { randomUUID } from "node:crypto";
import { runInNewContext } from "node:vm";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { HapiFaceEnrollmentService } from "../src/authenticators/HapiFaceEnrollmentService.js";
import { FACE_ENROLLMENT_FRESHNESS_MS, requireRecentEmailAuthority,
	type FaceEnrollmentAuthority, type FaceEnrollmentRepository } from "../src/authenticators/FaceEnrollmentTypes.js";
import { registerHapiFaceEnrollmentRoutes } from "../src/routes/hapiFaceEnrollment.js";
import { configureFaceEnrollment } from "../src/authenticators/FaceEnrollmentComposition.js";
import { faceEnrollmentContinuation, faceEnrollmentContinuationScript } from "../src/authenticators/FaceEnrollmentContinuation.js";

function authority(overrides: Partial<FaceEnrollmentAuthority> = {}): FaceEnrollmentAuthority {
	return { sub: randomUUID(), clientId: "fixture-client", scope: "openid email",
		authenticationMethod: "HAPI_EMAIL", authenticatedAt: new Date().toISOString(),
		expiresAt: Date.now() + 600_000, ...overrides };
}

function fixture() {
	const reservation = { alreadyEnrolled: false as const, transactionId: randomUUID(), providerTransactionId: randomUUID() };
	const repository: FaceEnrollmentRepository = {
		reserve: vi.fn(async () => reservation), bind: vi.fn(async () => new Date(Date.now() + 300_000).toISOString()),
		status: vi.fn(async () => ({ statusCode: 200, body: { status: "PENDING" } })),
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
	it("requires authenticated, valid scoped access for status reads", async () => {
		const { service } = fixture();
		const app = Fastify();
		await registerHapiFaceEnrollmentRoutes(app, service, { getAccessTokenRecord: async token =>
			token === "valid" ? { ...authority(), nonce: "nonce" } : token === "expired"
				? { ...authority({ expiresAt: Date.now() - 1 }), nonce: "nonce" } : null });
		try {
			const url = `/v1/authenticators/privateid/enroll/${randomUUID()}/status`;
			for (const token of [undefined, "missing", "expired"]) {
				expect((await app.inject({ url, headers: token ? { authorization: `Bearer ${token}` } : {} })).statusCode).toBe(401);
			}
			expect((await app.inject({ url: "/v1/authenticators/privateid/enroll/not-a-uuid/status", headers: { authorization: "Bearer valid" } })).statusCode).toBe(400);
			expect((await app.inject({ url: url + "?identitySubjectId=untrusted", headers: { authorization: "Bearer valid" } })).statusCode).toBe(400);
			const response = await app.inject({ url, headers: { authorization: "Bearer valid" } });
			expect(response.json()).toEqual({ status: "PENDING" });
			expect(response.headers["cache-control"]).toBe("no-store");
		} finally { await app.close(); }
	});
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

function browserFixture(context: { enrollmentId: string; expiresAt: string } | null,
	statuses: Array<{ status: number; body: Record<string, unknown> }> = []) {
	let now = Date.now();
	class BrowserDate extends Date { static override now() { return now; } }
	const storage = new Map<string, string>();
	if (context) storage.set("hapi.faceEnrollment", JSON.stringify(context));
	const message = { textContent: "" };
	let authorityRequest: Record<string, unknown> | undefined;
	const listeners = new Map<string, (event: unknown) => void>();
	const timers: Array<{ callback: () => void; delay: number; cancelled?: boolean }> = [];
	const requests: Array<{ url: string; headers: Record<string, string> }> = [];
	const caller = { postMessage(data: Record<string, unknown>) { authorityRequest = data; } };
	runInNewContext(faceEnrollmentContinuationScript, {
		Date: BrowserDate, crypto: { randomUUID }, location: { origin: "https://hapi.example.test" },
		document: { getElementById: () => message },
		sessionStorage: { getItem: (key: string) => storage.get(key), removeItem: (key: string) => storage.delete(key) },
		window: { opener: caller, addEventListener: (type: string, callback: (event: unknown) => void) => listeners.set(type, callback),
			removeEventListener: (type: string) => listeners.delete(type) },
		setTimeout: (callback: () => void, delay: number) => { const timer = { callback, delay }; timers.push(timer); return timer; },
		clearTimeout: (timer?: { cancelled?: boolean }) => { if (timer) timer.cancelled = true; },
		AbortSignal: { timeout: () => undefined },
		fetch: async (url: string, options: { headers: Record<string, string> }) => {
			requests.push({ url, headers: options.headers });
			const result = statuses.shift() ?? { status: 200, body: { status: "PENDING" } };
			return { ok: result.status >= 200 && result.status < 300, status: result.status, json: async () => result.body };
		}
	});
	async function settle() { for (let turn = 0; turn < 8; turn += 1) await Promise.resolve(); }
	return {
		message, storage, requests,
		async authorize(overrides: Record<string, unknown> = {}) {
			listeners.get("message")?.({ origin: "https://hapi.example.test", source: caller,
				data: { type: "hapi.faceEnrollment.authority", requestId: authorityRequest?.requestId,
					enrollmentId: context?.enrollmentId, accessToken: "in-memory-capability" }, ...overrides });
			await settle();
		},
		async tick() {
			while (timers[0]?.cancelled) timers.shift();
			const timer = timers.shift();
			if (timer) { now += timer.delay; timer.callback(); await settle(); }
		}
	};
}

describe("H5.1 non-authoritative browser continuation", () => {
	function retained() { return { enrollmentId: randomUUID(), expiresAt: new Date(Date.now() + 300_000).toISOString() }; }
	it("fails closed with no browser enrollment context and makes no status or attachment request", async () => {
		const browser = browserFixture(null);
		await browser.authorize();
		expect(browser.message.textContent).toContain("Unable to resume");
		expect(browser.requests).toHaveLength(0);
	});
	it("retains its own enrollment identifier, polls PENDING, then stops on webhook completion", async () => {
		const context = retained();
		const browser = browserFixture(context, [{ status: 200, body: { status: "PENDING" } }, { status: 200, body: { status: "COMPLETED" } }]);
		await browser.authorize();
		expect(browser.storage.has("hapi.faceEnrollment")).toBe(true);
		expect(browser.message.textContent).toContain("Waiting");
		await browser.tick();
		expect(browser.message.textContent).toContain("completed");
		expect(browser.requests.map(request => request.url)).toEqual(Array(2).fill(`/v1/authenticators/privateid/enroll/${context.enrollmentId}/status`));
		expect(browser.storage.size).toBe(0);
		await browser.tick();
		expect(browser.requests).toHaveLength(2);
	});
	it.each(["COMPLETED", "FAILED", "CONFLICT"])("stops immediately on %s and never starts another ceremony", async status => {
		const browser = browserFixture(retained(), [{ status: 200, body: { status } }]);
		await browser.authorize(); await browser.tick();
		expect(browser.requests).toHaveLength(1);
		expect(browser.storage.size).toBe(0);
	});
	it("rejects cross-origin or unrelated authentication messages and does not persist the capability", async () => {
		const browser = browserFixture(retained());
		await browser.authorize({ origin: "https://attacker.example" });
		await browser.authorize({ source: {} });
		expect(browser.requests).toHaveLength(0);
		await browser.authorize();
		expect(browser.requests).toHaveLength(1);
		expect([...browser.storage.values()].join()).not.toContain("in-memory-capability");
	});
	it("bounds pending polling and rejects expired context before requesting status", async () => {
		const browser = browserFixture(retained());
		await browser.authorize();
		for (let attempt = 0; attempt < 65; attempt += 1) await browser.tick();
		expect(browser.requests).toHaveLength(60);
		expect(browser.message.textContent).toContain("expired");
		const expired = browserFixture({ ...retained(), expiresAt: new Date(Date.now() - 1).toISOString() });
		await expired.authorize(); expect(expired.requests).toHaveLength(0);
	});
	it("stops on authorization errors and server expiry without exposing response fields", async () => {
		for (const result of [{ status: 401, body: { error: "UNAUTHORIZED", puid: "secret" } }, { status: 410, body: { status: "EXPIRED" } }]) {
			const browser = browserFixture(retained(), [result]);
			await browser.authorize(); await browser.tick();
			expect(browser.requests).toHaveLength(1);
			expect(browser.message.textContent).not.toContain("secret");
		}
	});
	it("uses hash-authorized scripts and no embedded principal, provider subject or global-session correlation", () => {
		const page = faceEnrollmentContinuation();
		expect(page.contentSecurityPolicy).toContain("script-src 'sha256-");
		expect(page.html).not.toMatch(/currentSessionId|providerSubject|\bpuid\b/);
		expect(page.html).toContain('type: "hapi.faceEnrollment.authority-request"');
	});
});
