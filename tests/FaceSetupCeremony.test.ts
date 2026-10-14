import { createHash, randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import Fastify, { type FastifyInstance } from "fastify";
import RedisMock from "ioredis-mock";
import { JSDOM } from "jsdom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { registerFaceSetupRoutes, type FaceSetupDependencies } from "../src/routes/faceSetup.js";
import { FaceSetupInteractionStore } from "../src/authenticators/FaceSetupInteractionStore.js";
import { FACE_SETUP_COOKIE, FaceSetupError } from "../src/authenticators/FaceSetupTypes.js";
import { faceSetupConsentPage } from "../src/authenticators/FaceSetupPages.js";
import { HapiFaceEnrollmentService } from "../src/authenticators/HapiFaceEnrollmentService.js";
import { oidcRedisKey } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import { FACE_AUTH_CONSENT_PURPOSE, FACE_AUTH_CONSENT_VERSION, FaceEnrollmentError,
	type FaceEnrollmentAuthority, type FaceEnrollmentRepository } from "../src/authenticators/FaceEnrollmentTypes.js";
import type { InteractiveEmailAuthentication, InteractiveEmailAuthority } from "../src/authentication/InteractiveEmailAuthentication.js";
import type { EmailPrincipal } from "../src/authentication/email/EmailAuthenticationTypes.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";

const CLIENT_ID = "bookwrm-client";
const RETURN_URI = "https://bookwrm.example.test/bookwrm/settings/account";
const SUBJECT = randomUUID();

function clientAuthorityFixture(): FaceSetupDependencies["clientAuthority"] {
	const application = { id: "app-1", tenantId: "tenant-1", status: "active" as const };
	const tenant = { id: "tenant-1", status: "active" as const, name: "Bookwrm" };
	const client = {
		clientId: CLIENT_ID, clientSecret: "secret", tokenEndpointAuthMethod: "client_secret_basic",
		applicationId: application.id, redirectUris: [RETURN_URI]
	};
	return {
		clients: { findByClientId: vi.fn(async (id: string) => (id === CLIENT_ID ? client : undefined)) },
		applications: { findById: vi.fn(async (id: string) => (id === application.id ? application : undefined)) },
		tenants: { findById: vi.fn(async (id: string) => (id === tenant.id ? tenant : undefined)) }
	} as unknown as FaceSetupDependencies["clientAuthority"];
}

function identitySubjectFixture(overrides: Partial<IdentitySubject> = {}): IdentitySubject {
	return {
		id: randomUUID(), oidcSubject: SUBJECT, primaryProvider: "HAPI_EMAIL", primaryProviderSubject: "identity@hapiinc.com",
		email: "identity@hapiinc.com", emailVerified: true, status: "ACTIVE",
		createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), ...overrides
	};
}

function interactiveFixture(principal: EmailPrincipal, mode: "AUTHENTICATION" | "REGISTRATION" | "INELIGIBLE" = "AUTHENTICATION") {
	const authority: InteractiveEmailAuthority = { context: { tenantId: "tenant-1", applicationId: "app-1" }, clientId: CLIENT_ID, tenantName: "Bookwrm" };
	const interactive: InteractiveEmailAuthentication = {
		authority: vi.fn(async clientId => (clientId === CLIENT_ID ? authority : Promise.reject(new Error("unknown client")))),
		start: vi.fn(async () => ({ challengeId: "challenge-1", expiresIn: 300, resendAfter: 30, mode })),
		resend: vi.fn(async () => ({ challengeId: "challenge-1", expiresIn: 300, resendAfter: 30 })),
		verify: vi.fn(async (_authority, _challengeId, code) => {
			if (code !== "123456") throw new Error("bad code");
			return mode === "AUTHENTICATION" ? { mode: "AUTHENTICATION" as const, authenticationResult: "result-token" }
				: { mode: "REGISTRATION" as const, principal };
		}),
		consumeResult: vi.fn(async () => principal)
	};
	return interactive;
}

function serviceFixture() {
	return {
		acceptConsent: vi.fn(async () => {}),
		start: vi.fn(async () => ({ enrolled: false, enrollmentId: "enrollment-1", launchUrl: "https://privateid.example.test/launch", expiresAt: new Date(Date.now() + 300_000).toISOString() })),
		status: vi.fn(async () => ({ statusCode: 200, body: { status: "PENDING" } })),
		capabilityStatus: vi.fn(async () => ({
			faceEnrollmentEligible: true, faceLoginEligible: true, consentRequired: true,
			enrollmentState: "ACTIVE" as const, consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: "text"
		}))
	} satisfies FaceSetupDependencies["service"];
}

function buildApp(overrides: Partial<FaceSetupDependencies> = {}, logs?: string[]) {
	const principal: EmailPrincipal = {
		sub: SUBJECT, clientId: CLIENT_ID, authenticationMethod: "HAPI_EMAIL",
		authenticatedAt: new Date().toISOString(), assurance: "email_otp"
	} as EmailPrincipal;
	const deps: FaceSetupDependencies = {
		interactions: new FaceSetupInteractionStore(),
		service: serviceFixture(),
		interactive: interactiveFixture(principal),
		identitySubjects: { findByOidcSubject: vi.fn(async sub => (sub === SUBJECT ? identitySubjectFixture() : undefined)) },
		clientAuthority: clientAuthorityFixture(),
		isPilotSubject: sub => sub === SUBJECT,
		isEnabled: () => true,
		...overrides
	};
	const app = Fastify(logs ? { logger: { stream: new Writable({
		write(chunk, _encoding, next) { logs.push(chunk.toString()); next(); }
	}) } } : {});
	return { app, deps, principal };
}

async function register(app: FastifyInstance, deps: FaceSetupDependencies) {
	await registerFaceSetupRoutes(app, deps);
	await app.ready();
}

function cookieFrom(response: { headers: Record<string, unknown> }): string {
	const setCookie = response.headers["set-cookie"];
	const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
	return String(raw).split(";")[0];
}

async function startCeremony(app: FastifyInstance) {
	const response = await app.inject({ method: "GET", url: `/face-setup/start?client_id=${CLIENT_ID}&return_uri=${encodeURIComponent(RETURN_URI)}` });
	expect(response.statusCode).toBe(302);
	return cookieFrom(response);
}

function csrfFromHtml(html: string): string {
	const match = html.match(/name="csrf" value="([^"]+)"/);
	if (!match) throw new Error("csrf not found in rendered page");
	return match[1];
}

describe("H5.4 Face Setup reauthorization ceremony", () => {
	let app: FastifyInstance;
	let deps: FaceSetupDependencies;

	beforeEach(async () => {
		({ app, deps } = buildApp());
		await register(app, deps);
	});

	it("starts a ceremony for a registered Bookwrm client and return URI", async () => {
		const cookie = await startCeremony(app);
		expect(cookie).toMatch(new RegExp(`^${FACE_SETUP_COOKIE}=`));
		const email = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		expect(email.statusCode).toBe(200);
		expect(email.body).toContain("Set up Face Login");
	});

	it("rejects an unregistered return URI", async () => {
		const response = await app.inject({
			method: "GET",
			url: `/face-setup/start?client_id=${CLIENT_ID}&return_uri=${encodeURIComponent("https://evil.example.test/steal")}`
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "INVALID_RETURN_URI" });
	});

	it("rejects an expired transaction", async () => {
		let now = Date.now();
		const interactions = new FaceSetupInteractionStore(undefined, undefined, () => now);
		({ app, deps } = buildApp({ interactions }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		now += 700_000; // past FACE_SETUP_TTL_MS -- the interaction must be treated as expired, not merely stale
		const email = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		expect(email.statusCode).toBe(400);
		expect(email.body).toContain("expired");
	});

	it("rejects a tampered CSRF token on the email submission", async () => {
		const cookie = await startCeremony(app);
		const response = await app.inject({
			method: "POST", url: "/face-setup/email", headers: { cookie },
			payload: { csrf: "not-the-real-csrf", email: "identity@hapiinc.com" }
		});
		expect(response.statusCode).toBe(400);
		expect(deps.interactive.start).not.toHaveBeenCalled();
	});

	it("reauthenticates an existing HAPI_EMAIL subject with a single OTP and resolves the same canonical subject", async () => {
		const cookie = await startCeremony(app);
		const emailPage = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(emailPage.body);
		const started = await app.inject({
			method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" }
		});
		expect(started.statusCode).toBe(200);
		expect(deps.interactive.start).toHaveBeenCalledTimes(1);
		const code = await app.inject({
			method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" }
		});
		expect(code.statusCode).toBe(200);
		expect(code.body).toContain("Set up Face Login");
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
		expect(deps.identitySubjects.findByOidcSubject).toHaveBeenCalledWith(SUBJECT);
	});

	it("recognizes reusable consent after H4 and starts enrollment without a duplicate consent screen or write", async () => {
		vi.mocked(deps.service.capabilityStatus).mockResolvedValue({
			faceEnrollmentEligible: true, faceLoginEligible: false, consentRequired: false,
			enrollmentState: "FAILED", consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: "text"
		});
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		expect(deps.service.start).toHaveBeenCalledTimes(1);
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
		expect(deps.interactive.consumeResult).toHaveBeenCalledTimes(1);
		expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("ENROLLING");
		const repeat = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(repeat.statusCode).toBe(303);
		expect(deps.service.start).toHaveBeenCalledTimes(1);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
	});

	it("never creates an IdentitySubject when the email is not an existing AUTHENTICATION-mode subject", async () => {
		const principal: EmailPrincipal = {
			sub: SUBJECT, clientId: CLIENT_ID, authenticationMethod: "HAPI_EMAIL",
			authenticatedAt: new Date().toISOString(), assurance: "email_otp"
		} as EmailPrincipal;
		({ app, deps } = buildApp({ interactive: interactiveFixture(principal, "REGISTRATION") }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const emailPage = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(emailPage.body);
		const response = await app.inject({
			method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "new@hapiinc.com" }
		});
		expect(response.statusCode).toBe(200);
		expect(response.body).toContain("couldn&#39;t find an existing Bookwrm account");
	});

	it("fails closed for a subject that is not the certified pilot", async () => {
		({ app, deps } = buildApp({ isPilotSubject: () => false }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const emailPage = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(emailPage.body);
		await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		const response = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		expect(response.statusCode).toBe(403);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
	});

	async function reachConsent(app: FastifyInstance, cookie: string) {
		const emailPage = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(emailPage.body);
		await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		return csrf;
	}

	it("Not Now creates no consent and no enrollment and returns a safe cancelled redirect", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "not_now" } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=cancelled`);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("Agree records FACE_AUTH_V1 consent exactly once and redirects to PrivateID enrollment", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe("https://privateid.example.test/launch");
		expect(deps.service.acceptConsent).toHaveBeenCalledTimes(1);
		expect(deps.service.acceptConsent).toHaveBeenCalledWith(
			expect.objectContaining({ sub: SUBJECT, authenticationMethod: "HAPI_EMAIL" }),
			FACE_AUTH_CONSENT_VERSION, FACE_AUTH_CONSENT_PURPOSE
		);
	});

	function enrollmentFixture() {
		const repository = {
			acceptConsent: vi.fn(async () => {}),
			reserve: vi.fn(async () => ({
				alreadyEnrolled: false as const, transactionId: "enrollment-row", providerTransactionId: "provider-transaction"
			})),
			bind: vi.fn(async () => new Date(Date.now() + 300_000).toISOString()),
			fail: vi.fn(async () => {}),
			capabilityStatus: serviceFixture().capabilityStatus,
			status: serviceFixture().status,
			webhook: vi.fn(async () => undefined),
			callback: vi.fn(async () => undefined)
		} satisfies FaceEnrollmentRepository;
		const provider = vi.fn(async (transactionId: string) => ({
			transactionId, sessionId: "provider-session", status: "created" as const,
			launchUrl: "https://privateid.example.test/launch", created: Date.now(), expires: Date.now() + 300_000
		}));
		return { repository, provider, service: new HapiFaceEnrollmentService(repository, provider) };
	}

	it("preserves ENROLLING on the exact production sequence of three identical consent POSTs", async () => {
		const fixture = enrollmentFixture();
		({ app, deps } = buildApp({ service: fixture.service }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const request = { method: "POST" as const, url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } };
		const handle = cookie.slice(FACE_SETUP_COOKIE.length + 1);
		const first = await app.inject(request);
		expect(first.statusCode).toBe(302);
		expect(first.headers.location).toBe("https://privateid.example.test/launch");
		expect((await deps.interactions.find(handle))?.phase).toBe("ENROLLING");
		for (let repeat = 0; repeat < 2; repeat++) {
			const response = await app.inject(request);
			expect(response.statusCode).toBe(303);
			expect(response.headers.location).toBe("/face-setup/continue");
			expect(response.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(handle))?.phase).toBe("ENROLLING");
		}
		const continuation = await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } });
		expect(continuation.statusCode).toBe(302);
		expect(continuation.headers.location).toBe(first.headers.location);
		expect(fixture.repository.acceptConsent).toHaveBeenCalledTimes(1);
		expect(fixture.repository.reserve).toHaveBeenCalledTimes(1);
		expect(fixture.provider).toHaveBeenCalledTimes(1);
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
		expect(deps.interactive.consumeResult).toHaveBeenCalledTimes(1);
	});

	it("atomically claims simultaneous consent submissions and preserves a pending continuation", async () => {
		const fixture = enrollmentFixture();
		let release = () => {};
		const gate = new Promise<void>(resolve => { release = resolve; });
		fixture.repository.acceptConsent.mockImplementation(async () => { await gate; });
		({ app, deps } = buildApp({ service: fixture.service }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const request = { method: "POST" as const, url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } };
		const first = app.inject(request);
		const second = app.inject(request);
		await vi.waitFor(() => expect(fixture.repository.acceptConsent).toHaveBeenCalledTimes(1));
		const duplicate = await Promise.race([first, second]);
		expect(duplicate.statusCode).toBe(303);
		const pending = await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } });
		expect(pending.statusCode).toBe(200);
		expect(pending.body).toContain("Finishing Face setup");
		release();
		expect((await Promise.all([first, second])).map(response => response.statusCode).sort()).toEqual([302, 303]);
		expect(fixture.repository.acceptConsent).toHaveBeenCalledTimes(1);
		expect(fixture.repository.reserve).toHaveBeenCalledTimes(1);
		expect(fixture.provider).toHaveBeenCalledTimes(1);
		expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("ENROLLING");
	});

	it("checks CSRF before any duplicate or phase handling and does not destroy enrollment", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		const response = await app.inject({
			method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf: "tampered", decision: "agree" }
		});
		expect(response.statusCode).toBe(400);
		expect(response.headers.location).toBeUndefined();
		expect(response.headers["set-cookie"]).toBeUndefined();
		expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("ENROLLING");
		expect(deps.service.start).toHaveBeenCalledTimes(1);
	});

	it.each(["client", "pilot", "return", "provider"] as const)("rejects changed %s authority before claiming consent", async field => {
		const pilot = vi.fn(() => true);
		({ app, deps } = buildApp({ isPilotSubject: pilot }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const handle = cookie.slice(FACE_SETUP_COOKIE.length + 1);
		if (field === "pilot") pilot.mockReturnValue(false);
		else {
			const interaction = (await deps.interactions.find(handle))!;
			if (field === "client") interaction.authority!.clientId = "different-client";
			if (field === "return") interaction.returnUri = "https://evil.example.test/";
			if (field === "provider") {
				vi.mocked(deps.identitySubjects.findByOidcSubject).mockResolvedValue(identitySubjectFixture({ primaryProvider: "PrivateID" }));
			}
			expect(await deps.interactions.save(handle, interaction)).toBe(true);
		}
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(response.statusCode).toBe(403);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it.each(["purpose", "version", "json"] as const)("fails closed for tampered interaction %s without expiration copy", async field => {
		const redis = new RedisMock();
		({ app, deps } = buildApp({ interactions: new FaceSetupInteractionStore(redis) }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const handle = cookie.slice(FACE_SETUP_COOKIE.length + 1);
		const key = oidcRedisKey(`face_setup_interaction:${createHash("sha256").update(handle).digest("base64url")}`);
		const record = JSON.parse((await redis.get(key))!);
		if (field === "purpose") record.purpose = "OIDC";
		if (field === "version") record.version = 9;
		await redis.set(key, field === "json" ? "{" : JSON.stringify(record));
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(response.statusCode).toBe(400);
		expect(response.body).toContain("couldn&#39;t continue");
		expect(response.body).not.toContain("has expired");
		expect(deps.service.start).not.toHaveBeenCalled();
		await redis.quit();
	});

	it.each(["cancelled", "completed"] as const)("does not resume a %s interaction", async outcome => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const request = { method: "POST" as const, url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: outcome === "cancelled" ? "not_now" : "agree" } };
		await app.inject(request);
		if (outcome === "completed") {
			vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 200, body: { status: "COMPLETED" } });
			await app.inject({ method: "GET", url: "/face-setup/callback", headers: { cookie } });
		}
		const replay = await app.inject({ ...request, payload: { csrf, decision: "agree" } });
		expect(replay.statusCode).toBe(400);
		expect(replay.body).not.toContain("has expired");
		expect(deps.service.start).toHaveBeenCalledTimes(outcome === "completed" ? 1 : 0);
	});

	it("fails closed for missing cookies and missing Redis records, without claiming expiry", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const request = { method: "POST" as const, url: "/face-setup/consent", payload: { csrf, decision: "agree" } };
		const missingCookie = await app.inject(request);
		expect(missingCookie.statusCode).toBe(400);
		expect(missingCookie.body).not.toContain("has expired");
		vi.spyOn(deps.interactions, "inspect").mockResolvedValue({ state: "missing" });
		const missingRecord = await app.inject({ ...request, headers: { cookie } });
		expect(missingRecord.statusCode).toBe(400);
		expect(missingRecord.body).not.toContain("has expired");
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("rejects expired consent before any mutation", async () => {
		let now = Date.now();
		({ app, deps } = buildApp({ interactions: new FaceSetupInteractionStore(undefined, undefined, () => now) }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		now += 600_000;
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(response.statusCode).toBe(400);
		expect(response.body).toContain("has expired");
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("rejects a failed atomic claim before any mutation", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		vi.spyOn(deps.interactions, "claimConsent").mockResolvedValue(false);
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(response.statusCode).toBe(503);
		expect(response.headers.location).toBeUndefined();
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
	});

	it("does not issue a cookie or redirect when interaction creation fails", async () => {
		vi.spyOn(deps.interactions, "create").mockRejectedValue(new FaceSetupError("INTERACTION_STORE_UNAVAILABLE", 503));
		const response = await app.inject({ method: "GET", url: `/face-setup/start?client_id=${CLIENT_ID}&return_uri=${encodeURIComponent(RETURN_URI)}` });
		expect(response.statusCode).toBe(503);
		expect(response.headers.location).toBeUndefined();
		expect(response.headers["set-cookie"]).toBeUndefined();
	});

	it.each([
		["{", 400],
		["x".repeat(5000), 413]
	] as const)("preserves request rejection status for malformed or oversized bodies", async (payload, status) => {
		const response = await app.inject({
			method: "POST", url: "/face-setup/consent", headers: { "content-type": "application/json" }, payload
		});
		expect(response.statusCode).toBe(status);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
	});

	it.each(["EMAIL", "CONSENT", "ENROLLING"] as const)("does not issue a next-step response after a %s persistence failure", async phase => {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		if (phase !== "EMAIL") {
			await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		}
		if (phase === "ENROLLING") {
			await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		}
		const save = deps.interactions.save.bind(deps.interactions);
		vi.spyOn(deps.interactions, "save").mockImplementation(async (handle, interaction) =>
			interaction.phase === phase ? false : save(handle, interaction));
		const response = await app.inject({
			method: "POST", headers: { cookie },
			url: phase === "EMAIL" ? "/face-setup/email" : phase === "CONSENT" ? "/face-setup/email/code" : "/face-setup/consent",
			payload: phase === "EMAIL" ? { csrf, email: "identity@hapiinc.com" } : phase === "CONSENT" ? { csrf, code: "123456" } : { csrf, decision: "agree" }
		});

		expect(response.statusCode).toBe(503);
		expect(response.headers.location).toBeUndefined();
		if (phase === "ENROLLING") {
			const repeat = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
			expect(repeat.statusCode).toBe(303);
			expect(deps.service.start).toHaveBeenCalledTimes(1);
			expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("STARTING");
		}
	});

	it("logs only safe lifecycle fields including duplicates and consumed state", async () => {
		const logs: string[] = [];
		({ app, deps } = buildApp({}, logs));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const request = { method: "POST" as const, url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } };
		await app.inject(request);
		await app.inject(request);
		await app.inject({ ...request, payload: { csrf: "invalid", decision: "agree" } });
		await app.inject({ method: "GET", url: "/face-setup/cancel", headers: { cookie } });
		await app.inject(request);
		const events = logs.flatMap(line => line.trim().split("\n").map(value => JSON.parse(value))).filter(entry => entry.event?.startsWith("FACE_SETUP_"));
		expect(new Set(events.map(entry => entry.event))).toEqual(new Set([
			"FACE_SETUP_INTERACTION_CREATED", "FACE_SETUP_INTERACTION_LOADED", "FACE_SETUP_CONSENT_STARTED",
			"FACE_SETUP_CONSENT_ACCEPTED", "FACE_SETUP_DUPLICATE_SUBMISSION", "FACE_SETUP_ENROLLMENT_STARTED",
			"FACE_SETUP_INTERACTION_CONSUMED", "FACE_SETUP_INTERACTION_FAILED"
		]));
		expect(events.some(entry => entry.reasonCode === "INTERACTION_ALREADY_CONSUMED")).toBe(true);
		expect(events.some(entry => entry.reasonCode === "CSRF_MISMATCH")).toBe(true);
		const serialized = JSON.stringify(events);
		for (const secret of [cookie, cookie.slice(FACE_SETUP_COOKIE.length + 1), csrf, SUBJECT, "enrollment-1", "identity@hapiinc.com", "123456", "privateid.example.test"]) {
			expect(serialized).not.toContain(secret);
		}
		for (const entry of events) {
			expect(Object.keys(entry).filter(key => !["level", "time", "pid", "hostname", "reqId", "msg"].includes(key)).sort()).toEqual(
				["event", "requestId", "cookiePresent", "interactionFound", "interactionState", "remainingTtlBucket", "httpStatus",
					...(entry.reasonCode ? ["reasonCode"] : [])].sort()
			);
		}
	});

	it("uses nonce-compatible submit-once protection for both consent forms", () => {
		const rendered = faceSetupConsentPage({ csrf: "local-test-csrf" });
		const dom = new JSDOM(rendered.html, { runScripts: "dangerously" });
		const nonce = dom.window.document.querySelector("script")!.nonce;
		expect(rendered.contentSecurityPolicy).toContain(`script-src 'nonce-${nonce}'`);
		const forms = dom.window.document.querySelectorAll("form");
		const first = new dom.window.Event("submit", { cancelable: true });
		expect(forms[0].dispatchEvent(first)).toBe(true);
		expect([...dom.window.document.querySelectorAll("button")].every(button => button.disabled)).toBe(true);
		expect(dom.window.document.getElementById("setup-progress")!.hidden).toBe(false);
		expect(forms[0].dispatchEvent(new dom.window.Event("submit", { cancelable: true }))).toBe(false);
		expect(forms[1].dispatchEvent(new dom.window.Event("submit", { cancelable: true }))).toBe(false);
		dom.window.close();
	});

	it("binds enrollment to the same canonical subject that authenticated", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		const [authorityArg] = (deps.service.start as ReturnType<typeof vi.fn>).mock.calls[0] as [FaceEnrollmentAuthority];
		expect(authorityArg.sub).toBe(SUBJECT);
	});

	it("fails closed on a provider conflict during consent/start", async () => {
		({ app, deps } = buildApp({
			service: { ...serviceFixture(), start: vi.fn(async () => { throw new FaceEnrollmentError("PROVIDER_SESSION_FAILED", 502); }) }
		}));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=failed`);
	});

	it("is idempotent across duplicate callback polls while the provider is still pending", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		const first = await app.inject({ method: "GET", url: "/face-setup/callback", headers: { cookie } });
		const second = await app.inject({ method: "GET", url: "/face-setup/callback", headers: { cookie } });
		expect(first.statusCode).toBe(200);
		expect(second.statusCode).toBe(200);
		expect(first.body).toContain("Finishing Face setup");
		expect(second.body).toContain("Finishing Face setup");
	});

	it("returns a safe success outcome with no token, PUID, or subject id in the URL", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		(deps.service.status as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ statusCode: 200, body: { status: "COMPLETED" } });
		const response = await app.inject({ method: "GET", url: "/face-setup/callback", headers: { cookie } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=success`);
		expect(String(response.headers.location)).not.toContain(SUBJECT);
	});

	it("returns a safe failed outcome when enrollment fails or is conflicted", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		(deps.service.status as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ statusCode: 200, body: { status: "CONFLICT" } });
		const response = await app.inject({ method: "GET", url: "/face-setup/callback", headers: { cookie } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=failed`);
	});

	it("cancel returns a safe cancelled outcome", async () => {
		const cookie = await startCeremony(app);
		const response = await app.inject({ method: "GET", url: "/face-setup/cancel", headers: { cookie } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=cancelled`);
	});

	it("another ceremony's CSRF cannot consume or destroy a different interaction", async () => {
		const cookieA = await startCeremony(app);
		const csrfA = await reachConsent(app, cookieA);
		const { app: appB, deps: depsB } = buildApp();
		await register(appB, depsB);
		const cookieB = await startCeremony(appB);
		const response = await appB.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie: cookieB }, payload: { csrf: csrfA, decision: "agree" } });
		expect(response.statusCode).toBe(400);
		expect(response.headers.location).toBeUndefined();
		expect((await depsB.interactions.find(cookieB.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("EMAIL");
		await appB.close();
	});

	it("rejects an invalid client at start", async () => {
		const response = await app.inject({ method: "GET", url: `/face-setup/start?client_id=unknown-client&return_uri=${encodeURIComponent(RETURN_URI)}` });
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({ error: "INVALID_CLIENT" });
	});

	it("returns 404 for all routes when the ceremony is disabled", async () => {
		({ app, deps } = buildApp({ isEnabled: () => false }));
		await register(app, deps);
		const response = await app.inject({ method: "GET", url: `/face-setup/start?client_id=${CLIENT_ID}&return_uri=${encodeURIComponent(RETURN_URI)}` });
		expect(response.statusCode).toBe(404);
	});
});

describe("Face Setup atomic Redis persistence", () => {
	it("allows one claim across independent store instances, rejects stale writes, and never extends expiry", async () => {
		const redis = new RedisMock();
		const first = new FaceSetupInteractionStore(redis);
		const second = new FaceSetupInteractionStore(redis);
		try {
			const { handle, interaction } = await first.create({ clientId: CLIENT_ID, returnUri: RETURN_URI });
			const deadline = interaction.expiresAt;
			interaction.phase = "CONSENT";
			interaction.authority = {
				sub: SUBJECT, clientId: CLIENT_ID, authenticationMethod: "HAPI_EMAIL",
				authenticatedAt: new Date().toISOString(), expiresAt: Date.now() + 300_000, scope: "openid"
			};
			expect(await first.save(handle, interaction)).toBe(true);
			const a = (await first.find(handle))!;
			const b = (await second.find(handle))!;
			const key = oidcRedisKey(`face_setup_interaction:${createHash("sha256").update(handle).digest("base64url")}`);
			const before = await redis.pttl(key);
			expect(await Promise.all([first.claimConsent(handle, a, "agree"), second.claimConsent(handle, b, "agree")])).toEqual([true, false]);
			expect(await redis.pttl(key)).toBeLessThanOrEqual(before);
			expect((await second.find(handle))?.expiresAt).toBe(deadline);
			b.phase = "CONSENT";
			expect(await second.save(handle, b)).toBe(false);
			expect((await first.find(handle))?.phase).toBe("STARTING");
			await first.clear(handle);
			expect(await first.save(handle, a)).toBe(false);
			expect(await second.inspect(handle)).toMatchObject({ state: "consumed" });
			expect(await redis.pttl(oidcRedisKey(`face_setup_consumed:${createHash("sha256").update(handle).digest("base64url")}`))).toBeLessThanOrEqual(before);
		} finally { await redis.quit(); }
	});

	it("surfaces Redis failures and refuses unsuccessful NX creation", async () => {
		const redis = new RedisMock();
		const store = new FaceSetupInteractionStore(redis);
		try {
			vi.spyOn(redis, "set").mockResolvedValueOnce(null);
			await expect(store.create({ clientId: CLIENT_ID, returnUri: RETURN_URI })).rejects.toMatchObject({ code: "INTERACTION_SAVE_FAILED" });
			const { handle } = await store.create({ clientId: CLIENT_ID, returnUri: RETURN_URI });
			vi.spyOn(redis, "get").mockRejectedValueOnce(new Error("connection closed"));
			await expect(store.inspect(handle)).rejects.toMatchObject({ code: "INTERACTION_STORE_UNAVAILABLE" });
		} finally { await redis.quit(); }
	});
});
