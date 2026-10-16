import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import Fastify, { type FastifyInstance } from "fastify";
import formbody from "@fastify/formbody";
import RedisMock from "ioredis-mock";
import { JSDOM } from "jsdom";
import { chromium, type Browser } from "playwright";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { registerFaceSetupRoutes, type FaceSetupDependencies } from "../src/routes/faceSetup.js";
import { FaceSetupInteractionStore } from "../src/authenticators/FaceSetupInteractionStore.js";
import { FACE_SETUP_COOKIE, FaceSetupError } from "../src/authenticators/FaceSetupTypes.js";
import { faceSetupCodePage, faceSetupConsentPage, faceSetupEmailPage } from "../src/authenticators/FaceSetupPages.js";
import { chooserPage, codePage, emailPage } from "../src/oidc/UniversalLoginPages.js";
import { HapiFaceEnrollmentService } from "../src/authenticators/HapiFaceEnrollmentService.js";
import { oidcRedisKey } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import { FACE_AUTH_CONSENT_PURPOSE, FACE_AUTH_CONSENT_TEXT, FACE_AUTH_CONSENT_VERSION, FaceEnrollmentError,
	type FaceEnrollmentAuthority, type FaceEnrollmentRepository } from "../src/authenticators/FaceEnrollmentTypes.js";
import type { InteractiveEmailAuthentication, InteractiveEmailAuthority } from "../src/authentication/InteractiveEmailAuthentication.js";
import type { EmailPrincipal } from "../src/authentication/email/EmailAuthenticationTypes.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";
import { VerificationError } from "../src/email/VerificationChallenge.js";

const CLIENT_ID = "bookwrm-client";
const RETURN_URI = "https://bookwrm.example.test/bookwrm/settings/account";
const SUBJECT = randomUUID();

function clientAuthorityFixture(): FaceSetupDependencies["clientAuthority"] {
	const application = { id: "app-1", tenantId: "tenant-1", name: "Bookwrm", status: "active" as const,
		allowedAuthenticationMethods: ["HAPI_EMAIL"], allowedIdentityProviders: [], faceSetupEnabled: true };
	const tenant = { id: "tenant-1", status: "active" as const, name: "Bookwrm" };
	const client = {
		clientId: CLIENT_ID, clientSecret: "secret", tokenEndpointAuthMethod: "client_secret_basic", status: "active",
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
			if (code !== "123456") throw new VerificationError("INVALID_CODE");
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

function expectNavigation(response: { statusCode: number; headers: Record<string, unknown>; body: string }, destination: string) {
	expect(response.statusCode).toBe(200);
	expect(response.headers.location).toBeUndefined();
	const dom = new JSDOM(response.body);
	expect(dom.window.document.querySelector('meta[http-equiv="refresh"]')?.getAttribute("content")).toBe(`0;url=${destination}`);
	expect(dom.window.document.querySelector("a")?.getAttribute("href")).toBe(destination);
	expect(response.headers["content-security-policy"]).toContain("form-action 'self'");
	dom.window.close();
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
		expectNavigation(repeat, "/face-setup/continue");
		expect(deps.service.start).toHaveBeenCalledTimes(1);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
	});

	it("preserves enrollment across the live sequence of three OTP POSTs with reusable consent", async () => {
		const fixture = enrollmentFixture();
		fixture.repository.capabilityStatus.mockResolvedValue({
			faceEnrollmentEligible: true, faceLoginEligible: false, consentRequired: false,
			enrollmentState: "FAILED", consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: "text"
		});
		({ app, deps } = buildApp({ service: fixture.service }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const handle = cookie.slice(FACE_SETUP_COOKIE.length + 1);
		const request = { method: "POST" as const, url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } };
		for (let repeat = 0; repeat < 2; repeat++) {
			const response = await app.inject(request);
			expectNavigation(response, "/face-setup/continue");
			expect(response.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(handle))?.phase).toBe("ENROLLING");
		}
		const stalePage = await app.inject({ method: "GET", url: "/face-setup/email/code", headers: { cookie } });
		expectNavigation(stalePage, "/face-setup/continue");
		expect(stalePage.headers["set-cookie"]).toBeUndefined();
		const continuation = await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } });
		expect(continuation.headers.location).toBe("https://privateid.example.test/launch");
		expect(fixture.repository.acceptConsent).not.toHaveBeenCalled();
		expect(fixture.repository.reserve).toHaveBeenCalledTimes(1);
		expect(fixture.repository.bind).toHaveBeenCalledTimes(1);
		expect(fixture.provider).toHaveBeenCalledTimes(1);
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
		expect(deps.interactive.consumeResult).toHaveBeenCalledTimes(1);
	});

	it("preserves STARTING when an OTP POST repeats while consent reuse is creating a session", async () => {
		const fixture = enrollmentFixture();
		fixture.repository.capabilityStatus.mockResolvedValue({
			faceEnrollmentEligible: true, faceLoginEligible: false, consentRequired: false,
			enrollmentState: "FAILED", consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: "text"
		});
		let release = () => {};
		const gate = new Promise<void>(resolve => { release = resolve; });
		const createSession = fixture.provider.getMockImplementation()!;
		fixture.provider.mockImplementation(async transactionId => {
			await gate;
			return createSession(transactionId);
		});
		({ app, deps } = buildApp({ service: fixture.service }));
		await register(app, deps);
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		const request = { method: "POST" as const, url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } };
		const first = app.inject(request);
		try {
			await vi.waitFor(() => expect(fixture.provider).toHaveBeenCalledTimes(1));
			const repeat = await app.inject(request);
			expectNavigation(repeat, "/face-setup/continue");
			expect(repeat.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("STARTING");
		} finally { release(); }
		expectNavigation(await first, "/face-setup/continue");
		expect(fixture.repository.reserve).toHaveBeenCalledTimes(1);
		expect(fixture.provider).toHaveBeenCalledTimes(1);
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
	});

	it("returns repeated OTP submissions to existing consent without accepting it", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const repeat = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		expectNavigation(repeat, "/face-setup/consent");
		expect(repeat.headers["set-cookie"]).toBeUndefined();
		expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("CONSENT");
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		expect(deps.service.start).not.toHaveBeenCalled();
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
	});

	it.each(["csrf", "pilot", "client", "return", "freshness"] as const)("rejects an OTP replay with invalid %s without consuming enrollment", async field => {
		const pilot = vi.fn(() => true);
		({ app, deps } = buildApp({ isPilotSubject: pilot }));
		await register(app, deps);
		vi.mocked(deps.service.capabilityStatus).mockResolvedValue({
			faceEnrollmentEligible: true, faceLoginEligible: false, consentRequired: false,
			enrollmentState: "FAILED", consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: "text"
		});
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const handle = cookie.slice(FACE_SETUP_COOKIE.length + 1);
		if (field === "pilot") pilot.mockReturnValue(false);
		if (field === "client" || field === "return" || field === "freshness") {
			const interaction = (await deps.interactions.find(handle))!;
			if (field === "client") interaction.authority!.clientId = "different-client";
			if (field === "return") interaction.returnUri = "https://evil.example.test/";
			if (field === "freshness") interaction.authority!.authenticatedAt = new Date(Date.now() - 700_000).toISOString();
			expect(await deps.interactions.save(handle, interaction)).toBe(true);
		}
		const repeat = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf: field === "csrf" ? "tampered" : csrf, code: "123456" } });
		expect(repeat.statusCode).toBe(field === "csrf" ? 400 : 403);
		expect(repeat.headers.location).toBeUndefined();
		expect(repeat.headers["set-cookie"]).toBeUndefined();
		expect((await deps.interactions.find(handle))?.phase).toBe("ENROLLING");
		expect(deps.service.start).toHaveBeenCalledTimes(1);
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
	});

	it.each(["cancelled", "completed"] as const)("never resumes OTP POSTs after a %s ceremony", async outcome => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: outcome === "cancelled" ? "not_now" : "agree" } });
		if (outcome === "completed") {
			vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 200, body: { status: "COMPLETED" } });
			await app.inject({ method: "GET", url: "/face-setup/callback", headers: { cookie } });
		}
		const repeat = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		expect(repeat.statusCode).toBe(400);
		expect(repeat.headers.location).toBeUndefined();
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
		expect(deps.service.start).toHaveBeenCalledTimes(outcome === "cancelled" ? 0 : 1);
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
		expectNavigation(response, `${RETURN_URI}?face_setup=cancelled`);
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("Agree records FACE_AUTH_V1 consent exactly once and redirects to PrivateID enrollment", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		const response = await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expectNavigation(response, "/face-setup/continue");
		const continuation = await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } });
		expect(continuation.statusCode).toBe(302);
		expect(continuation.headers.location).toBe("https://privateid.example.test/launch");
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
		expectNavigation(first, "/face-setup/continue");
		expect((await deps.interactions.find(handle))?.phase).toBe("ENROLLING");
		for (let repeat = 0; repeat < 2; repeat++) {
			const response = await app.inject(request);
			expectNavigation(response, "/face-setup/continue");
			expect(response.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(handle))?.phase).toBe("ENROLLING");
		}
		const continuation = await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } });
		expect(continuation.statusCode).toBe(302);
		expect(continuation.headers.location).toBe("https://privateid.example.test/launch");
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
		expectNavigation(duplicate, "/face-setup/continue");
		const pending = await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } });
		expect(pending.statusCode).toBe(200);
		expect(pending.body).toContain("Finishing Face setup");
		release();
		for (const response of await Promise.all([first, second])) expectNavigation(response, "/face-setup/continue");
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
			expectNavigation(repeat, "/face-setup/continue");
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
		await app.inject({ method: "GET", url: `/face-setup/cancel?csrf=${encodeURIComponent(csrf)}`, headers: { cookie } });
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
		expectNavigation(response, `${RETURN_URI}?face_setup=failed`);
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
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		const response = await app.inject({ method: "GET", url: `/face-setup/cancel?csrf=${encodeURIComponent(csrf)}`, headers: { cookie } });
		expectNavigation(response, `${RETURN_URI}?face_setup=cancelled`);
	});

	it.each(["START", "VERIFY", "RESEND"] as const)("single-claims concurrent email %s operations", async operation => {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		if (operation !== "START") {
			await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		}
		let release = () => {};
		const gate = new Promise<void>(resolve => { release = resolve; });
		if (operation === "START") {
			const start = vi.mocked(deps.interactive.start).getMockImplementation()!;
			vi.mocked(deps.interactive.start).mockImplementation(async (...args) => { await gate; return start(...args); });
		} else if (operation === "VERIFY") {
			const verify = vi.mocked(deps.interactive.verify).getMockImplementation()!;
			vi.mocked(deps.interactive.verify).mockImplementation(async (...args) => { await gate; return verify(...args); });
		} else {
			const resend = vi.mocked(deps.interactive.resend).getMockImplementation()!;
			vi.mocked(deps.interactive.resend).mockImplementation(async (...args) => { await gate; return resend(...args); });
		}
		const request = {
			method: "POST" as const, headers: { cookie },
			url: operation === "START" ? "/face-setup/email" : operation === "VERIFY" ? "/face-setup/email/code" : "/face-setup/email/resend",
			payload: { csrf, email: "identity@hapiinc.com", code: "123456" }
		};
		const first = app.inject(request);
		try {
			const mock = operation === "START" ? deps.interactive.start : operation === "VERIFY" ? deps.interactive.verify : deps.interactive.resend;
			await vi.waitFor(() => expect(mock).toHaveBeenCalledTimes(1));
			const repeat = await app.inject(request);
			expect(repeat.statusCode).toBe(303);
			expect(repeat.headers.location).toBe("/face-setup/email/code");
			expect(repeat.headers["set-cookie"]).toBeUndefined();
			expect(mock).toHaveBeenCalledTimes(1);
			const polling = await app.inject({ method: "GET", url: "/face-setup/email/code", headers: { cookie } });
			expect(polling.body).toContain("Finishing Face setup");
		} finally { release(); }
		expect((await first).statusCode).toBe(200);
		expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.emailOperation).toBeUndefined();
	});

	it("does not send a second challenge for a sequential email-submit replay", async () => {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		const request = { method: "POST" as const, url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } };
		expect((await app.inject(request)).statusCode).toBe(200);
		const repeat = await app.inject(request);
		expect(repeat.statusCode).toBe(303);
		expect(repeat.headers.location).toBe("/face-setup/email/code");
		expect(repeat.headers["set-cookie"]).toBeUndefined();
		expect(deps.interactive.start).toHaveBeenCalledTimes(1);
	});

	it.each(["INVALID_CODE", "CHALLENGE_EXPIRED"])("rejects %s without advancing authority or enrollment", async code => {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		vi.mocked(deps.interactive.verify).mockRejectedValueOnce(new VerificationError(code));
		const response = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		expect(response.statusCode).toBe(401);
		const current = await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1));
		expect(current?.phase).toBe("EMAIL");
		expect(current?.authority).toBeUndefined();
		expect(current?.emailOperation).toBeUndefined();
		expect(deps.interactive.consumeResult).not.toHaveBeenCalled();
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("fails closed without repeating an uncertain OTP verification", async () => {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		vi.mocked(deps.interactive.verify).mockRejectedValueOnce(new Error("unexpected storage failure"));
		const request = { method: "POST" as const, url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } };
		expect((await app.inject(request)).statusCode).toBe(500);
		expect((await app.inject(request)).statusCode).toBe(303);
		expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.emailOperation).toBe("VERIFY");
		expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("preserves advanced state on stale email, resend, and email-page requests", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		for (const request of [
			{ method: "GET" as const, url: "/face-setup/email" },
			{ method: "POST" as const, url: "/face-setup/email", payload: { csrf, email: "identity@hapiinc.com" } },
			{ method: "POST" as const, url: "/face-setup/email/resend", payload: { csrf } }
		]) {
			const response = await app.inject({ ...request, headers: { cookie } });
			expectNavigation(response, "/face-setup/continue");
			expect(response.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("ENROLLING");
		}
		expect(deps.interactive.start).toHaveBeenCalledTimes(1);
		expect(deps.interactive.resend).not.toHaveBeenCalled();
		expect(deps.service.start).toHaveBeenCalledTimes(1);
	});

	it("rejects premature callback and consent GETs without consuming email state", async () => {
		const cookie = await startCeremony(app);
		for (const url of ["/face-setup/callback", "/face-setup/consent"]) {
			const response = await app.inject({ method: "GET", url, headers: { cookie } });
			expect(response.statusCode).toBe(400);
			expect(response.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("EMAIL");
		}
		expect(deps.service.status).not.toHaveBeenCalled();
	});

	it("single-consumes concurrent successful callbacks and rejects subsequent replays", async () => {
		const cookie = await startCeremony(app);
		const csrf = await reachConsent(app, cookie);
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		let release = () => {};
		const gate = new Promise<void>(resolve => { release = resolve; });
		vi.mocked(deps.service.status).mockImplementation(async () => { await gate; return { statusCode: 200, body: { status: "COMPLETED" } }; });
		const request = { method: "GET" as const, url: "/face-setup/callback", headers: { cookie } };
		const first = app.inject(request);
		const second = app.inject(request);
		try { await vi.waitFor(() => expect(deps.service.status).toHaveBeenCalledTimes(2)); }
		finally { release(); }
		const results = await Promise.all([first, second]);
		expect(results.map(result => result.statusCode).sort()).toEqual([302, 409]);
		expect(results.filter(result => result.headers["set-cookie"])).toHaveLength(1);
		expect(results.find(result => result.statusCode === 302)?.headers.location).toBe(`${RETURN_URI}?face_setup=success`);
		const replay = await app.inject(request);
		expect(replay.statusCode).toBe(400);
		expect(deps.service.start).toHaveBeenCalledTimes(1);
	});

	it("rejects cancellation without CSRF and does not resume after a valid cancellation", async () => {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		for (const url of ["/face-setup/cancel", "/face-setup/cancel?csrf=invalid"]) {
			const response = await app.inject({ method: "GET", url, headers: { cookie } });
			expect(response.statusCode).toBe(400);
			expect(response.headers["set-cookie"]).toBeUndefined();
			expect((await deps.interactions.find(cookie.slice(FACE_SETUP_COOKIE.length + 1)))?.phase).toBe("EMAIL");
		}
		const request = { method: "GET" as const, url: `/face-setup/cancel?csrf=${encodeURIComponent(csrf)}`, headers: { cookie } };
		expectNavigation(await app.inject(request), `${RETURN_URI}?face_setup=cancelled`);
		expect((await app.inject(request)).statusCode).toBe(200);
		expect((await app.inject({ method: "GET", url: "/face-setup/email/code", headers: { cookie } })).statusCode).toBe(400);
		expect(deps.service.start).not.toHaveBeenCalled();
	});

	it("never clears a newer interaction snapshot during a stale terminal consume", async () => {
		const cookie = await startCeremony(app);
		const handle = cookie.slice(FACE_SETUP_COOKIE.length + 1);
		const stale = (await deps.interactions.find(handle))!;
		const current = (await deps.interactions.find(handle))!;
		expect(await deps.interactions.claimEmail(handle, current, "START")).toBe(true);
		expect(await deps.interactions.consume(handle, stale)).toBe(false);
		expect((await deps.interactions.find(handle))?.emailOperation).toBe("START");
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

describe("H5.4D-2 dedicated Face Setup callback", () => {
	let app: FastifyInstance;
	let deps: FaceSetupDependencies;

	beforeEach(async () => {
		({ app, deps } = buildApp());
		await register(app, deps);
	});
	afterEach(async () => {
		vi.useRealTimers();
		await app.close();
	});

	async function enroll() {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		await app.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie }, payload: { csrf, decision: "agree" } });
		expect((await deps.interactions.find(cookie.split("=")[1]))?.phase).toBe("ENROLLING");
		return cookie;
	}
	const capability = (enrollmentState: "ACTIVE" | "NOT_ENROLLED" | "FAILED", faceLoginEligible = enrollmentState === "ACTIVE") => ({
		faceEnrollmentEligible: true, faceLoginEligible, consentRequired: false, enrollmentState,
		consentVersion: FACE_AUTH_CONSENT_VERSION, consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: FACE_AUTH_CONSENT_TEXT
	} as const);
	const callback = (cookie?: string, query = "") =>
		app.inject({ method: "GET", url: `/face-setup/callback${query}`, headers: cookie ? { cookie } : {} });

	it("starts the Face Setup provider session with the dedicated Face Setup return target only", async () => {
		await enroll();
		expect(deps.service.start).toHaveBeenCalledTimes(1);
		expect(vi.mocked(deps.service.start).mock.calls[0][1]).toEqual({ returnTo: "face-setup" });
	});

	it("success: resolves from durable enrollment + authenticator state and ignores provider query parameters", async () => {
		const cookie = await enroll();
		vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 200, body: { status: "COMPLETED" } });
		const response = await callback(cookie, "?reason=failed&status=FAILED&sub=attacker&puid=x");
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=success`);
		expect(vi.mocked(deps.service.status).mock.calls[0][0]).toBe("enrollment-1");
		expect(vi.mocked(deps.service.status).mock.calls[0][1].sub).toBe(SUBJECT);
		expect(String(response.headers["set-cookie"])).toContain("Max-Age=0");
		expect(response.body).not.toContain("Unable to resume enrollment");
	});

	it("success claimed by the browser is not trusted while the durable enrollment is still pending", async () => {
		const cookie = await enroll();
		const response = await callback(cookie, "?reason=success&status=COMPLETED");
		expect(response.statusCode).toBe(200);
		expect(response.body).toContain("Finishing Face setup");
		expect(response.headers.location).toBeUndefined();
	});

	it.each(["CONFLICT", "FAILED"])("%s: preserves identity and returns a safe failed outcome without consulting authenticator state", async status => {
		const cookie = await enroll();
		vi.mocked(deps.service.capabilityStatus).mockClear();
		vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 200, body: { status } });
		const response = await callback(cookie);
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=failed`);
		expect(deps.service.capabilityStatus).not.toHaveBeenCalled();
		expect(deps.service.start).toHaveBeenCalledTimes(1);
	});

	it("cancelled/abandoned provider ceremony (expired enrollment, no authenticator) returns a safe failed outcome", async () => {
		const cookie = await enroll();
		vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 410, body: { status: "EXPIRED" } });
		vi.mocked(deps.service.capabilityStatus).mockResolvedValueOnce(capability("NOT_ENROLLED"));
		const response = await callback(cookie, "?reason=cancelled");
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=failed`);
	});

	it("late return after the enrollment window resolves success from the finalized authenticator", async () => {
		const cookie = await enroll();
		vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 410, body: { status: "EXPIRED" } });
		vi.mocked(deps.service.capabilityStatus).mockResolvedValueOnce(capability("ACTIVE"));
		const response = await callback(cookie);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=success`);
	});

	it("an unresolvable enrollment (not found / not authorized) fails safe without becoming success", async () => {
		const cookie = await enroll();
		vi.mocked(deps.service.status).mockRejectedValueOnce(new FaceEnrollmentError("ENROLLMENT_NOT_FOUND", 404));
		vi.mocked(deps.service.capabilityStatus).mockResolvedValueOnce(capability("FAILED"));
		const response = await callback(cookie);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=failed`);
	});

	it("a legitimate return after the 5-minute email freshness window still resolves while the interaction lives", async () => {
		const cookie = await enroll();
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(Date.now() + 6 * 60_000);
		// Launching enrollment still requires fresh email authority.
		expect((await app.inject({ method: "GET", url: "/face-setup/continue", headers: { cookie } })).statusCode).toBe(403);
		vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 200, body: { status: "COMPLETED" } });
		const response = await callback(cookie);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=success`);
		const statusAuthority = vi.mocked(deps.service.status).mock.calls.at(-1)![1];
		expect(statusAuthority.sub).toBe(SUBJECT);
		expect(statusAuthority.clientId).toBe(CLIENT_ID);
		expect(statusAuthority.expiresAt).toBeGreaterThan(Date.now());
		expect(statusAuthority.expiresAt).toBeLessThanOrEqual(Date.now() + 4 * 60_000);
	});

	it("still rejects a callback whose subject is no longer eligible (subject binding is not weakened)", async () => {
		const cookie = await enroll();
		vi.mocked(deps.identitySubjects.findByOidcSubject).mockResolvedValue(identitySubjectFixture({ status: "SUSPENDED" as IdentitySubject["status"] }));
		vi.mocked(deps.service.status).mockClear();
		const response = await callback(cookie);
		expect(response.statusCode).toBe(403);
		expect(deps.service.status).not.toHaveBeenCalled();
	});

	it("duplicate callback after resolution cannot re-resolve or create anything", async () => {
		const cookie = await enroll();
		vi.mocked(deps.service.status).mockResolvedValueOnce({ statusCode: 200, body: { status: "COMPLETED" } });
		expect((await callback(cookie)).headers.location).toBe(`${RETURN_URI}?face_setup=success`);
		const calls = vi.mocked(deps.service.status).mock.calls.length;
		const duplicate = await callback(cookie);
		expect(duplicate.statusCode).toBe(400);
		expect(duplicate.body).toContain("We couldn&#39;t continue Face Login setup.");
		expect(vi.mocked(deps.service.status).mock.calls.length).toBe(calls);
		expect(deps.service.start).toHaveBeenCalledTimes(1);
	});

	it("stale callback (interaction expired or cookie absent) shows a safe page and makes no enrollment call", async () => {
		const cookie = await enroll();
		vi.mocked(deps.service.status).mockClear();
		const missing = await callback();
		expect(missing.statusCode).toBe(400);
		expect(missing.body).not.toContain("Unable to resume enrollment");
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(Date.now() + 11 * 60_000);
		const stale = await callback(cookie);
		expect(stale.statusCode).toBe(400);
		// Redis evicts at TTL, so the record is either reported expired or already gone -- both are safe.
		expect(stale.body).toMatch(/This sign-in request has expired|We couldn&#39;t continue Face Login setup\./);
		expect(stale.body).not.toContain("Unable to resume enrollment");
		expect(deps.service.status).not.toHaveBeenCalled();
	});
});

describe("H5.4D-2 Face Setup OTP presentation and resend", () => {
	let app: FastifyInstance;
	let deps: FaceSetupDependencies;

	beforeEach(async () => {
		({ app, deps } = buildApp());
		await register(app, deps);
	});
	afterEach(async () => { await app.close(); });

	async function reachCode() {
		const cookie = await startCeremony(app);
		const page = await app.inject({ method: "GET", url: "/face-setup/email", headers: { cookie } });
		const csrf = csrfFromHtml(page.body);
		const code = await app.inject({ method: "POST", url: "/face-setup/email", headers: { cookie }, payload: { csrf, email: "identity@hapiinc.com" } });
		return { cookie, csrf, code, handle: cookie.split("=")[1] };
	}
	const styleOf = (html: string) => new JSDOM(html).window.document.querySelector("style")?.textContent;

	it("uses the Universal Login OTP presentation with Face context, masked email and six-digit entry", async () => {
		const { code } = await reachCode();
		expect(code.statusCode).toBe(200);
		const document = new JSDOM(code.body).window.document;
		expect(document.querySelector(".progress")?.textContent).toBe("STEP 2 OF 2");
		expect(document.querySelector("h1")?.textContent).toBe("Check your inbox");
		expect(document.body.textContent).toContain("Continue setting up Face Login.");
		expect(document.body.textContent).toContain("Enter the 6-digit code we sent to");
		expect(document.querySelector(".email-hint")?.textContent).toBe("i***@hapiinc.com");
		expect(code.body).not.toContain("identity@hapiinc.com");
		const input = document.querySelector<HTMLInputElement>("input#code.otp-code")!;
		expect(input.getAttribute("inputmode")).toBe("numeric");
		expect(input.getAttribute("autocomplete")).toBe("one-time-code");
		expect(input.getAttribute("pattern")).toBe("[0-9]{6,9}");
		expect(input.getAttribute("aria-label")).toBe("Six-digit verification code");
		expect(document.querySelector("#otp-submit")?.textContent).toBe("Verify & Continue");
		expect(document.body.textContent).toContain("Didn't get it?");
		expect(document.querySelector("#resend-form")?.getAttribute("action")).toBe("/face-setup/email/resend");
		expect(document.querySelector("#resend-submit")?.textContent).toBe("Resend code");
		expect(document.querySelector("#otp-status")?.getAttribute("aria-live")).toBe("polite");
		expect(document.querySelector("footer")?.textContent).toBe("Secure identity powered by HAPI ID");
		const csp = String(code.headers["content-security-policy"]);
		expect(csp).toMatch(/script-src 'nonce-[^']+'/);
		expect(csp).toContain("form-action 'self'");
		expect(csp).not.toContain("unsafe-inline");
		expect(document.querySelector("script")?.getAttribute("nonce")).toBeTruthy();
	});

	it("shares the identical Universal Login visual system (styles, branding, OTP control) for the Bookwrm client", () => {
		const clientId = "bookwrm-base44-production";
		const face = faceSetupCodePage({ csrf: "fixture", clientId, emailHint: "i***@hapiinc.com" });
		const login = codePage({ csrf: "fixture", clientId });
		expect(styleOf(face.html)).toBe(styleOf(login.html));
		const faceDocument = new JSDOM(face.html).window.document;
		const loginDocument = new JSDOM(login.html).window.document;
		expect(faceDocument.querySelector("main")?.className).toBe(loginDocument.querySelector("main")?.className);
		expect(faceDocument.querySelector("main > :first-child")?.outerHTML).toBe(loginDocument.querySelector("main > :first-child")?.outerHTML);
		expect(faceDocument.querySelector("input.otp-code")?.outerHTML).toBe(loginDocument.querySelector("input.otp-code")?.outerHTML);
		expect(faceDocument.querySelector("#otp-submit")?.textContent).toBe(loginDocument.querySelector("#otp-submit")?.textContent);
		expect(faceDocument.querySelector("footer")?.textContent).toBe("Secure identity powered by HAPI ID");
		expect(faceDocument.querySelector("#otp-form")?.getAttribute("action")).toBe("/face-setup/email/code");
	});

	it("resend reuses the same H4 challenge inside the same ceremony without resetting it or starting enrollment", async () => {
		const { cookie, csrf, handle } = await reachCode();
		const before = (await deps.interactions.find(handle))!;
		const response = await app.inject({ method: "POST", url: "/face-setup/email/resend", headers: { cookie }, payload: { csrf } });
		expect(response.statusCode).toBe(200);
		expect(response.body).toContain("We sent a new code. Earlier codes no longer work.");
		expect(deps.interactive.resend).toHaveBeenCalledWith(expect.anything(), "challenge-1", "AUTHENTICATION");
		const after = (await deps.interactions.find(handle))!;
		expect(after.phase).toBe("EMAIL");
		expect(after.email).toEqual(before.email);
		expect(after.expiresAt).toBe(before.expiresAt);
		expect(after.csrf).toBe(before.csrf);
		expect(deps.interactive.start).toHaveBeenCalledTimes(1);
		expect(deps.service.start).not.toHaveBeenCalled();
		const verified = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		expect(verified.statusCode).toBe(200);
		expect(deps.interactive.verify).toHaveBeenCalledWith(expect.anything(), "challenge-1", "123456", "AUTHENTICATION");
	});

	it("resend cooldown is enforced by H4 and surfaced without losing the ceremony", async () => {
		const { cookie, csrf, handle } = await reachCode();
		vi.mocked(deps.interactive.resend).mockRejectedValueOnce(new VerificationError("RESEND_TOO_SOON", 429));
		const response = await app.inject({ method: "POST", url: "/face-setup/email/resend", headers: { cookie }, payload: { csrf } });
		expect(response.statusCode).toBe(429);
		expect(response.body).toContain("Please wait before requesting another code.");
		expect(response.body).toContain("Resend code");
		expect((await deps.interactions.find(handle))?.phase).toBe("EMAIL");
		expect((await deps.interactions.find(handle))?.emailOperation).toBeUndefined();
		const verified = await app.inject({ method: "POST", url: "/face-setup/email/code", headers: { cookie }, payload: { csrf, code: "123456" } });
		expect(verified.statusCode).toBe(200);
	});

	it("a non-throttle resend rejection is a safe 400 that never retries or restarts the challenge", async () => {
		const { cookie, csrf } = await reachCode();
		vi.mocked(deps.interactive.resend).mockRejectedValueOnce(new VerificationError("CHALLENGE_EXPIRED", 410));
		const response = await app.inject({ method: "POST", url: "/face-setup/email/resend", headers: { cookie }, payload: { csrf } });
		expect(response.statusCode).toBe(400);
		expect(response.body).toContain("A new code can&#39;t be sent for this request.");
		expect(deps.interactive.start).toHaveBeenCalledTimes(1);
	});

	it("repeated resend is safe: same challenge, no identity or enrollment side effects, CSRF still required", async () => {
		const { cookie, csrf, handle } = await reachCode();
		const before = (await deps.interactions.find(handle))!;
		for (let index = 0; index < 3; index++) {
			const response = await app.inject({ method: "POST", url: "/face-setup/email/resend", headers: { cookie }, payload: { csrf } });
			expect(response.statusCode).toBe(200);
		}
		const forged = await app.inject({ method: "POST", url: "/face-setup/email/resend", headers: { cookie }, payload: { csrf: "forged" } });
		expect(forged.statusCode).toBe(400);
		expect(deps.interactive.resend).toHaveBeenCalledTimes(3);
		expect(vi.mocked(deps.interactive.resend).mock.calls.every(call => call[1] === "challenge-1")).toBe(true);
		expect(deps.interactive.start).toHaveBeenCalledTimes(1);
		expect(deps.service.start).not.toHaveBeenCalled();
		expect(deps.service.acceptConsent).not.toHaveBeenCalled();
		const after = (await deps.interactions.find(handle))!;
		expect(after.expiresAt).toBe(before.expiresAt);
		expect(after.email).toEqual(before.email);
	});
});

describe("H5.4 real Chromium form/CSP navigation contract", () => {
	let browser: Browser;
	let destination: Server;
	let destinationOrigin: string;
	const origin = "https://identity.bookwrm.com";

	beforeAll(async () => {
		const directory = mkdtempSync(join(tmpdir(), "hapi-browser-tls-"));
		const keyPath = join(directory, "key.pem");
		const certPath = join(directory, "cert.pem");
		try {
			execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
				"-keyout", keyPath, "-out", certPath, "-subj", "/CN=localhost", "-days", "1"],
			{ stdio: ["ignore", "pipe", "pipe"] });
			destination = createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (_request, response) => {
				response.setHeader("Content-Type", "text/html");
				response.end("<h1>Mock destination</h1>");
			});
		} finally {
			rmSync(keyPath, { force: true });
			rmSync(certPath, { force: true });
			rmSync(directory, { recursive: true });
		}
		await new Promise<void>(resolve => destination.listen(0, "127.0.0.1", resolve));
		destinationOrigin = `https://127.0.0.1:${(destination.address() as AddressInfo).port}`;
		browser = await chromium.launch();
	});
	afterAll(async () => {
		await browser?.close();
		if (destination) await new Promise<void>((resolve, reject) => destination.close(error => error ? reject(error) : resolve()));
	});

	it("reproduces the original same-origin OTP POST succeeding before Chrome blocks its external 302", async () => {
		const context = await browser.newContext();
		try {
			const page = await context.newPage();
			const rendered = faceSetupCodePage({ csrf: "local-fixture" });
			const requests: string[] = [];
			await context.route("**/*", async route => {
				const request = route.request();
				requests.push(`${request.method()} ${new URL(request.url()).origin}`);
				if (request.method() === "POST") {
					return route.fulfill({ status: 302, headers: { location: "https://privateid.example.test/launch" } });
				}
				return route.fulfill({ contentType: "text/html", body: rendered.html,
					headers: { "content-security-policy": rendered.contentSecurityPolicy } });
			});
			await page.goto(`${origin}/face-setup/email/code`);
			expect(await page.evaluate(() => location.origin)).toBe(origin);
			expect(await page.locator("#otp-form").getAttribute("action")).toBe("/face-setup/email/code");
			expect(await page.locator("#otp-form").evaluate(form => (form as HTMLFormElement).action)).toBe(`${origin}/face-setup/email/code`);
			expect(await page.locator('meta[http-equiv="Content-Security-Policy"]').count()).toBe(0);
			await page.locator("#code").fill("123456");
			const violation = page.waitForEvent("console", { predicate: message =>
				message.type() === "error" && message.text().includes("form-action 'self'") });
			await page.getByRole("button", { name: "Verify & Continue", exact: true }).click();
			expect((await violation).text()).toContain(`Sending form data to '${origin}/face-setup/email/code'`);
			expect(requests).toEqual([`GET ${origin}`, `POST ${origin}`]);
			expect(page.url()).toBe(`${origin}/face-setup/email/code`);
		} finally { await context.close(); }
	});

	const formPages = [
		["Face email/cancel", () => faceSetupEmailPage({ csrf: "local-fixture" })],
		["Face OTP", () => faceSetupCodePage({ csrf: "local-fixture" })],
		["Face consent", () => faceSetupConsentPage({ csrf: "local-fixture" })],
		...["generic-client", "bookwrm-base44-production"].flatMap(clientId => [
			[`${clientId} chooser`, () => chooserPage({ clientId, csrf: "local-fixture", emailAvailable: true, faceAvailable: true })],
			[`${clientId} email`, () => emailPage({ clientId, csrf: "local-fixture" })],
			[`${clientId} OTP/resend`, () => codePage({ clientId, csrf: "local-fixture" })]
		] as const)
	] as const;

	it.each(formPages)("submits every %s form under form-action self using the actual document origin", async (_label, render) => {
		const context = await browser.newContext();
		try {
			const page = await context.newPage();
			const rendered = render();
			const errors: string[] = [];
			page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
			const policy = rendered.contentSecurityPolicy.includes("form-action")
				? rendered.contentSecurityPolicy : `${rendered.contentSecurityPolicy}; form-action 'self'`;
			await context.route("**/*", route => route.fulfill({ contentType: "text/html",
				body: new URL(route.request().url()).pathname === "/fixture" ? rendered.html : "<h1>Form received</h1>",
				headers: { "content-security-policy": policy } }));
			// A non-default external port makes any hardcoded canonical-origin action fail.
			const actualOrigin = `${origin}:8443`;
			await page.goto(`${actualOrigin}/fixture`);
			const actions = await page.locator("form").evaluateAll(forms => forms.map(form => form.getAttribute("action")));
			expect(actions.length).toBeGreaterThan(0);
			for (let index = 0; index < actions.length; index++) {
				const action = actions[index];
				expect(action).toMatch(/^\/(?!\/)/);
				expect(new URL(action!, actualOrigin).origin).toBe(actualOrigin);
				if (index) await page.goto(`${actualOrigin}/fixture`);
				const form = page.locator("form").nth(index);
				for (const input of await form.locator("input[required]").all()) {
					await input.fill(await input.getAttribute("type") === "email" ? "local@example.test" : "123456");
				}
				await Promise.all([
					page.waitForURL(url => url.pathname === action),
					form.locator("button").click()
				]);
				expect(await page.getByRole("heading").textContent()).toBe("Form received");
			}
			expect(errors).toEqual([]);
		} finally { await context.close(); }
	});

	async function ceremony(consentRequired: boolean) {
		const { app, deps } = buildApp();
		await app.register(formbody);
		const returnUri = `${destinationOrigin}/return`;
		const launchUrl = `${destinationOrigin}/launch`;
		const findClient = vi.mocked(deps.clientAuthority.clients.findByClientId).getMockImplementation()!;
		vi.mocked(deps.clientAuthority.clients.findByClientId).mockImplementation(async clientId => {
			const client = await findClient(clientId);
			return client ? { ...client, redirectUris: [returnUri] } : undefined;
		});
		vi.mocked(deps.service.start).mockResolvedValue({
			enrolled: false, enrollmentId: "enrollment-1", launchUrl, expiresAt: new Date(Date.now() + 300_000).toISOString()
		});
		vi.mocked(deps.service.capabilityStatus).mockResolvedValue({
			faceEnrollmentEligible: true, faceLoginEligible: false, consentRequired,
			enrollmentState: "FAILED", consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: FACE_AUTH_CONSENT_TEXT
		});
		let otpHtml = "";
		let otpCsp = "";
		app.addHook("onSend", async (request, reply, payload) => {
			if (request.method === "POST" && request.url === "/face-setup/email" && typeof payload === "string") {
				otpHtml = payload;
				otpCsp = String(reply.getHeader("Content-Security-Policy"));
			}
			return payload;
		});
		app.get("/fixture/stale-otp", async (_request, reply) =>
			reply.header("Content-Security-Policy", otpCsp).type("text/html").send(otpHtml));
		await registerFaceSetupRoutes(app, deps);
		const localOrigin = await app.listen({ host: "127.0.0.1", port: 0 });
		const context = await browser.newContext({ ignoreHTTPSErrors: true });
		const page = await context.newPage();
		page.setDefaultTimeout(3000);
		const errors: string[] = [];
		page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
		return { app, deps, page, context, errors, origin: localOrigin, returnUri, launchUrl,
			close: async () => { await context.close(); await app.close(); } };
	}

	it.each([false, true])("verifies the first OTP exactly once and reaches a mocked provider without CSP errors (consentRequired=%s)", async consentRequired => {
		const flow = await ceremony(consentRequired);
		try {
			const { page, deps, context } = flow;
			await page.goto(`${flow.origin}/face-setup/start?client_id=${CLIENT_ID}&return_uri=${encodeURIComponent(flow.returnUri)}`);
			await page.locator("#email").fill("local@example.test");
			await page.getByRole("button", { name: "Continue", exact: true }).click();
			await page.locator("#code").fill("123456");
			await page.getByRole("button", { name: "Verify & Continue", exact: true }).click();
			if (consentRequired) await page.getByRole("button", { name: "Agree & Continue", exact: true }).click();
			await page.waitForURL(flow.launchUrl);
			const cookie = (await context.cookies(`${flow.origin}/face-setup/email`)).find(cookie => cookie.name === FACE_SETUP_COOKIE)!;
			expect((await deps.interactions.find(cookie.value))?.phase).toBe("ENROLLING");
			for (let repeat = 0; repeat < 2; repeat++) {
				await page.goto(`${flow.origin}/fixture/stale-otp`);
				await page.locator("#code").fill("123456");
				await page.getByRole("button", { name: "Verify & Continue", exact: true }).click();
				await page.waitForURL(flow.launchUrl);
			}
			expect(deps.interactive.verify).toHaveBeenCalledTimes(1);
			expect(deps.interactive.consumeResult).toHaveBeenCalledTimes(1);
			expect(deps.service.start).toHaveBeenCalledTimes(1);
			expect(deps.service.acceptConsent).toHaveBeenCalledTimes(consentRequired ? 1 : 0);
			expect(flow.errors).toEqual([]);
		} finally { await flow.close(); }
	});

	it.each(["email", "consent"])("cancels from the %s form without a blocked return or enrollment mutation", async phase => {
		const flow = await ceremony(true);
		try {
			await flow.page.goto(`${flow.origin}/face-setup/start?client_id=${CLIENT_ID}&return_uri=${encodeURIComponent(flow.returnUri)}`);
			if (phase === "consent") {
				await flow.page.locator("#email").fill("local@example.test");
				await flow.page.getByRole("button", { name: "Continue", exact: true }).click();
				await flow.page.locator("#code").fill("123456");
				await flow.page.getByRole("button", { name: "Verify & Continue", exact: true }).click();
			}
			await flow.page.getByRole("button", { name: "Not Now", exact: true }).click();
			await flow.page.waitForURL(`${flow.returnUri}?face_setup=cancelled`);
			expect(flow.deps.service.acceptConsent).not.toHaveBeenCalled();
			expect(flow.deps.service.start).not.toHaveBeenCalled();
			expect((await flow.context.cookies(`${flow.origin}/face-setup/email`)).some(cookie => cookie.name === FACE_SETUP_COOKIE)).toBe(false);
			expect(flow.errors).toEqual([]);
		} finally { await flow.close(); }
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
