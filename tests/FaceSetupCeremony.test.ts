import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { registerFaceSetupRoutes, type FaceSetupDependencies } from "../src/routes/faceSetup.js";
import { FaceSetupInteractionStore } from "../src/authenticators/FaceSetupInteractionStore.js";
import { FACE_SETUP_COOKIE } from "../src/authenticators/FaceSetupTypes.js";
import { FACE_AUTH_CONSENT_PURPOSE, FACE_AUTH_CONSENT_VERSION, FaceEnrollmentError,
	type FaceEnrollmentAuthority } from "../src/authenticators/FaceEnrollmentTypes.js";
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
			faceEnrollmentEligible: true, faceLoginEligible: true, consentRequired: false,
			enrollmentState: "ACTIVE" as const, consentVersion: FACE_AUTH_CONSENT_VERSION,
			consentPurpose: FACE_AUTH_CONSENT_PURPOSE, consentText: "text"
		}))
	} satisfies FaceSetupDependencies["service"];
}

function buildApp(overrides: Partial<FaceSetupDependencies> = {}) {
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
	const app = Fastify();
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

	it("a different authenticated subject's cookie cannot be reused to consume another ceremony's consent step", async () => {
		const cookieA = await startCeremony(app);
		const csrfA = await reachConsent(app, cookieA);
		const { app: appB, deps: depsB } = buildApp();
		await register(appB, depsB);
		const cookieB = await startCeremony(appB);
		// Attempt to use interaction A's csrf/cookie against app B's independently-keyed store -- app B never finds it.
		const response = await appB.inject({ method: "POST", url: "/face-setup/consent", headers: { cookie: cookieB }, payload: { csrf: csrfA, decision: "agree" } });
		expect(response.statusCode).toBe(302);
		expect(response.headers.location).toBe(`${RETURN_URI}?face_setup=failed`);
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
