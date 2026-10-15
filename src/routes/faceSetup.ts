import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { VerificationError } from "../email/VerificationChallenge.js";
import { resolveH1ClientAuthority, type H1ClientAuthority } from "../identity/H1ClientAuthority.js";
import type { IdentityRegistry } from "../identity/IdentityRegistry.js";
import type { InteractiveEmailAuthentication, InteractiveEmailAuthority } from "../authentication/InteractiveEmailAuthentication.js";
import { EmailAuthenticationError } from "../authentication/email/EmailAuthenticationTypes.js";
import {
	FACE_AUTH_CONSENT_PURPOSE, FACE_AUTH_CONSENT_VERSION, FACE_ENROLLMENT_FRESHNESS_MS,
	FaceEnrollmentError, requireRecentEmailAuthority, type FaceEnrollmentAuthority
} from "../authenticators/FaceEnrollmentTypes.js";
import type { HapiFaceEnrollmentService } from "../authenticators/HapiFaceEnrollmentService.js";
import { FaceSetupInteractionStore } from "../authenticators/FaceSetupInteractionStore.js";
import {
	FACE_SETUP_COOKIE, FaceSetupError, buildOutcomeRedirect, type FaceSetupInteraction
} from "../authenticators/FaceSetupTypes.js";
import { logFaceSetup, type FaceSetupReason } from "../authenticators/FaceSetupDiagnostics.js";
import {
	faceSetupCodePage, faceSetupConsentPage, faceSetupEmailPage, faceSetupMessagePage, faceSetupNavigationPage, faceSetupProcessingPage
} from "../authenticators/FaceSetupPages.js";

export type FaceSetupDependencies = {
	interactions: FaceSetupInteractionStore;
	service: Pick<HapiFaceEnrollmentService, "acceptConsent" | "start" | "status" | "capabilityStatus">;
	interactive: InteractiveEmailAuthentication;
	identitySubjects: Pick<IdentityRegistry, "findByOidcSubject">;
	clientAuthority: H1ClientAuthority;
	// Certified pilot gate (H5.4 #10): checked against the canonical, server-resolved oidc subject only --
	// never against a client-supplied email or user id. An empty/undefined predicate denies everyone.
	isPilotSubject: (oidcSubject: string) => boolean;
	isEnabled: () => boolean;
};

const expiredPage = () => faceSetupMessagePage({
	title: "This sign-in request has expired",
	message: "Return to Bookwrm and choose \"Set Up Face Login\" again to start over."
});

const notEligiblePage = (message: string) => faceSetupMessagePage({ title: "Face Login isn't available", message });
const continuationFailedPage = () => faceSetupMessagePage({
	title: "We couldn't continue Face Login setup.",
	message: "Return to Bookwrm and start Face Login setup again."
});

function cookieHeader(handle: string | null): string {
	return handle
		? `${FACE_SETUP_COOKIE}=${handle}; Path=/face-setup; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
		: `${FACE_SETUP_COOKIE}=; Path=/face-setup; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function readHandle(request: FastifyRequest): string | undefined {
	return request.headers.cookie?.split(";").map(value => value.trim())
		.find(value => value.startsWith(`${FACE_SETUP_COOKIE}=`))?.slice(FACE_SETUP_COOKIE.length + 1);
}

function sendPage(reply: FastifyReply, status: number, rendered: { html: string; contentSecurityPolicy: string }) {
	return reply.code(status).header("Cache-Control", "no-store").header("Pragma", "no-cache")
		.header("Referrer-Policy", "no-referrer").header("X-Frame-Options", "DENY")
		.header("Content-Security-Policy", rendered.contentSecurityPolicy)
		.type("text/html; charset=utf-8").send(rendered.html);
}

export async function registerFaceSetupRoutes(app: FastifyInstance, deps: FaceSetupDependencies): Promise<void> {
	await app.register(async scope => registerRoutes(scope, deps));
}

async function registerRoutes(app: FastifyInstance, deps: FaceSetupDependencies): Promise<void> {
	const { interactions, service, interactive, identitySubjects, clientAuthority, isPilotSubject, isEnabled } = deps;

	app.setErrorHandler((error, request, reply) => {
		const reason = error instanceof FaceSetupError
			? error.code === "INTERACTION_SAVE_FAILED" ? "INTERACTION_SAVE_FAILED" : "INTERACTION_STORE_UNAVAILABLE"
			: "UNEXPECTED_FAILURE";
		const status = error instanceof FaceSetupError ? error.statusCode
			: error instanceof Error && "statusCode" in error && typeof error.statusCode === "number" ? error.statusCode : 500;
		logFaceSetup(request, "FACE_SETUP_INTERACTION_FAILED", status, undefined, reason);
		return sendPage(reply, status, continuationFailedPage());
	});

	const guardEnabled = (reply: FastifyReply): boolean => {
		if (isEnabled()) return true;
		reply.code(404).send({ error: "not_found" });
		return false;
	};

	// Terminates the ceremony: clears the interaction record and its cookie, then sends a safe redirect
	// back to the registered Bookwrm return URI with only an outcome flag -- never a token, PUID, or identifier.
	const finish = async (reply: FastifyReply, handle: string | undefined, interaction: FaceSetupInteraction,
		outcome: "success" | "cancelled" | "failed") => {
		if (!await interactions.consume(handle, interaction)) {
			logFaceSetup(reply.request, "FACE_SETUP_INTERACTION_FAILED", 409, interaction, "INTERACTION_SAVE_FAILED");
			return sendPage(reply, 409, continuationFailedPage());
		}
		const formNavigation = reply.request.method === "POST" || reply.request.routeOptions.url === "/face-setup/cancel";
		logFaceSetup(reply.request, "FACE_SETUP_INTERACTION_CONSUMED", formNavigation ? 200 : 302, interaction);
		reply.header("Set-Cookie", cookieHeader(null));
		const destination = buildOutcomeRedirect(interaction.returnUri, outcome);
		return formNavigation ? sendPage(reply, 200, faceSetupNavigationPage(destination))
			: reply.code(302).header("Location", destination).send();
	};

	const load = async (request: FastifyRequest, reply: FastifyReply): Promise<{ handle: string; interaction: FaceSetupInteraction } | null> => {
		if (!guardEnabled(reply)) return null;
		const handle = readHandle(request);
		const inspection = await interactions.inspect(handle);
		const interaction = inspection.interaction;
		if (!interaction || !handle) {
			const reason: FaceSetupReason = !handle ? "COOKIE_MISSING"
				: inspection.state === "expired" ? "INTERACTION_EXPIRED"
				: inspection.state === "invalid" ? "INTERACTION_INVALID"
				: inspection.state === "consumed" ? "INTERACTION_ALREADY_CONSUMED" : "INTERACTION_NOT_FOUND";
			logFaceSetup(request, "FACE_SETUP_INTERACTION_LOADED", 400, undefined, reason, inspection);
			logFaceSetup(request, "FACE_SETUP_INTERACTION_FAILED", 400, undefined, reason, inspection);
			sendPage(reply, 400, inspection.state === "expired" ? expiredPage() : continuationFailedPage());
			return null;
		}
		logFaceSetup(request, "FACE_SETUP_INTERACTION_LOADED", 200, interaction, undefined, inspection);
		return { handle, interaction };
	};

	const csrfOk = (interaction: FaceSetupInteraction, candidate: unknown) => FaceSetupInteractionStore.csrfMatches(interaction, candidate);
	const reject = (reply: FastifyReply, interaction: FaceSetupInteraction, reason: FaceSetupReason, status = 400) => {
		logFaceSetup(reply.request, "FACE_SETUP_INTERACTION_FAILED", status, interaction, reason);
		return sendPage(reply, status, continuationFailedPage());
	};
	const persist = async (reply: FastifyReply, handle: string, interaction: FaceSetupInteraction) => {
		if (await interactions.save(handle, interaction)) return true;
		reject(reply, interaction, "INTERACTION_SAVE_FAILED", 503);
		return false;
	};

	const consentAuthorityValid = async (reply: FastifyReply, interaction: FaceSetupInteraction): Promise<boolean> => {
		const authority = interaction.authority;
		if (!authority || authority.clientId !== interaction.clientId) {
			reject(reply, interaction, "AUTHORITY_INVALID", 403);
			return false;
		}
		try { requireRecentEmailAuthority(authority); }
		catch (error) {
			if (!(error instanceof FaceEnrollmentError)) throw error;
			reject(reply, interaction, "AUTHORITY_INVALID", 403);
			return false;
		}
		const client = await clientAuthority.clients.findByClientId(interaction.clientId);
		if (!client || !client.redirectUris.includes(interaction.returnUri) || !await emailAuthority(interaction)) {
			reject(reply, interaction, "CLIENT_INVALID", 403);
			return false;
		}
		const subject = await identitySubjects.findByOidcSubject(authority.sub);
		if (!subject || subject.oidcSubject !== authority.sub || !isPilotSubject(subject.oidcSubject) ||
			subject.primaryProvider !== "HAPI_EMAIL" || subject.status !== "ACTIVE" ||
			subject.emailVerified !== true || subject.email !== subject.primaryProviderSubject) {
			reject(reply, interaction, "AUTHORITY_INVALID", 403);
			return false;
		}
		return true;
	};

	const continuation = (reply: FastifyReply, interaction: FaceSetupInteraction) => {
		if (interaction.phase === "STARTING") {
			return sendPage(reply, 200, faceSetupProcessingPage("/face-setup/continue"));
		}
		if (interaction.phase !== "ENROLLING" || !interaction.enrollment ||
			Date.parse(interaction.enrollment.expiresAt) <= Date.now()) {
			return reject(reply, interaction, "PHASE_INVALID");
		}
		return reply.code(302).header("Cache-Control", "no-store").header("Location", interaction.enrollment.launchUrl).send();
	};

	// Resolves the same H1 client authority already bound at /face-setup/start; a client disabled or
	// reconfigured mid-ceremony fails closed rather than silently trusting the stale binding.
	const emailAuthority = async (interaction: FaceSetupInteraction): Promise<InteractiveEmailAuthority | null> => {
		try {
			const authority = await interactive.authority(interaction.clientId);
			return authority.clientId === interaction.clientId ? authority : null;
		} catch (error) {
			if (error instanceof VerificationError) return null;
			throw error;
		}
	};

	const resumeVerifiedEmail = async (request: FastifyRequest, reply: FastifyReply, interaction: FaceSetupInteraction) => {
		if (interaction.phase !== "CONSENT" && interaction.phase !== "STARTING" && interaction.phase !== "ENROLLING") {
			return reject(reply, interaction, "PHASE_INVALID");
		}
		if (!await consentAuthorityValid(reply, interaction)) return undefined;
		logFaceSetup(request, "FACE_SETUP_DUPLICATE_SUBMISSION", 200, interaction);
		return sendPage(reply, 200, faceSetupNavigationPage(
			interaction.phase === "CONSENT" ? "/face-setup/consent" : "/face-setup/continue"));
	};

	const repeatEmail = async (request: FastifyRequest, reply: FastifyReply, handle: string) => {
		const current = await load(request, reply);
		if (!current) return undefined;
		if (current.handle !== handle) return reject(reply, current.interaction, "INTERACTION_INVALID");
		if (current.interaction.phase !== "EMAIL") return resumeVerifiedEmail(request, reply, current.interaction);
		if (!current.interaction.emailOperation && !current.interaction.email) {
			return reject(reply, current.interaction, "INTERACTION_SAVE_FAILED", 503);
		}
		logFaceSetup(request, "FACE_SETUP_DUPLICATE_SUBMISSION", 303, current.interaction);
		return reply.code(303).header("Cache-Control", "no-store").header("Location", "/face-setup/email/code").send();
	};

	const submitConsent = async (request: FastifyRequest, reply: FastifyReply, handle: string,
		interaction: FaceSetupInteraction, csrf: string, decision: "agree" | "not_now") => {
		if (!csrfOk(interaction, csrf)) return reject(reply, interaction, "CSRF_MISMATCH");
		if (!await consentAuthorityValid(reply, interaction)) return undefined;
		const authority = interaction.authority;
		if (!authority) return reject(reply, interaction, "AUTHORITY_INVALID", 403);
		const duplicate = (current: FaceSetupInteraction) => {
			if (current.phase !== "STARTING" && current.phase !== "ENROLLING") return reject(reply, current, "PHASE_INVALID");
			logFaceSetup(request, "FACE_SETUP_DUPLICATE_SUBMISSION", 200, current);
			return sendPage(reply, 200, faceSetupNavigationPage("/face-setup/continue"));
		};
		if (interaction.phase !== "CONSENT") return duplicate(interaction);
		if (!await interactions.claimConsent(handle, interaction, decision)) {
			const current = await load(request, reply);
			if (!current) return undefined;
			if (!csrfOk(current.interaction, csrf)) return reject(reply, current.interaction, "CSRF_MISMATCH");
			if (!await consentAuthorityValid(reply, current.interaction)) return undefined;
			if (current.interaction.phase === "CONSENT") return reject(reply, current.interaction, "INTERACTION_SAVE_FAILED", 503);
			return duplicate(current.interaction);
		}
		if (decision === "not_now") return finish(reply, handle, interaction, "cancelled");

		logFaceSetup(request, "FACE_SETUP_CONSENT_STARTED", 200, interaction);
		try {
			const capability = await service.capabilityStatus(authority);
			if (capability.consentRequired) {
				await service.acceptConsent(authority, FACE_AUTH_CONSENT_VERSION, FACE_AUTH_CONSENT_PURPOSE);
				logFaceSetup(request, "FACE_SETUP_CONSENT_ACCEPTED", 200, interaction);
			}
			const started = await service.start(authority);
			if (typeof started.enrollmentId !== "string" || typeof started.launchUrl !== "string" || typeof started.expiresAt !== "string") {
				const status = await service.capabilityStatus(authority);
				return finish(reply, handle, interaction, status.enrollmentState === "ACTIVE" && status.faceLoginEligible ? "success" : "failed");
			}
			interaction.enrollment = { enrollmentId: started.enrollmentId, expiresAt: started.expiresAt, launchUrl: started.launchUrl };
			interaction.phase = "ENROLLING";
			if (!await persist(reply, handle, interaction)) return undefined;
			logFaceSetup(request, "FACE_SETUP_ENROLLMENT_STARTED", 200, interaction);
			return sendPage(reply, 200, faceSetupNavigationPage("/face-setup/continue"));
		} catch (error) {
			if (error instanceof FaceEnrollmentError) {
				logFaceSetup(request, "FACE_SETUP_INTERACTION_FAILED", 200, interaction, "ENROLLMENT_FAILED");
				return finish(reply, handle, interaction, "failed");
			}
			throw error;
		}
	};

	app.get("/face-setup/start", async (request, reply) => {
		if (!guardEnabled(reply)) return undefined;
		const query = z.object({ client_id: z.string().min(1), return_uri: z.string().url() }).safeParse(request.query ?? {});
		if (!query.success) return reply.code(400).send({ error: "invalid_request" });
		let authority;
		try {
			authority = await resolveH1ClientAuthority(query.data.client_id, clientAuthority);
		} catch (error) {
			if (error instanceof VerificationError) return reply.code(400).send({ error: "INVALID_CLIENT" });
			throw error;
		}
		const record = await clientAuthority.clients.findByClientId(query.data.client_id);
		if (!record || !record.redirectUris.includes(query.data.return_uri)) {
			return reply.code(400).send({ error: "INVALID_RETURN_URI" });
		}
		const { handle, interaction } = await interactions.create({ clientId: authority.clientId, returnUri: query.data.return_uri });
		logFaceSetup(request, "FACE_SETUP_INTERACTION_CREATED", 302, interaction);
		reply.header("Set-Cookie", cookieHeader(handle));
		return reply.code(302).header("Location", "/face-setup/email").send();
	});

	app.get("/face-setup/email", async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		if (loaded.interaction.phase !== "EMAIL") return resumeVerifiedEmail(request, reply, loaded.interaction);
		if (loaded.interaction.emailOperation || loaded.interaction.email) return repeatEmail(request, reply, loaded.handle);
		return sendPage(reply, 200, faceSetupEmailPage({ csrf: loaded.interaction.csrf }));
	});

	app.post("/face-setup/email", { bodyLimit: 4096 }, async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		const { handle, interaction } = loaded;
		const body = z.object({ csrf: z.string(), email: z.string().email() }).safeParse(request.body ?? {});
		if (!body.success || !csrfOk(interaction, body.data.csrf)) {
			if (interaction.phase !== "EMAIL") return reject(reply, interaction, "CSRF_MISMATCH");
			return sendPage(reply, 400, faceSetupEmailPage({ csrf: interaction.csrf, error: "Please try again." }));
		}
		if (interaction.phase !== "EMAIL") return resumeVerifiedEmail(request, reply, interaction);
		if (interaction.email || interaction.emailOperation) return repeatEmail(request, reply, handle);
		const authority = await emailAuthority(interaction);
		if (!authority) return reject(reply, interaction, "CLIENT_INVALID", 403);
		if (!await interactions.claimEmail(handle, interaction, "START")) return repeatEmail(request, reply, handle);
		let started;
		try {
			started = await interactive.start(authority, body.data.email);
		} catch (error) {
			if (error instanceof VerificationError || error instanceof EmailAuthenticationError) {
				delete interaction.emailOperation;
				if (!await persist(reply, handle, interaction)) return undefined;
				return sendPage(reply, 429, faceSetupEmailPage({ csrf: interaction.csrf, error: "Too many attempts. Please wait and try again." }));
			}
			throw error;
		}
		// H5.4 #2: Face setup only ever reauthenticates an existing HAPI_EMAIL subject -- a brand-new or
		// ineligible email never creates an IdentitySubject or enters the registration path here.
		if (started.mode !== "AUTHENTICATION") {
			delete interaction.emailOperation;
			if (!await persist(reply, handle, interaction)) return undefined;
			return sendPage(reply, 200, faceSetupEmailPage({
				csrf: interaction.csrf,
				error: "We couldn't find an existing Bookwrm account with that email. Use the email you already sign in with."
			}));
		}
		interaction.email = { challengeId: started.challengeId };
		delete interaction.emailOperation;
		if (!await persist(reply, handle, interaction)) return undefined;
		return sendPage(reply, 200, faceSetupCodePage({ csrf: interaction.csrf }));
	});

	app.get("/face-setup/email/code", async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		if (loaded.interaction.phase !== "EMAIL") return resumeVerifiedEmail(request, reply, loaded.interaction);
		if (loaded.interaction.emailOperation) {
			return sendPage(reply, 200, faceSetupProcessingPage("/face-setup/email/code"));
		}
		if (!loaded.interaction.email) return reject(reply, loaded.interaction, "PHASE_INVALID");
		return sendPage(reply, 200, faceSetupCodePage({ csrf: loaded.interaction.csrf }));
	});

	app.post("/face-setup/email/resend", { bodyLimit: 4096 }, async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		const { interaction } = loaded;
		const body = z.object({ csrf: z.string() }).safeParse(request.body ?? {});
		if (!body.success || !csrfOk(interaction, body.data.csrf)) {
			if (interaction.phase !== "EMAIL") return reject(reply, interaction, "CSRF_MISMATCH");
			return sendPage(reply, 400, faceSetupCodePage({ csrf: interaction.csrf, error: "Please try again." }));
		}
		if (interaction.phase !== "EMAIL") return resumeVerifiedEmail(request, reply, interaction);
		if (interaction.emailOperation) return repeatEmail(request, reply, loaded.handle);
		if (!interaction.email) return reject(reply, interaction, "PHASE_INVALID");
		const authority = await emailAuthority(interaction);
		if (!authority) return reject(reply, interaction, "CLIENT_INVALID", 403);
		if (!await interactions.claimEmail(loaded.handle, interaction, "RESEND")) return repeatEmail(request, reply, loaded.handle);
		try {
			await interactive.resend(authority, interaction.email.challengeId, "AUTHENTICATION");
		} catch (error) {
			if (!(error instanceof VerificationError) && !(error instanceof EmailAuthenticationError)) throw error;
			delete interaction.emailOperation;
			if (!await persist(reply, loaded.handle, interaction)) return undefined;
			return sendPage(reply, 429, faceSetupCodePage({ csrf: interaction.csrf, error: "Too many attempts. Please wait and try again." }));
		}
		delete interaction.emailOperation;
		if (!await persist(reply, loaded.handle, interaction)) return undefined;
		return sendPage(reply, 200, faceSetupCodePage({ csrf: interaction.csrf }));
	});

	app.post("/face-setup/email/code", { bodyLimit: 4096 }, async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		const { handle, interaction } = loaded;
		const body = z.object({ csrf: z.string(), code: z.string().min(1) }).safeParse(request.body ?? {});
		if (interaction.phase !== "EMAIL") {
			if (!body.success || !csrfOk(interaction, body.data.csrf)) return reject(reply, interaction, "CSRF_MISMATCH");
			return resumeVerifiedEmail(request, reply, interaction);
		}
		if (!body.success || !csrfOk(interaction, body.data.csrf)) {
			return sendPage(reply, 400, faceSetupCodePage({ csrf: interaction.csrf, error: "Please try again." }));
		}
		if (interaction.emailOperation) return repeatEmail(request, reply, handle);
		if (!interaction.email) return reject(reply, interaction, "PHASE_INVALID");
		const authority = await emailAuthority(interaction);
		if (!authority) return reject(reply, interaction, "CLIENT_INVALID", 403);
		if (!await interactions.claimEmail(handle, interaction, "VERIFY")) return repeatEmail(request, reply, handle);
		let verification;
		try {
			verification = await interactive.verify(authority, interaction.email.challengeId, body.data.code, "AUTHENTICATION");
		} catch (error) {
			if (!(error instanceof VerificationError) && !(error instanceof EmailAuthenticationError)) throw error;
			delete interaction.emailOperation;
			if (!await persist(reply, handle, interaction)) return undefined;
			return sendPage(reply, 401, faceSetupCodePage({
				csrf: interaction.csrf,
				error: "We couldn't sign you in with that code. Check the code or request a new one."
			}));
		}
		if (verification.mode !== "AUTHENTICATION") return finish(reply, handle, interaction, "failed");
		const principal = await interactive.consumeResult(authority, verification.authenticationResult);

		// H5.4 #5: the authenticated HAPI subject, not any Bookwrm/Base44-supplied email, is authoritative.
		const subject = await identitySubjects.findByOidcSubject(principal.sub);
		if (!subject || subject.primaryProvider !== "HAPI_EMAIL" || subject.status !== "ACTIVE" ||
			subject.emailVerified !== true || subject.email !== subject.primaryProviderSubject) {
			if (!await interactions.consume(handle, interaction)) return reject(reply, interaction, "INTERACTION_SAVE_FAILED", 409);
			reply.header("Set-Cookie", cookieHeader(null));
			return sendPage(reply, 403, notEligiblePage("This account isn't eligible for Face setup yet."));
		}

		// H5.4 #10: pilot gate decided only after fresh canonical authentication, keyed on the stable sub.
		if (!isPilotSubject(principal.sub)) {
			if (!await interactions.consume(handle, interaction)) return reject(reply, interaction, "INTERACTION_SAVE_FAILED", 409);
			reply.header("Set-Cookie", cookieHeader(null));
			return sendPage(reply, 403, notEligiblePage("Face Login isn't available for your account yet."));
		}

		const authenticatedAtMs = Date.parse(principal.authenticatedAt);
		const faceAuthority: FaceEnrollmentAuthority = {
			sub: principal.sub, clientId: interaction.clientId, authenticationMethod: "HAPI_EMAIL",
			authenticatedAt: principal.authenticatedAt, scope: "openid",
			expiresAt: authenticatedAtMs + FACE_ENROLLMENT_FRESHNESS_MS
		};
		interaction.authority = faceAuthority;
		interaction.phase = "CONSENT";
		delete interaction.emailOperation;
		if (!await persist(reply, handle, interaction)) return undefined;
		const capability = await service.capabilityStatus(faceAuthority);
		if (!capability.consentRequired) {
			return submitConsent(request, reply, handle, interaction, body.data.csrf, "agree");
		}
		return sendPage(reply, 200, faceSetupConsentPage({ csrf: interaction.csrf }));
	});

	app.get("/face-setup/consent", async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		if (loaded.interaction.phase === "STARTING" || loaded.interaction.phase === "ENROLLING") {
			if (!await consentAuthorityValid(reply, loaded.interaction)) return undefined;
			return continuation(reply, loaded.interaction);
		}
		if (loaded.interaction.phase !== "CONSENT" || !loaded.interaction.authority) {
			return reject(reply, loaded.interaction, "PHASE_INVALID");
		}
		return sendPage(reply, 200, faceSetupConsentPage({ csrf: loaded.interaction.csrf }));
	});

	app.post("/face-setup/consent", { bodyLimit: 4096 }, async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		const { handle, interaction } = loaded;
		const body = z.object({ csrf: z.string(), decision: z.enum(["agree", "not_now"]) }).safeParse(request.body ?? {});
		if (!body.success || !csrfOk(interaction, body.data.csrf)) {
			return reject(reply, interaction, "CSRF_MISMATCH");
		}
		return submitConsent(request, reply, handle, interaction, body.data.csrf, body.data.decision);
	});

	app.get("/face-setup/continue", async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded || !await consentAuthorityValid(reply, loaded.interaction)) return undefined;
		return continuation(reply, loaded.interaction);
	});

	app.get("/face-setup/callback", async (request, reply) => {
		const loaded = await load(request, reply);
		if (!loaded) return undefined;
		const { handle, interaction } = loaded;
		if (interaction.phase !== "ENROLLING" || !interaction.enrollment || !interaction.authority) {
			return reject(reply, interaction, "PHASE_INVALID");
		}
		if (!await consentAuthorityValid(reply, interaction)) return undefined;
		let result;
		try {
			result = await service.status(interaction.enrollment.enrollmentId, interaction.authority);
		} catch (error) {
			if (error instanceof FaceEnrollmentError) return finish(reply, handle, interaction, "failed");
			throw error;
		}
		const status = typeof result.body?.status === "string" ? result.body.status : undefined;
		if (status === "COMPLETED") {
			const capability = await service.capabilityStatus(interaction.authority);
			return finish(reply, handle, interaction,
				capability.enrollmentState === "ACTIVE" && capability.faceLoginEligible ? "success" : "failed");
		}
		if (status === "PENDING" && interaction.expiresAt > Date.now()) {
			return sendPage(reply, 200, faceSetupProcessingPage("/face-setup/callback"));
		}
		return finish(reply, handle, interaction, "failed");
	});

	app.get("/face-setup/cancel", async (request, reply) => {
		if (!guardEnabled(reply)) return undefined;
		const handle = readHandle(request);
		const interaction = await interactions.find(handle);
		if (!interaction) {
			reply.header("Set-Cookie", cookieHeader(null));
			return sendPage(reply, 200, faceSetupMessagePage({
				title: "Face setup cancelled",
				message: "You can close this page and return to Bookwrm."
			}));
		}
		const query = z.object({ csrf: z.string() }).safeParse(request.query ?? {});
		if (!query.success || !csrfOk(interaction, query.data.csrf)) return reject(reply, interaction, "CSRF_MISMATCH");
		return finish(reply, handle, interaction, "cancelled");
	});
}
