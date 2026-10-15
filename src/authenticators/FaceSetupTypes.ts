import type { FaceEnrollmentAuthority } from "./FaceEnrollmentTypes.js";

// H5.4: a HAPI-owned Face Setup reauthorization ceremony. Bookwrm never passes a Base44/SSO token into
// this flow -- it only redirects the browser here, and HAPI mints fresh canonical authority itself via a
// brand-new H4 email OTP round trip before FACE_AUTH_V1 consent and PrivateID enrollment ever run.
export const FACE_SETUP_PURPOSE = "FACE_SETUP";
export const FACE_SETUP_TTL_MS = 600_000; // outer ceremony cap (email entry/verification window)
export const FACE_SETUP_COOKIE = "hapi_face_setup";

export type FaceSetupPhase = "EMAIL" | "CONSENT" | "STARTING" | "ENROLLING" | "CANCELLED";

export type FaceSetupOutcome = "success" | "cancelled" | "failed";

export class FaceSetupError extends Error {
	constructor(public readonly code: string, public readonly statusCode = 400, options?: ErrorOptions) {
		super(code, options);
	}
}

// Deliberately excludes the email address, PUID, provider credentials and any bearer token -- only the
// minimal server-side authority HapiFaceEnrollmentService already requires, scoped to this one browser
// ceremony. `email.hint` is a display-only masked form (e.g. "i***@example.com") for the OTP page.
export type FaceSetupInteraction = {
	version: 1;
	purpose: typeof FACE_SETUP_PURPOSE;
	clientId: string;
	returnUri: string;
	csrf: string;
	phase: FaceSetupPhase;
	createdAt: number;
	expiresAt: number;
	emailOperation?: "START" | "VERIFY" | "RESEND";
	email?: { challengeId: string; hint?: string };
	authority?: FaceEnrollmentAuthority;
	enrollment?: { enrollmentId: string; expiresAt: string; launchUrl: string };
};

// H5.4D-2: dedicated provider browser-return path for Face Setup (never the shared /privateid/callback).
export const FACE_SETUP_CALLBACK_PATH = "/face-setup/callback";

export function maskEmailHint(email: string): string {
	const at = email.lastIndexOf("@");
	if (at < 1) return "your email";
	return `${email[0]}***${email.slice(at)}`;
}

export function buildOutcomeRedirect(returnUri: string, outcome: FaceSetupOutcome): string {
	const url = new URL(returnUri);
	url.searchParams.set("face_setup", outcome);
	return url.toString();
}
