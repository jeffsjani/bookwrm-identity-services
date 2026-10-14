import type { FaceEnrollmentAuthority } from "./FaceEnrollmentTypes.js";

// H5.4: a HAPI-owned Face Setup reauthorization ceremony. Bookwrm never passes a Base44/SSO token into
// this flow -- it only redirects the browser here, and HAPI mints fresh canonical authority itself via a
// brand-new H4 email OTP round trip before FACE_AUTH_V1 consent and PrivateID enrollment ever run.
export const FACE_SETUP_PURPOSE = "FACE_SETUP";
export const FACE_SETUP_TTL_MS = 600_000; // outer ceremony cap (email entry/verification window)
export const FACE_SETUP_COOKIE = "hapi_face_setup";

export type FaceSetupPhase = "EMAIL" | "CONSENT" | "ENROLLING";

export type FaceSetupOutcome = "success" | "cancelled" | "failed";

export class FaceSetupError extends Error {
	constructor(public readonly code: string, public readonly statusCode = 400) {
		super(code);
	}
}

// Deliberately excludes email, PUID, provider credentials and any bearer token -- only the minimal
// server-side authority HapiFaceEnrollmentService already requires, scoped to this one browser ceremony.
export type FaceSetupInteraction = {
	version: 1;
	purpose: typeof FACE_SETUP_PURPOSE;
	clientId: string;
	returnUri: string;
	csrf: string;
	phase: FaceSetupPhase;
	createdAt: number;
	expiresAt: number;
	email?: { challengeId: string };
	authority?: FaceEnrollmentAuthority;
	enrollment?: { enrollmentId: string; expiresAt: string };
};

export function buildOutcomeRedirect(returnUri: string, outcome: FaceSetupOutcome): string {
	const url = new URL(returnUri);
	url.searchParams.set("face_setup", outcome);
	return url.toString();
}
