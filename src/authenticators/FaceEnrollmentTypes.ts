import type { AccessTokenRecord } from "../oidc/infrastructure/RedisOIDCStore.js";
import type { PrivateIDSession } from "../privateid/PrivateIDSession.js";

export const FACE_ENROLLMENT_FRESHNESS_MS = 300_000;
export const FACE_ENROLLMENT_TTL_MS = 300_000;
export const FACE_AUTH_CONSENT_VERSION = "FACE_AUTH_V1";
export const FACE_AUTH_CONSENT_PURPOSE = "FACE_AUTHENTICATION";
export const FACE_AUTH_CONSENT_TEXT = "Face is an optional sign-in method and enrollment uses PrivateID. Email remains available as a fallback. Enrollment is optional.";

export class FaceEnrollmentError extends Error {
	constructor(public readonly code: string, public readonly statusCode = 409) {
		super(code);
	}
}

export type FaceEnrollmentAuthority = Pick<AccessTokenRecord,
	"sub" | "clientId" | "authenticationMethod" | "authenticatedAt" | "expiresAt" | "scope">;

export function requireRecentEmailAuthority(authority: FaceEnrollmentAuthority, now = Date.now()): void {
	const authenticatedAt = Date.parse(authority.authenticatedAt ?? "");
	if (authority.authenticationMethod !== "HAPI_EMAIL" || !Number.isFinite(authenticatedAt) ||
		authenticatedAt > now || now - authenticatedAt > FACE_ENROLLMENT_FRESHNESS_MS ||
		!Number.isFinite(authority.expiresAt) || authority.expiresAt <= now ||
		!authority.scope.split(" ").includes("openid")) {
		throw new FaceEnrollmentError("RECENT_EMAIL_AUTHENTICATION_REQUIRED", 401);
	}
}

export type FaceEnrollmentReservation =
	| { alreadyEnrolled: true }
	| { alreadyEnrolled: false; transactionId: string; providerTransactionId: string };

export type FaceEnrollmentReply = { statusCode: number; body: Record<string, unknown> };

export type FaceCapabilityEnrollmentState = "NOT_ENROLLED" | "PENDING" | "ACTIVE" | "FAILED" | "REVOKED";
export type FaceEnrollmentStatus = FaceCapabilityEnrollmentState | "COMPLETED" | "CONFLICT";

export type FaceCapabilityStatus = {
	faceEnrollmentEligible: boolean;
	faceLoginEligible: boolean;
	consentRequired: boolean;
	enrollmentState: FaceCapabilityEnrollmentState;
	consentVersion: typeof FACE_AUTH_CONSENT_VERSION;
	consentPurpose: typeof FACE_AUTH_CONSENT_PURPOSE;
	consentText: typeof FACE_AUTH_CONSENT_TEXT;
};

export function requireStatusAuthority(authority: FaceEnrollmentAuthority, now = Date.now()): void {
	if (!Number.isFinite(authority.expiresAt) || authority.expiresAt <= now ||
		!authority.sub || !authority.clientId || !authority.scope.split(" ").includes("openid")) {
		throw new FaceEnrollmentError("UNAUTHORIZED", 401);
	}
}

export interface FaceEnrollmentRepository {
	reserve(authority: FaceEnrollmentAuthority): Promise<FaceEnrollmentReservation>;
	acceptConsent(authority: FaceEnrollmentAuthority, consentVersion: string, purpose: string): Promise<void>;
	capabilityStatus(authority: FaceEnrollmentAuthority, enabled: boolean): Promise<FaceCapabilityStatus>;
	status(enrollmentId: string, authority: FaceEnrollmentAuthority): Promise<FaceEnrollmentReply>;
	bind(reservation: Extract<FaceEnrollmentReservation, { alreadyEnrolled: false }>,
		session: PrivateIDSession): Promise<string>;
	fail(providerTransactionId: string): Promise<void>;
	webhook(transactionId: string | undefined, sessionId: string | undefined,
		status: string, puid: string | undefined, enabled: boolean): Promise<FaceEnrollmentReply | undefined>;
	callback(transactionId: string | undefined, sessionId: string | undefined): Promise<FaceEnrollmentReply | undefined>;
}

export interface FaceEnrollmentCallbacks {
	webhook(transactionId: string | undefined, sessionId: string | undefined,
		status: string, puid: string | undefined): Promise<FaceEnrollmentReply | undefined>;
	callback(transactionId: string | undefined, sessionId: string | undefined): Promise<FaceEnrollmentReply | undefined>;
}
