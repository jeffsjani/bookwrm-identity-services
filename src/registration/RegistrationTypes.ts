import type { VerificationContext } from "../email/VerificationChallenge.js";

// Re-exported under a registration-domain name; H3 never redefines tenant/application authority --
// it is always the same trusted H1 client context used by H2 (see routes/registration.ts authorize()).
export type RegistrationContext = VerificationContext;

export type CompleteRegistrationInput = {
		context: RegistrationContext;
		// Opaque reference to verified H2 evidence. Equal to the VerificationChallenge id
		// (see EmailVerificationService.verify()'s `verificationId` return value) -- never a
		// client-supplied email/claim. Task 2/3.
		verificationId: string;
};

export type RegistrationOutcome = {
		registered: true;
		subject: string;
		email: string;
		emailVerified: true;
		// Internal-only diagnostics (never returned over HTTP): whether this call created a brand new
		// canonical identity (Case A), reused an existing one for the same email (Case B), or was a
		// successful-retry replay of an already-consumed verification (Task 10).
		created: boolean;
		idempotentReplay: boolean;
};

export type RegistrationErrorCode =
		| "UNAUTHORIZED"
		| "INVALID_EVIDENCE"
		| "INVALID_PURPOSE"
		| "UNVERIFIED_CHALLENGE"
		| "EXPIRED_CHALLENGE"
		| "LOCKED_CHALLENGE"
		| "EVIDENCE_ALREADY_CONSUMED"
		| "ACCOUNT_CONFLICT"
		| "REGISTRATION_UNAVAILABLE";

export class RegistrationError extends Error {
		constructor(public readonly code: RegistrationErrorCode, public readonly statusCode = 400) {
				super(code);
		}
}

export type RegistrationAuditType =
		| "IDENTITY_REGISTRATION_STARTED"
		| "IDENTITY_REGISTERED"
		| "IDENTITY_REGISTRATION_IDEMPOTENT"
		| "IDENTITY_REGISTRATION_CONFLICT"
		| "IDENTITY_REGISTRATION_FAILED";

export type RegistrationAuditEntry = {
		id: string;
		tenantId: string;
		applicationId: string | null;
		verificationChallengeId: string | null;
		identitySubjectId: string | null;
		type: RegistrationAuditType;
		// Privacy-conscious metadata only (Task 12): never the OTP/code, never raw secrets.
		detail?: string;
		occurredAt: string;
};
