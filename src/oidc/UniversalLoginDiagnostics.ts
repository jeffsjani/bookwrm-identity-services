import { createHmac, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { configuration } from "../config/ConfigurationService.js";

// HAPI ID H6.5B: safe, privacy-preserving diagnostics for the Universal Login interaction
// lifecycle. Every value accepted here is non-sensitive by construction -- this module never
// takes a raw interaction handle, cookie value, CSRF token, PKCE verifier/challenge, OTP, email,
// state/nonce, authorization code, or access/ID token as a loggable field.

export type UniversalLoginReasonCode =
	| "COOKIE_MISSING"
	| "INTERACTION_NOT_FOUND"
	| "INTERACTION_EXPIRED"
	| "CSRF_MISMATCH"
	| "AUTHORITY_INVALID"
	| "INTERACTION_SAVE_FAILED"
	| "CLIENT_INVALID"
	| "INTERACTION_ALREADY_CONSUMED";

export type RemainingTtlBucket = ">300s" | "60-300s" | "1-59s" | "expired" | "unknown";

// Coarse bucketing only -- never logs the exact expiresAt/remaining millisecond value.
export function bucketRemainingTtl(remainingMs: number | undefined): RemainingTtlBucket {
	if (remainingMs === undefined) return "unknown";
	if (remainingMs <= 0) return "expired";
	const seconds = remainingMs / 1000;
	if (seconds > 300) return ">300s";
	if (seconds >= 60) return "60-300s";
	return "1-59s";
}

// Derives a short, one-way correlation id from the interaction handle so multiple log lines for
// the same login attempt can be grouped without ever logging the handle, cookie, or Redis key.
// Prefers the existing HAPI_EMAIL_VERIFICATION_SECRET (domain-separated) so no new production
// secret is required; falls back to a process-local random key if that secret isn't configured.
// Never accepted anywhere as authentication/authorization proof -- diagnostic only.
let ephemeralKey: Buffer | undefined;
function diagnosticKey(): Buffer {
	const configured = configuration.get("HAPI_EMAIL_VERIFICATION_SECRET")?.trim();
	if (configured && Buffer.byteLength(configured) >= 32) return Buffer.from(configured);
	if (!ephemeralKey) ephemeralKey = randomBytes(32);
	return ephemeralKey;
}

export function diagnosticCorrelationId(handle: string | undefined): string | undefined {
	if (!handle) return undefined;
	return createHmac("sha256", diagnosticKey())
		.update(`universal-login-diagnostic-correlation:${handle}`)
		.digest("hex")
		.slice(0, 16);
}

export type UniversalLoginDiagnosticEvent =
	| "UNIVERSAL_LOGIN_INTERACTION_CREATED"
	| "UNIVERSAL_LOGIN_INTERACTION_LOADED"
	| "UNIVERSAL_LOGIN_EMAIL_STARTED"
	| "UNIVERSAL_LOGIN_EMAIL_VERIFIED"
	| "UNIVERSAL_LOGIN_INTERACTION_CONSUMED"
	| "UNIVERSAL_LOGIN_INTERACTION_FAILED"
	| "UNIVERSAL_LOGIN_OIDC_REDIRECT_ISSUED";

// Strict allowlist: only these fields may ever be attached to a Universal Login diagnostic log
// line. Keeping this as a typed object (rather than a free-form bag) is itself the safeguard
// against accidentally logging a sensitive value from a call site.
export type UniversalLoginDiagnosticFields = {
	event: UniversalLoginDiagnosticEvent;
	route: string;
	clientId?: string;
	correlationId?: string;
	reasonCode?: UniversalLoginReasonCode;
	cookiePresent?: boolean;
	interactionFound?: boolean;
	csrfValid?: boolean;
	authorityValid?: boolean;
	clientValid?: boolean;
	remainingTtlBucket?: RemainingTtlBucket;
	authenticationMethod?: "email" | "face";
	httpStatus?: number;
};

export function logUniversalLoginDiagnostic(app: FastifyInstance, fields: UniversalLoginDiagnosticFields): void {
	const { event, route, clientId, correlationId, reasonCode, cookiePresent, interactionFound, csrfValid,
		authorityValid, clientValid, remainingTtlBucket, authenticationMethod, httpStatus } = fields;
	app.log.info({
		event, route, clientId, correlationId, reasonCode, cookiePresent, interactionFound, csrfValid,
		authorityValid, clientValid, remainingTtlBucket, authenticationMethod, httpStatus
	}, "Universal Login diagnostic");
}
