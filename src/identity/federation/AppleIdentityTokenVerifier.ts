import { createHash } from "node:crypto";
import {
		createLocalJWKSet,
		createRemoteJWKSet,
		errors as joseErrors,
		jwtVerify,
		type JSONWebKeySet,
		type JWTVerifyGetKey
} from "jose";

import { constantTimeStringEqual } from "../../security/ServiceAuthentication.js";
import type { LinkRequest } from "../IdentityFederationService.js";

// Exact Apple OIDC issuer; any other value -- including case or trailing-slash variants -- fails.
export const APPLE_ISSUER = "https://appleid.apple.com";
export const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";
// Apple private relay addresses are forwarding aliases owned by Apple, not user mailboxes. They
// are safe to display/store as contact hints but MUST never participate in account matching.
export const APPLE_PRIVATE_RELAY_DOMAIN = "privaterelay.appleid.com";

export type AppleVerificationErrorCode =
		| "invalid_token"
		| "invalid_signature"
		| "wrong_issuer"
		| "wrong_audience"
		| "token_expired"
		| "nonce_mismatch"
		| "missing_subject"
		| "unsupported_algorithm";

export class AppleIdentityTokenError extends Error {
		constructor(readonly code: AppleVerificationErrorCode, message: string) {
				super(message);
				this.name = "AppleIdentityTokenError";
		}
}

// The server-side verification result. providerIssuer + providerSubject form the ONLY identity
// key ever handed to the federation layer; email is carried as display metadata and can never
// link or merge accounts.
export type VerifiedAppleIdentity = {
		provider: "APPLE";
		providerIssuer: string;
		providerSubject: string;
		audience: string;
		email?: string;
		emailVerified?: boolean;
		isPrivateRelayEmail: boolean;
		authTime?: number;
		expiresAt: number;
		// SHA-256 of the raw identity token: a non-reversible audit reference (identity_link_audit
		// evidence_reference); the raw token is never stored or logged.
		evidenceReference: string;
};

export type AppleIdentityTokenVerifierOptions = {
		// The Apple client contexts (Services ID / app bundle ID) tokens must be issued for.
		expectedAudiences: readonly string[];
		// Synthetic JWKS for tests. When omitted, Apple's live JWKS endpoint is used -- which this
		// tranche never does in any wired code path (no live Apple credentials required).
		jwks?: JSONWebKeySet;
		clockToleranceSeconds?: number;
		now?: () => Date;
};

// HAPI ID V2-C: server-only verification of Apple `id_token` assertions. Deliberately NOT wired
// to any HTTP route and holding no Apple credentials -- it validates assertions that a future
// authenticated linking flow will obtain. The browser can never supply a trusted Apple subject:
// only this verifier's output may feed IdentityFederationService.
export class AppleIdentityTokenVerifier {
		private readonly getKey: JWTVerifyGetKey;
		private readonly audiences: readonly string[];
		private readonly clockToleranceSeconds: number;
		private readonly now: () => Date;

		constructor(options: AppleIdentityTokenVerifierOptions) {
				if (!options.expectedAudiences || options.expectedAudiences.length === 0) {
						throw new Error("AppleIdentityTokenVerifier requires at least one expected audience");
				}
				this.audiences = options.expectedAudiences;
				this.getKey = options.jwks
						? createLocalJWKSet(options.jwks)
						: createRemoteJWKSet(new URL(APPLE_JWKS_URL));
				this.clockToleranceSeconds = options.clockToleranceSeconds ?? 0;
				this.now = options.now ?? (() => new Date());
		}

		// Verifies signature (Apple JWKS, RS256 only), exact issuer, audience, expiration, nonce
		// binding and subject presence. The nonce is REQUIRED: every linking/authentication
		// transaction must have bound one when the Apple request was launched.
		async verify(identityToken: string, expectations: { nonce: string }): Promise<VerifiedAppleIdentity> {
				if (typeof identityToken !== "string" || identityToken.trim().length === 0) {
						throw new AppleIdentityTokenError("invalid_token", "identity token is required");
				}
				if (typeof expectations.nonce !== "string" || expectations.nonce.trim().length === 0) {
						throw new AppleIdentityTokenError("nonce_mismatch", "an expected nonce is required");
				}

				let payload: Record<string, unknown>;
				let protectedHeader: { alg?: string };
				try {
						const result = await jwtVerify(identityToken, this.getKey, {
								issuer: APPLE_ISSUER,
								audience: [...this.audiences],
								algorithms: ["RS256"],
								clockTolerance: this.clockToleranceSeconds,
								currentDate: this.now()
						});
						payload = result.payload as Record<string, unknown>;
						protectedHeader = result.protectedHeader;
				} catch (error) {
						throw this.mapJoseError(error);
				}

				if (protectedHeader.alg !== "RS256") {
						throw new AppleIdentityTokenError("unsupported_algorithm", "Apple identity tokens must be RS256-signed");
				}

				const subject = typeof payload.sub === "string" ? payload.sub.trim() : "";
				if (!subject) {
						throw new AppleIdentityTokenError("missing_subject", "Apple identity token is missing a subject");
				}

				const presentedNonce = typeof payload.nonce === "string" ? payload.nonce : "";
				if (!presentedNonce || !constantTimeStringEqual(presentedNonce, expectations.nonce)) {
						throw new AppleIdentityTokenError("nonce_mismatch", "Apple identity token nonce does not match this transaction");
				}

				const email = typeof payload.email === "string" && payload.email.trim().length > 0
						? payload.email.trim()
						: undefined;
				// Apple serializes some boolean claims as the strings "true"/"false".
				const emailVerified = this.normalizeAppleBoolean(payload.email_verified);
				const isPrivateRelayEmail = this.normalizeAppleBoolean(payload.is_private_email) === true
						|| (email !== undefined && email.toLowerCase().endsWith(`@${APPLE_PRIVATE_RELAY_DOMAIN}`));

				const audience = Array.isArray(payload.aud)
						? String(payload.aud[0])
						: String(payload.aud);

				return {
						provider: "APPLE",
						providerIssuer: APPLE_ISSUER,
						providerSubject: subject,
						audience,
						...(email !== undefined ? { email } : {}),
						...(emailVerified !== undefined ? { emailVerified } : {}),
						isPrivateRelayEmail,
						...(typeof payload.auth_time === "number" ? { authTime: payload.auth_time } : {}),
						expiresAt: typeof payload.exp === "number" ? payload.exp : 0,
						evidenceReference: createHash("sha256").update(identityToken).digest("base64url")
				};
		}

		private normalizeAppleBoolean(value: unknown): boolean | undefined {
				if (typeof value === "boolean") {
						return value;
				}
				if (value === "true") {
						return true;
				}
				if (value === "false") {
						return false;
				}
				return undefined;
		}

		private mapJoseError(error: unknown): AppleIdentityTokenError {
				if (error instanceof joseErrors.JWTExpired) {
						return new AppleIdentityTokenError("token_expired", "Apple identity token has expired");
				}
				if (error instanceof joseErrors.JWTClaimValidationFailed) {
						if (error.claim === "iss") {
								return new AppleIdentityTokenError("wrong_issuer", "Apple identity token issuer is not appleid.apple.com");
						}
						if (error.claim === "aud") {
								return new AppleIdentityTokenError("wrong_audience", "Apple identity token audience is not a registered client context");
						}
						return new AppleIdentityTokenError("invalid_token", `Apple identity token claim validation failed: ${error.claim}`);
				}
				if (error instanceof joseErrors.JWSSignatureVerificationFailed
						|| error instanceof joseErrors.JWKSNoMatchingKey) {
						return new AppleIdentityTokenError("invalid_signature", "Apple identity token signature verification failed");
				}
				if (error instanceof joseErrors.JOSEAlgNotAllowed) {
						return new AppleIdentityTokenError("unsupported_algorithm", "Apple identity tokens must be RS256-signed");
				}
				return new AppleIdentityTokenError("invalid_token", "Apple identity token could not be verified");
		}
}

// Bridges a server-verified Apple identity into the V2-B federation policy layer. This is the
// ONLY sanctioned construction path for an APPLE LinkRequest: the provider subject comes from a
// verified token, never from a browser-supplied value, and email plays no role.
export function toAppleLinkRequest(
		identitySubjectId: string,
		verified: VerifiedAppleIdentity,
		correlationId?: string
): LinkRequest {
		return {
				identitySubjectId,
				provider: "APPLE",
				providerIssuer: verified.providerIssuer,
				providerSubject: verified.providerSubject,
				providerClientContext: verified.audience,
				evidenceReference: verified.evidenceReference,
				...(correlationId !== undefined ? { correlationId } : {})
		};
}
