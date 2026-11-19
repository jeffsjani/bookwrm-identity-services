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
import type { VerifiedFederatedIdentity } from "./FederatedIdentityTypes.js";

// Google issues id_tokens under either issuer form; both are accepted EXACTLY -- any other value,
// including case or trailing-slash variants, fails. The canonical https form is always recorded
// as the federation identity key so one Google subject can never appear under two issuer rows.
export const GOOGLE_ISSUER = "https://accounts.google.com";
export const GOOGLE_LEGACY_ISSUER = "accounts.google.com";
export const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

export type GoogleVerificationErrorCode =
		| "invalid_token"
		| "invalid_signature"
		| "wrong_issuer"
		| "wrong_audience"
		| "token_expired"
		| "nonce_mismatch"
		| "missing_subject"
		| "unsupported_algorithm";

export class GoogleIdentityTokenError extends Error {
		constructor(readonly code: GoogleVerificationErrorCode, message: string) {
				super(message);
				this.name = "GoogleIdentityTokenError";
		}
}

// The server-side verification result. providerIssuer + providerSubject form the ONLY identity
// key ever handed to the federation layer; email is carried as display metadata (only when Google
// attests email_verified) and can never link or merge accounts.
export type VerifiedGoogleIdentity = VerifiedFederatedIdentity & {
		provider: "GOOGLE";
		// Google Workspace hosted domain (hd claim) carried as display metadata only.
		hostedDomain?: string;
};

export type GoogleIdentityTokenVerifierOptions = {
		// The registered Google OAuth client ids tokens must be issued for.
		expectedAudiences: readonly string[];
		// Synthetic JWKS for tests. When omitted, Google's live JWKS endpoint is used -- which this
		// tranche never does in any wired code path (no live Google credentials required).
		jwks?: JSONWebKeySet;
		clockToleranceSeconds?: number;
		now?: () => Date;
};

// HAPI ID V2-D: server-only verification of Google `id_token` assertions. Mirrors
// AppleIdentityTokenVerifier exactly: JWKS signature (RS256 only), exact issuer, registered
// audience, expiration, REQUIRED per-transaction nonce binding, and subject presence. The browser
// can never supply a trusted Google subject: only this verifier's output may feed
// IdentityFederationService or FederatedIdentityResolutionService.
export class GoogleIdentityTokenVerifier {
		private readonly getKey: JWTVerifyGetKey;
		private readonly audiences: readonly string[];
		private readonly clockToleranceSeconds: number;
		private readonly now: () => Date;

		constructor(options: GoogleIdentityTokenVerifierOptions) {
				if (!options.expectedAudiences || options.expectedAudiences.length === 0) {
						throw new Error("GoogleIdentityTokenVerifier requires at least one expected audience");
				}
				this.audiences = options.expectedAudiences;
				this.getKey = options.jwks
						? createLocalJWKSet(options.jwks)
						: createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
				this.clockToleranceSeconds = options.clockToleranceSeconds ?? 0;
				this.now = options.now ?? (() => new Date());
		}

		async verify(identityToken: string, expectations: { nonce: string }): Promise<VerifiedGoogleIdentity> {
				if (typeof identityToken !== "string" || identityToken.trim().length === 0) {
						throw new GoogleIdentityTokenError("invalid_token", "identity token is required");
				}
				if (typeof expectations.nonce !== "string" || expectations.nonce.trim().length === 0) {
						throw new GoogleIdentityTokenError("nonce_mismatch", "an expected nonce is required");
				}

				let payload: Record<string, unknown>;
				let protectedHeader: { alg?: string };
				try {
						const result = await jwtVerify(identityToken, this.getKey, {
								issuer: [GOOGLE_ISSUER, GOOGLE_LEGACY_ISSUER],
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
						throw new GoogleIdentityTokenError("unsupported_algorithm", "Google identity tokens must be RS256-signed");
				}

				const subject = typeof payload.sub === "string" ? payload.sub.trim() : "";
				if (!subject) {
						throw new GoogleIdentityTokenError("missing_subject", "Google identity token is missing a subject");
				}

				const presentedNonce = typeof payload.nonce === "string" ? payload.nonce : "";
				if (!presentedNonce || !constantTimeStringEqual(presentedNonce, expectations.nonce)) {
						throw new GoogleIdentityTokenError("nonce_mismatch", "Google identity token nonce does not match this transaction");
				}

				// Google's email claim is trusted as display metadata ONLY when email_verified is
				// attested true; an unverified email is never surfaced at all.
				const emailVerified = this.normalizeBoolean(payload.email_verified);
				const rawEmail = typeof payload.email === "string" && payload.email.trim().length > 0
						? payload.email.trim()
						: undefined;
				const email = emailVerified === true ? rawEmail : undefined;

				const audience = Array.isArray(payload.aud)
						? String(payload.aud[0])
						: String(payload.aud);
				const hostedDomain = typeof payload.hd === "string" && payload.hd.trim().length > 0
						? payload.hd.trim()
						: undefined;

				return {
						provider: "GOOGLE",
						// Canonicalized: both accepted issuer forms map to the single https identity key.
						providerIssuer: GOOGLE_ISSUER,
						providerSubject: subject,
						audience,
						...(email !== undefined ? { email } : {}),
						...(emailVerified !== undefined ? { emailVerified } : {}),
						isPrivateRelayEmail: false,
						...(hostedDomain !== undefined ? { hostedDomain } : {}),
						...(typeof payload.auth_time === "number" ? { authTime: payload.auth_time } : {}),
						expiresAt: typeof payload.exp === "number" ? payload.exp : 0,
						evidenceReference: createHash("sha256").update(identityToken).digest("base64url")
				};
		}

		private normalizeBoolean(value: unknown): boolean | undefined {
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

		private mapJoseError(error: unknown): GoogleIdentityTokenError {
				if (error instanceof joseErrors.JWTExpired) {
						return new GoogleIdentityTokenError("token_expired", "Google identity token has expired");
				}
				if (error instanceof joseErrors.JWTClaimValidationFailed) {
						if (error.claim === "iss") {
								return new GoogleIdentityTokenError("wrong_issuer", "Google identity token issuer is not accounts.google.com");
						}
						if (error.claim === "aud") {
								return new GoogleIdentityTokenError("wrong_audience", "Google identity token audience is not a registered client");
						}
						return new GoogleIdentityTokenError("invalid_token", `Google identity token claim validation failed: ${error.claim}`);
				}
				if (error instanceof joseErrors.JWSSignatureVerificationFailed
						|| error instanceof joseErrors.JWKSNoMatchingKey) {
						return new GoogleIdentityTokenError("invalid_signature", "Google identity token signature verification failed");
				}
				if (error instanceof joseErrors.JOSEAlgNotAllowed) {
						return new GoogleIdentityTokenError("unsupported_algorithm", "Google identity tokens must be RS256-signed");
				}
				return new GoogleIdentityTokenError("invalid_token", "Google identity token could not be verified");
		}
}

// Bridges a server-verified Google identity into the V2-B federation policy layer. This is the
// ONLY sanctioned construction path for a GOOGLE LinkRequest: the provider subject comes from a
// verified token, never from a browser-supplied value, and email plays no role.
export function toGoogleLinkRequest(
		identitySubjectId: string,
		verified: VerifiedGoogleIdentity,
		correlationId?: string
): LinkRequest {
		return {
				identitySubjectId,
				provider: "GOOGLE",
				providerIssuer: verified.providerIssuer,
				providerSubject: verified.providerSubject,
				providerClientContext: verified.audience,
				evidenceReference: verified.evidenceReference,
				...(correlationId !== undefined ? { correlationId } : {})
		};
}
