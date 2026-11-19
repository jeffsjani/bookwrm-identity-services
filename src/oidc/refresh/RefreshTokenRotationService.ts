import { createHash, randomBytes, randomUUID } from "node:crypto";

import { configuration } from "../../config/ConfigurationService.js";
import type {
		RefreshTokenFamily,
		RefreshTokenFamilyRevocationReason,
		RefreshTokenGeneration
} from "../../models/RefreshTokenFamily.js";
import type { RefreshTokenFamilyRepository } from "./RefreshTokenFamilyRepository.js";
import { InMemoryRefreshTokenFamilyRepository } from "./InMemoryRefreshTokenFamilyRepository.js";
import { PostgresRefreshTokenFamilyRepository } from "./PostgresRefreshTokenFamilyRepository.js";

const REFRESH_TOKEN_BYTES = 32;

// Lifetimes from the approved V2-B design (docs/HAPI-ID-V2B-Refresh-Token-Family-Design.md §4).
export type RefreshClientProfile = "native_public" | "confidential_web";

export type RefreshLifetimePolicy = {
		slidingTtlMs: number;
		absoluteTtlMs: number;
};

export const REFRESH_LIFETIMES: Record<RefreshClientProfile, RefreshLifetimePolicy> = {
		native_public: {
				slidingTtlMs: 14 * 24 * 60 * 60 * 1000,
				absoluteTtlMs: 90 * 24 * 60 * 60 * 1000
		},
		confidential_web: {
				slidingTtlMs: 24 * 60 * 60 * 1000,
				absoluteTtlMs: 30 * 24 * 60 * 60 * 1000
		}
};

export type RefreshRotationErrorCode =
		// Unknown, expired, revoked or consumed token; also replay (after family revocation). Always
		// maps to OAuth `invalid_grant` -- the client must re-run interactive authentication.
		| "invalid_refresh_token"
		// A valid token was presented by the wrong client. Maps to `invalid_grant` without consuming
		// the token (client misconfiguration must not destroy the legitimate holder's grant).
		| "client_mismatch"
		// Lost a same-instant race against another refresh using the same token. Maps to
		// `invalid_grant`; the winner's response carries the only valid successor. Clients MUST
		// serialize refreshes and MUST NOT blindly retry a refresh request (a retry presents a
		// consumed token and triggers family revocation).
		| "concurrent_rotation";

export class RefreshRotationError extends Error {
		constructor(
				readonly code: RefreshRotationErrorCode,
				message: string,
				// True when this failure revoked the token's whole family (confirmed reuse).
				readonly familyRevoked = false
		) {
				super(message);
				this.name = "RefreshRotationError";
		}
}

export type IssuedRefreshToken = {
		// Returned exactly once; only the hash is persisted.
		refreshToken: string;
		family: RefreshTokenFamily;
		generation: RefreshTokenGeneration;
};

export function hashRefreshToken(token: string): string {
		return createHash("sha256").update(token).digest("base64url");
}

export type IssueRefreshFamilyInput = {
		identitySubjectId: string;
		clientId: string;
		scope: string;
		clientProfile: RefreshClientProfile;
		sessionId?: string;
		deviceReference?: string;
		authenticationMethod?: string;
		authenticatedAt?: string;
};

// HAPI ID V2-C rotating refresh-token family service (implements the approved V2-B design).
// Behavior gate: the OIDC layer only invokes this service when HAPI_REFRESH_GRANT_ENABLED is on;
// the service itself is inert otherwise. Raw refresh tokens exist only in return values -- they
// are never persisted, logged, or accepted from anywhere except the token endpoint.
export class RefreshTokenRotationService {
		constructor(
				private readonly repository: RefreshTokenFamilyRepository = defaultRepository(),
				private readonly lifetimes: Record<RefreshClientProfile, RefreshLifetimePolicy> = REFRESH_LIFETIMES,
				private readonly now: () => Date = () => new Date()
		) {}

		// Issuance at authorization-code exchange: creates the family and generation 1 atomically.
		async issueFamily(input: IssueRefreshFamilyInput): Promise<IssuedRefreshToken> {
				const policy = this.lifetimes[input.clientProfile];
				const at = this.now();
				const refreshToken = this.mintToken();
				const absoluteExpiresAt = new Date(at.getTime() + policy.absoluteTtlMs);
				const generationExpiresAt = new Date(Math.min(
						at.getTime() + policy.slidingTtlMs,
						absoluteExpiresAt.getTime()));

				const created = await this.repository.createFamily({
						familyId: randomUUID(),
						generationId: randomUUID(),
						identitySubjectId: input.identitySubjectId,
						clientId: input.clientId,
						scope: input.scope,
						tokenHash: hashRefreshToken(refreshToken),
						...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
						...(input.deviceReference !== undefined ? { deviceReference: input.deviceReference } : {}),
						...(input.authenticationMethod !== undefined
								? { authenticationMethod: input.authenticationMethod } : {}),
						...(input.authenticatedAt !== undefined ? { authenticatedAt: input.authenticatedAt } : {}),
						absoluteExpiresAt: absoluteExpiresAt.toISOString(),
						generationExpiresAt: generationExpiresAt.toISOString(),
						now: at.toISOString()
				});
				return { refreshToken, family: created.family, generation: created.generation };
		}

		// grant_type=refresh_token: one-time consumption with atomic successor mint. Every failure
		// throws a typed RefreshRotationError; raw token material never appears in error messages.
		async rotate(input: {
				refreshToken: string;
				clientId: string;
				clientProfile: RefreshClientProfile;
		}): Promise<IssuedRefreshToken> {
				const policy = this.lifetimes[input.clientProfile];
				const at = this.now();
				const successorToken = this.mintToken();
				const outcome = await this.repository.rotate({
						presentedTokenHash: hashRefreshToken(input.refreshToken),
						clientId: input.clientId,
						newGenerationId: randomUUID(),
						newTokenHash: hashRefreshToken(successorToken),
						slidingTtlMs: policy.slidingTtlMs,
						now: at.toISOString()
				});

				switch (outcome.status) {
						case "rotated":
								return { refreshToken: successorToken, family: outcome.family, generation: outcome.generation };
						case "reuse_detected":
								// Confirmed replay: the repository revoked the entire family in the same
								// transaction. The legitimate holder's next refresh also fails -- interactive
								// re-authentication is required.
								throw new RefreshRotationError("invalid_refresh_token",
										"Refresh token reuse detected; token family revoked", true);
						case "client_mismatch":
								throw new RefreshRotationError("client_mismatch",
										"Refresh token was not issued to this client");
						case "concurrent_rotation":
								throw new RefreshRotationError("concurrent_rotation",
										"Concurrent refresh detected; retry with the latest refresh token is not possible -- re-authenticate");
						case "not_found":
						case "family_revoked":
						case "family_expired":
						case "generation_expired":
								throw new RefreshRotationError("invalid_refresh_token",
										"Refresh token is invalid, expired, or revoked");
				}
		}

		// Explicit revocations: logout, per-session, per-device, subject lifecycle, RFC 7009.
		async revokeFamily(familyId: string, reason: RefreshTokenFamilyRevocationReason): Promise<boolean> {
				return this.repository.revokeFamily(familyId, reason, this.now().toISOString());
		}

		async revokePresentedToken(refreshToken: string, reason: RefreshTokenFamilyRevocationReason = "client_request"): Promise<boolean> {
				return this.repository.revokeFamilyByTokenHash(
						hashRefreshToken(refreshToken), reason, this.now().toISOString());
		}

		async revokeAllForSubject(identitySubjectId: string, reason: RefreshTokenFamilyRevocationReason): Promise<number> {
				return this.repository.revokeAllForSubject(identitySubjectId, reason, this.now().toISOString());
		}

		async revokeBySession(sessionId: string, reason: RefreshTokenFamilyRevocationReason = "session_revoked"): Promise<number> {
				return this.repository.revokeBySession(sessionId, reason, this.now().toISOString());
		}

		async revokeByDevice(
				identitySubjectId: string,
				deviceReference: string,
				reason: RefreshTokenFamilyRevocationReason = "device_revoked"
		): Promise<number> {
				return this.repository.revokeByDevice(
						identitySubjectId, deviceReference, reason, this.now().toISOString());
		}

		async getFamily(familyId: string): Promise<RefreshTokenFamily | undefined> {
				return this.repository.findFamily(familyId);
		}

		async listFamilies(identitySubjectId: string): Promise<RefreshTokenFamily[]> {
				return this.repository.listFamiliesBySubject(identitySubjectId);
		}

		async listGenerations(familyId: string): Promise<RefreshTokenGeneration[]> {
				return this.repository.listGenerations(familyId);
		}

		private mintToken(): string {
				return `hrt_${randomBytes(REFRESH_TOKEN_BYTES).toString("base64url")}`;
		}
}

function defaultRepository(): RefreshTokenFamilyRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? new InMemoryRefreshTokenFamilyRepository()
				: new PostgresRefreshTokenFamilyRepository();
}
