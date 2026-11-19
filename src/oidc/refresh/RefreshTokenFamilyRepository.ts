import type {
		RefreshTokenFamily,
		RefreshTokenGeneration
} from "../../models/RefreshTokenFamily.js";

export type CreateRefreshTokenFamilyCommand = {
		// Server-generated identifiers and hashes (never caller-supplied protocol values).
		familyId: string;
		generationId: string;
		identitySubjectId: string;
		clientId: string;
		scope: string;
		tokenHash: string;
		sessionId?: string;
		deviceReference?: string;
		authenticationMethod?: string;
		authenticatedAt?: string;
		absoluteExpiresAt: string;
		generationExpiresAt: string;
		now: string;
};

export type RotateRefreshTokenCommand = {
		// Hash of the token presented by the client; never the raw token.
		presentedTokenHash: string;
		// Authenticated client identity making the refresh call.
		clientId: string;
		// Server-generated successor.
		newGenerationId: string;
		newTokenHash: string;
		// min(now + sliding TTL, family absolute ceiling) is computed by the repository.
		slidingTtlMs: number;
		now: string;
};

export type RotateRefreshTokenOutcome =
		// One-time consumption succeeded: presented generation is terminally 'rotated', successor active.
		| { status: "rotated"; family: RefreshTokenFamily; generation: RefreshTokenGeneration }
		| { status: "not_found" }
		// Replay of an already-consumed (or revoked) generation: the ENTIRE family was revoked in the
		// same transaction (reason 'reuse_detected') before this result was returned.
		| { status: "reuse_detected"; familyId: string }
		| { status: "family_revoked" }
		| { status: "family_expired" }
		| { status: "generation_expired" }
		// The presented token belongs to a family bound to a different client.
		| { status: "client_mismatch" }
		// Lost a same-instant race: another transaction rotated this generation first and the active
		// uniqueness constraint rejected the second successor. Nothing was changed by the loser.
		| { status: "concurrent_rotation" };

// Transactional refresh-token family system of record. Implementations must guarantee:
// (1) rotation is atomic -- consume + successor insert commit together or not at all;
// (2) at most one active generation per family (database-enforced, fail-closed under concurrency);
// (3) reuse of a consumed generation revokes the whole family in the same transaction;
// (4) raw tokens are never stored -- only hashes.
export interface RefreshTokenFamilyRepository {
		createFamily(command: CreateRefreshTokenFamilyCommand): Promise<{
				family: RefreshTokenFamily;
				generation: RefreshTokenGeneration;
		}>;
		rotate(command: RotateRefreshTokenCommand): Promise<RotateRefreshTokenOutcome>;
		revokeFamily(familyId: string, reason: string, at: string): Promise<boolean>;
		// RFC 7009-style: revoke the family a presented token belongs to (idempotent; unknown tokens
		// report false without error).
		revokeFamilyByTokenHash(tokenHash: string, reason: string, at: string): Promise<boolean>;
		revokeAllForSubject(identitySubjectId: string, reason: string, at: string): Promise<number>;
		revokeBySession(sessionId: string, reason: string, at: string): Promise<number>;
		revokeByDevice(identitySubjectId: string, deviceReference: string, reason: string, at: string): Promise<number>;
		findFamily(familyId: string): Promise<RefreshTokenFamily | undefined>;
		listFamiliesBySubject(identitySubjectId: string): Promise<RefreshTokenFamily[]>;
		listGenerations(familyId: string): Promise<RefreshTokenGeneration[]>;
}
