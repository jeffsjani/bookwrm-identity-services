import type {
		RefreshTokenFamily,
		RefreshTokenGeneration
} from "../../models/RefreshTokenFamily.js";
import type {
		CreateRefreshTokenFamilyCommand,
		RefreshTokenFamilyRepository,
		RotateRefreshTokenCommand,
		RotateRefreshTokenOutcome
} from "./RefreshTokenFamilyRepository.js";

// Test-only mirror of PostgresRefreshTokenFamilyRepository invariants, including the single
// active generation per family rule and same-transaction family revocation on reuse.
export class InMemoryRefreshTokenFamilyRepository implements RefreshTokenFamilyRepository {
		private readonly families = new Map<string, RefreshTokenFamily>();
		private readonly generations = new Map<string, RefreshTokenGeneration>();
		// Serializes rotations the way row locks do in PostgreSQL, so concurrent rotate() calls in
		// tests observe the same fail-closed semantics.
		private rotationQueue: Promise<unknown> = Promise.resolve();

		async createFamily(command: CreateRefreshTokenFamilyCommand) {
				this.assertUniqueTokenHash(command.tokenHash);
				const family: RefreshTokenFamily = {
						id: command.familyId,
						identitySubjectId: command.identitySubjectId,
						clientId: command.clientId,
						scope: command.scope,
						...(command.sessionId !== undefined ? { sessionId: command.sessionId } : {}),
						...(command.deviceReference !== undefined ? { deviceReference: command.deviceReference } : {}),
						...(command.authenticationMethod !== undefined
								? { authenticationMethod: command.authenticationMethod } : {}),
						...(command.authenticatedAt !== undefined ? { authenticatedAt: command.authenticatedAt } : {}),
						status: "active",
						absoluteExpiresAt: command.absoluteExpiresAt,
						createdAt: command.now,
						updatedAt: command.now
				};
				const generation: RefreshTokenGeneration = {
						id: command.generationId,
						familyId: command.familyId,
						tokenHash: command.tokenHash,
						generation: 1,
						status: "active",
						expiresAt: command.generationExpiresAt,
						createdAt: command.now,
						updatedAt: command.now
				};
				this.families.set(family.id, family);
				this.generations.set(generation.id, generation);
				return { family: { ...family }, generation: { ...generation } };
		}

		rotate(command: RotateRefreshTokenCommand): Promise<RotateRefreshTokenOutcome> {
				const run = this.rotationQueue.then(() => this.rotateSerialized(command));
				this.rotationQueue = run.catch(() => undefined);
				return run;
		}

		private async rotateSerialized(command: RotateRefreshTokenCommand): Promise<RotateRefreshTokenOutcome> {
				const presented = [...this.generations.values()]
						.find((generation) => generation.tokenHash === command.presentedTokenHash);
				if (!presented) {
						return { status: "not_found" };
				}
				const family = this.families.get(presented.familyId);
				if (!family) {
						return { status: "not_found" };
				}
				if (family.status === "revoked") {
						return { status: "family_revoked" };
				}
				const nowMs = Date.parse(command.now);
				if (family.status === "expired" || Date.parse(family.absoluteExpiresAt) <= nowMs) {
						family.status = "expired";
						family.updatedAt = command.now;
						return { status: "family_expired" };
				}
				if (family.clientId !== command.clientId) {
						return { status: "client_mismatch" };
				}
				if (presented.status === "rotated" || presented.status === "revoked") {
						// Replay of a consumed token: standard OAuth 2.1 response -- revoke the whole family.
						this.revokeFamilyInternal(family, "reuse_detected", command.now);
						return { status: "reuse_detected", familyId: family.id };
				}
				if (presented.status === "expired" || Date.parse(presented.expiresAt) <= nowMs) {
						presented.status = "expired";
						presented.updatedAt = command.now;
						return { status: "generation_expired" };
				}

				presented.status = "rotated";
				presented.rotatedAt = command.now;
				presented.replacedBy = command.newGenerationId;
				presented.updatedAt = command.now;

				const expiresAt = new Date(Math.min(
						nowMs + command.slidingTtlMs,
						Date.parse(family.absoluteExpiresAt))).toISOString();
				const successor: RefreshTokenGeneration = {
						id: command.newGenerationId,
						familyId: family.id,
						tokenHash: command.newTokenHash,
						generation: presented.generation + 1,
						status: "active",
						expiresAt,
						createdAt: command.now,
						updatedAt: command.now
				};
				this.generations.set(successor.id, successor);
				family.updatedAt = command.now;
				return { status: "rotated", family: { ...family }, generation: { ...successor } };
		}

		async revokeFamily(familyId: string, reason: string, at: string): Promise<boolean> {
				const family = this.families.get(familyId);
				if (!family || family.status !== "active") {
						return false;
				}
				this.revokeFamilyInternal(family, reason, at);
				return true;
		}

		async revokeFamilyByTokenHash(tokenHash: string, reason: string, at: string): Promise<boolean> {
				const generation = [...this.generations.values()]
						.find((candidate) => candidate.tokenHash === tokenHash);
				if (!generation) {
						return false;
				}
				return this.revokeFamily(generation.familyId, reason, at);
		}

		async revokeAllForSubject(identitySubjectId: string, reason: string, at: string): Promise<number> {
				let count = 0;
				for (const family of this.families.values()) {
						if (family.identitySubjectId === identitySubjectId && family.status === "active") {
								this.revokeFamilyInternal(family, reason, at);
								count += 1;
						}
				}
				return count;
		}

		async revokeBySession(sessionId: string, reason: string, at: string): Promise<number> {
				let count = 0;
				for (const family of this.families.values()) {
						if (family.sessionId === sessionId && family.status === "active") {
								this.revokeFamilyInternal(family, reason, at);
								count += 1;
						}
				}
				return count;
		}

		async revokeByDevice(
				identitySubjectId: string,
				deviceReference: string,
				reason: string,
				at: string
		): Promise<number> {
				let count = 0;
				for (const family of this.families.values()) {
						if (family.identitySubjectId === identitySubjectId
								&& family.deviceReference === deviceReference
								&& family.status === "active") {
								this.revokeFamilyInternal(family, reason, at);
								count += 1;
						}
				}
				return count;
		}

		async findFamily(familyId: string): Promise<RefreshTokenFamily | undefined> {
				const family = this.families.get(familyId);
				return family ? { ...family } : undefined;
		}

		async listFamiliesBySubject(identitySubjectId: string): Promise<RefreshTokenFamily[]> {
				return [...this.families.values()]
						.filter((family) => family.identitySubjectId === identitySubjectId)
						.sort((a, b) => a.createdAt.localeCompare(b.createdAt))
						.map((family) => ({ ...family }));
		}

		async listGenerations(familyId: string): Promise<RefreshTokenGeneration[]> {
				return [...this.generations.values()]
						.filter((generation) => generation.familyId === familyId)
						.sort((a, b) => a.generation - b.generation)
						.map((generation) => ({ ...generation }));
		}

		private revokeFamilyInternal(family: RefreshTokenFamily, reason: string, at: string): void {
				family.status = "revoked";
				family.revokedAt = at;
				family.revocationReason = reason;
				family.updatedAt = at;
				for (const generation of this.generations.values()) {
						if (generation.familyId === family.id && generation.status === "active") {
								generation.status = "revoked";
								generation.updatedAt = at;
						}
				}
		}

		private assertUniqueTokenHash(tokenHash: string): void {
				for (const generation of this.generations.values()) {
						if (generation.tokenHash === tokenHash) {
								throw Object.assign(new Error("duplicate refresh token hash"), { code: "23505" });
						}
				}
		}
}
