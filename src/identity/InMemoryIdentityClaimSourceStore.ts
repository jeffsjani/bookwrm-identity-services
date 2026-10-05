import type { IdentityClaimName } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";
import type { ClaimSourceMap, ClaimTimestampMap, IdentityClaimSourceStore } from "./IdentityClaimSourceStore.js";

// Deterministic, process-local stand-in for PostgresIdentityClaimSourceStore (unit tests only --
// never used in production, see IdentityRegistry-style driver selection in IdentityClaimResolver).
export class InMemoryIdentityClaimSourceStore implements IdentityClaimSourceStore {
		private readonly sourcesByIdentitySubjectId = new Map<string, ClaimSourceMap>();
		private readonly updatedAtByIdentitySubjectId = new Map<string, ClaimTimestampMap>();

		async getClaimSources(identitySubjectId: string): Promise<ClaimSourceMap> {
				return { ...(this.sourcesByIdentitySubjectId.get(identitySubjectId) ?? {}) };
		}

		async getClaimUpdatedAt(identitySubjectId: string): Promise<ClaimTimestampMap> {
				return { ...(this.updatedAtByIdentitySubjectId.get(identitySubjectId) ?? {}) };
		}

		async recordClaimSource(identitySubjectId: string, claim: IdentityClaimName, source: IdentityClaimSource, timestamp: string): Promise<void> {
				const sources = this.sourcesByIdentitySubjectId.get(identitySubjectId) ?? {};
				sources[claim] = source;
				this.sourcesByIdentitySubjectId.set(identitySubjectId, sources);

				const timestamps = this.updatedAtByIdentitySubjectId.get(identitySubjectId) ?? {};
				timestamps[claim] = timestamp;
				this.updatedAtByIdentitySubjectId.set(identitySubjectId, timestamps);
		}
}

export const inMemoryIdentityClaimSourceStore = new InMemoryIdentityClaimSourceStore();
