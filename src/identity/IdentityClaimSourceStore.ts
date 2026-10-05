import type { IdentityClaimName } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";

export type ClaimSourceMap = Partial<Record<IdentityClaimName, IdentityClaimSource>>;
export type ClaimTimestampMap = Partial<Record<IdentityClaimName, string>>;

// HAPI ID H3P: governance metadata recording which source currently owns each IdentitySubject claim.
// Durable PostgreSQL storage keyed by the immutable identity_subjects.id -- never email,
// oidcSubject, or a mutable provider subject (Task 2). Deliberately minimal: no generalized
// evidence system, just (identitySubjectId, claim) -> (source, updatedAt).
//
// Existing subjects with no row here have genuinely unrecorded/unknown historical provenance
// (Task 5) -- callers must never infer or fabricate a source for them.
export interface IdentityClaimSourceStore {
		getClaimSources(identitySubjectId: string): Promise<ClaimSourceMap>;
		getClaimUpdatedAt(identitySubjectId: string): Promise<ClaimTimestampMap>;
		recordClaimSource(identitySubjectId: string, claim: IdentityClaimName, source: IdentityClaimSource, timestamp: string): Promise<void>;
}
