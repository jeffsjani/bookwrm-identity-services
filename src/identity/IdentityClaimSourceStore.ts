import type { IdentityClaimName } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";

export type ClaimSourceMap = Partial<Record<IdentityClaimName, IdentityClaimSource>>;
export type ClaimTimestampMap = Partial<Record<IdentityClaimName, string>>;

// Durable-for-process-lifetime record of which source currently owns each claim (governance
// metadata only -- not part of the IdentitySubject persistence schema, see Phase 3.1 non-goals).
const sourcesByOidcSubject = new Map<string, ClaimSourceMap>();
const updatedAtByOidcSubject = new Map<string, ClaimTimestampMap>();

export function getClaimSources(oidcSubject: string): ClaimSourceMap {
		return { ...(sourcesByOidcSubject.get(oidcSubject) ?? {}) };
}

export function getClaimUpdatedAt(oidcSubject: string): ClaimTimestampMap {
		return { ...(updatedAtByOidcSubject.get(oidcSubject) ?? {}) };
}

export function recordClaimSource(oidcSubject: string, claim: IdentityClaimName, source: IdentityClaimSource, timestamp: string): void {
		const sources = sourcesByOidcSubject.get(oidcSubject) ?? {};
		sources[claim] = source;
		sourcesByOidcSubject.set(oidcSubject, sources);

		const timestamps = updatedAtByOidcSubject.get(oidcSubject) ?? {};
		timestamps[claim] = timestamp;
		updatedAtByOidcSubject.set(oidcSubject, timestamps);
}
