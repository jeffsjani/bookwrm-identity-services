import type { IdentityClaimName } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";

export type ClaimAuditEntry = {
		oidcSubject: string;
		claim: IdentityClaimName;
		oldValue: unknown;
		newValue: unknown;
		source: IdentityClaimSource;
		timestamp: string;
		reason: string;
};

export type ClaimAuditInput = Omit<ClaimAuditEntry, "timestamp">;

const auditByOidcSubject = new Map<string, ClaimAuditEntry[]>();

// Every accepted/updated claim change is recorded here; this is the only write path (Task 6).
export function recordClaimAudit(input: ClaimAuditInput): ClaimAuditEntry {
		const entry: ClaimAuditEntry = { ...input, timestamp: new Date().toISOString() };
		const entries = auditByOidcSubject.get(input.oidcSubject) ?? [];
		entries.push(entry);
		auditByOidcSubject.set(input.oidcSubject, entries);
		return entry;
}

export function getClaimAudit(oidcSubject: string): ClaimAuditEntry[] {
		return [...(auditByOidcSubject.get(oidcSubject) ?? [])];
}
