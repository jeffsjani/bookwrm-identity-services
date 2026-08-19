export type IdentityAuditEventType =
		| "IDENTITY_CREATED"
		| "AUTHENTICATOR_LINKED"
		| "AUTHENTICATOR_UNLINKED"
		| "MERGE"
		| "RECOVERY";

export type IdentityAuditEntry = {
		oidcSubject: string;
		type: IdentityAuditEventType;
		detail: Record<string, unknown>;
		timestamp: string;
};

// Append-only; no update/delete is exposed, so entries are immutable once recorded (Task 3).
const auditByOidcSubject = new Map<string, IdentityAuditEntry[]>();

export function recordIdentityAudit(
		oidcSubject: string,
		type: IdentityAuditEventType,
		detail: Record<string, unknown> = {}
): IdentityAuditEntry {
		const entry: IdentityAuditEntry = { oidcSubject, type, detail, timestamp: new Date().toISOString() };
		const entries = auditByOidcSubject.get(oidcSubject) ?? [];
		entries.push(entry);
		auditByOidcSubject.set(oidcSubject, entries);
		return entry;
}

export function getIdentityAudit(oidcSubject: string): IdentityAuditEntry[] {
		return [...(auditByOidcSubject.get(oidcSubject) ?? [])];
}
