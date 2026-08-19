import type { IdentitySubject } from "../models/IdentitySubject.js";

export type PendingIdentityStage = "pending" | "persisted" | "blocked";

// Tracks a PrivateID identity between "we know who claims to be authenticating"
// and "IdentityRegistry has durably persisted an IdentitySubject for them" (RC1 Task 6).
export type PendingIdentityRecord = {
		privateIdUserId: string;
		email?: string;
		emailVerified?: boolean;
		displayName?: string;
		stage: PendingIdentityStage;
		identitySubject?: IdentitySubject;
		reason?: string;
};

const pendingByPrivateIdUserId = new Map<string, PendingIdentityRecord>();

export function beginPendingIdentity(
		privateIdUserId: string,
		email: string | undefined,
		emailVerified: boolean | undefined,
		displayName: string | undefined
): PendingIdentityRecord {
		const record: PendingIdentityRecord = { privateIdUserId, email, emailVerified, displayName, stage: "pending" };
		pendingByPrivateIdUserId.set(privateIdUserId, record);
		return record;
}

export function markPersisted(privateIdUserId: string, identitySubject: IdentitySubject): PendingIdentityRecord | undefined {
		const record = pendingByPrivateIdUserId.get(privateIdUserId);
		if (!record) {
				return undefined;
		}

		record.stage = "persisted";
		record.identitySubject = identitySubject;
		record.reason = undefined;
		return record;
}

// Reserved for future account activation state; it never blocks identity creation.
export function markBlocked(privateIdUserId: string, reason: string): PendingIdentityRecord | undefined {
		const record = pendingByPrivateIdUserId.get(privateIdUserId);
		if (!record) {
				return undefined;
		}

		record.stage = "blocked";
		record.reason = reason;
		return record;
}

export function getPendingIdentity(privateIdUserId: string): PendingIdentityRecord | undefined {
		return pendingByPrivateIdUserId.get(privateIdUserId);
}

// Health/observability only (Phase 5 Task 1); not used for any decision logic.
export function getPendingIdentityStats(): { total: number; pending: number; blocked: number } {
		const records = [...pendingByPrivateIdUserId.values()];
		return {
				total: records.length,
				pending: records.filter((record) => record.stage === "pending").length,
				blocked: records.filter((record) => record.stage === "blocked").length
		};
}
