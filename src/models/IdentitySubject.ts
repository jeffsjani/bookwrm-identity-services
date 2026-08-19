import type { IdentityClaimSource } from "../identity/IdentityClaimSource.js";

export type IdentityProvider = "PrivateID" | "Google" | "Apple" | "Passkey" | "Enterprise";

export type IdentitySubjectStatus = "ACTIVE" | "LOCKED" | "DISABLED";

// Claim fields governed by IdentityClaimPolicy/IdentityClaimResolver; sub is deliberately excluded (immutable).
export type IdentityClaimName = "email" | "emailVerified" | "displayName" | "preferredUsername";

// Railway's permanent identity record; oidcSubject is immutable once minted.
export type IdentitySubject = {
		id: string;
		oidcSubject: string;
		primaryProvider: IdentityProvider;
		primaryProviderSubject: string;
		email: string;
		emailVerified: boolean;
		displayName: string;
		status: IdentitySubjectStatus;
		createdAt: string;
		updatedAt: string;
		lastAuthenticatedAt?: string;
		// Governance metadata (Phase 3.1): which source last set each claim, and when.
		claimSources?: Partial<Record<IdentityClaimName, IdentityClaimSource>>;
		claimUpdatedAt?: Partial<Record<IdentityClaimName, string>>;
};
