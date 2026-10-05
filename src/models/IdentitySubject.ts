import type { IdentityClaimSource } from "../identity/IdentityClaimSource.js";

// HAPI ID H3: "HAPI_EMAIL" is the canonical-registration provider identity, keyed by normalized verified
// email (see RegistrationService). It reuses the existing (primaryProvider, primaryProviderSubject)
// uniqueness constraint for atomic duplicate-registration protection; it never changes existing rows.
export type IdentityProvider = "PrivateID" | "Google" | "Apple" | "Passkey" | "Enterprise" | "HAPI_EMAIL";

export type IdentitySubjectStatus = "ACTIVE" | "LOCKED" | "DISABLED";

// Claim fields governed by IdentityClaimPolicy/IdentityClaimResolver; sub is deliberately excluded (immutable).
export type IdentityClaimName = "email" | "emailVerified" | "displayName" | "preferredUsername";

// Railway's permanent identity record; oidcSubject is immutable once minted.
export type IdentitySubject = {
		id: string;
		oidcSubject: string;
		// HAPI ID H1: scopes this subject to an Application (undefined only for pre-H1 rows pending backfill).
		applicationId?: string;
		primaryProvider: IdentityProvider;
		primaryProviderSubject: string;
		email?: string;
		emailVerified?: boolean;
		displayName?: string;
		status: IdentitySubjectStatus;
		createdAt: string;
		updatedAt: string;
		lastAuthenticatedAt?: string;
		// Governance metadata (Phase 3.1): which source last set each claim, and when.
		claimSources?: Partial<Record<IdentityClaimName, IdentityClaimSource>>;
		claimUpdatedAt?: Partial<Record<IdentityClaimName, string>>;
};
