import type { IdentityProvider, IdentitySubject, IdentitySubjectStatus } from "../models/IdentitySubject.js";

export type CreateIdentitySubjectInput = {
		id: string;
		oidcSubject: string;
		primaryProvider: IdentityProvider;
		primaryProviderSubject: string;
		email: string;
		emailVerified: boolean;
		displayName: string;
		status: IdentitySubjectStatus;
};

export type UpdateIdentitySubjectInput = Partial<
		Pick<IdentitySubject, "email" | "emailVerified" | "displayName" | "status">
>;

// Storage contract for IdentitySubject. No OIDC/claims logic belongs here.
export interface IdentitySubjectRepository {
		create(input: CreateIdentitySubjectInput): Promise<IdentitySubject>;
		findByOidcSubject(oidcSubject: string): Promise<IdentitySubject | undefined>;
		findByProviderSubject(provider: IdentityProvider, providerSubject: string): Promise<IdentitySubject | undefined>;
		update(oidcSubject: string, changes: UpdateIdentitySubjectInput): Promise<IdentitySubject | undefined>;
		touchLastAuthentication(oidcSubject: string): Promise<IdentitySubject | undefined>;
		delete(oidcSubject: string): Promise<boolean>;
		exists(provider: IdentityProvider, providerSubject: string): Promise<boolean>;
		// Read-only listing/search for the Identity Administration API (Phase 4).
		list(): Promise<IdentitySubject[]>;
		findByEmail(email: string): Promise<IdentitySubject[]>;
		// Re-points the primary authenticator identifier for Identity Recovery (Phase 5 Task 8).
		// Must fail (or return undefined) if newProviderSubject already belongs to a different oidcSubject.
		relinkPrimaryProviderSubject(oidcSubject: string, newProviderSubject: string): Promise<IdentitySubject | undefined>;
		// Atomically inserts a new subject or returns the pre-existing one for the same provider identity.
		// Guarantees exactly one row per (primaryProvider, primaryProviderSubject) under concurrent calls.
		resolveOrCreate(input: CreateIdentitySubjectInput): Promise<IdentitySubject>;
}
