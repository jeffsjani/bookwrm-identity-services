import { createHash } from "node:crypto";

import type {
		ExternalIdentity,
		ExternalIdentityProvider,
		IdentityAuthenticationMethod,
		IdentityLinkAuditEntry
} from "../models/ExternalIdentity.js";

// Keyed, non-reversible reference to a provider subject for append-only audit rows.
export function providerSubjectRef(providerSubject: string): string {
		return createHash("sha256").update(providerSubject).digest("base64url");
}

export type LinkExternalIdentityCommand = {
		// Server-generated identifiers (never caller-supplied protocol values).
		externalIdentityId: string;
		methodId: string;
		identitySubjectId: string;
		provider: ExternalIdentityProvider;
		providerIssuer: string;
		providerSubject: string;
		providerClientContext?: string;
		// Reference to authentication evidence (record id or hash); never a raw provider token.
		evidenceReference?: string;
		correlationId: string;
};

export type LinkConflictReason =
		| "provider_identity_linked_to_other_subject"
		| "subject_provider_already_linked";

export type LinkExternalIdentityResult =
		| { status: "linked"; externalIdentity: ExternalIdentity }
		// Exact same provider identity already linked to the same subject: idempotent retry.
		| { status: "already_linked"; externalIdentity: ExternalIdentity }
		| { status: "conflict"; reason: LinkConflictReason }
		| { status: "rejected"; reason: "subject_not_found" | "subject_not_active" };

export type UnlinkExternalIdentityCommand = {
		identitySubjectId: string;
		externalIdentityId: string;
		evidenceReference?: string;
		correlationId: string;
};

export type UnlinkExternalIdentityResult =
		| { status: "unlinked"; externalIdentity: ExternalIdentity }
		| { status: "rejected"; reason: "not_found" | "last_method" };

export type NewIdentityLinkAuditEntry = Omit<IdentityLinkAuditEntry, "occurredAt">;

// Transactional system-of-record operations for external identity linking. Implementations must
// guarantee: (1) link/unlink mutations and their audit rows commit atomically; (2) the exact
// provider identity is unique among active links (database-enforced, fail-closed under
// concurrency); (3) unlinking never removes a subject's last usable authentication method.
export interface ExternalIdentityRepository {
		link(command: LinkExternalIdentityCommand): Promise<LinkExternalIdentityResult>;
		unlink(command: UnlinkExternalIdentityCommand): Promise<UnlinkExternalIdentityResult>;
		findActiveByProviderIdentity(
				provider: ExternalIdentityProvider,
				providerIssuer: string,
				providerSubject: string
		): Promise<ExternalIdentity | undefined>;
		listBySubject(identitySubjectId: string): Promise<ExternalIdentity[]>;
		// Includes the derived HAPI_EMAIL method when the subject's primary provider is a verified email.
		listAuthenticationMethods(identitySubjectId: string): Promise<IdentityAuthenticationMethod[]>;
		listAudit(identitySubjectId: string): Promise<IdentityLinkAuditEntry[]>;
}
