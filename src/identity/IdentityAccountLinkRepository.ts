import type { IdentityAccountLink, IdentityAccountLinkSource, IdentityAccountLinkStatus } from "../models/IdentityAccountLink.js";

export type CreateIdentityAccountLinkInput = {
		id: string;
		source: IdentityAccountLinkSource;
		externalUserId: string;
		identitySubjectId: string;
		status: IdentityAccountLinkStatus;
};

// Storage contract for IdentityAccountLink. Uniqueness on (source, externalUserId) is enforced by
// implementations so a Bookwrm account can never silently become linked to a different IdentitySubject.
export interface IdentityAccountLinkRepository {
		findByExternalUserId(source: IdentityAccountLinkSource, externalUserId: string): Promise<IdentityAccountLink | undefined>;
		create(input: CreateIdentityAccountLinkInput): Promise<IdentityAccountLink>;
}
