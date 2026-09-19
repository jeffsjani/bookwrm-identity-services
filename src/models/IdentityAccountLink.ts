export type IdentityAccountLinkSource = "bookwrm";

export type IdentityAccountLinkStatus = "active";

// Provider-neutral association between an external Bookwrm account and an IdentitySubject.
// Deliberately separate from providerSubject/UserAuthenticator.userId/oidcSubject (Release C5.1).
export type IdentityAccountLink = {
		id: string;
		source: IdentityAccountLinkSource;
		externalUserId: string;
		identitySubjectId: string;
		status: IdentityAccountLinkStatus;
		linkedAt: string;
		updatedAt: string;
};
