export type ApplicationStatus = "active" | "suspended";
export type AuthenticationMethod = "HAPI_EMAIL" | "PRIVATEID_FACE" | "EXTERNAL_OIDC" | "EXTERNAL_SAML";
export type ApplicationPresentation = {
		logoUri?: string;
		primaryColor?: string;
		accentColor?: string;
		supportUri?: string;
		privacyUri?: string;
		termsUri?: string;
};

// A registered relying-party product within a Tenant (e.g. Bookwrm's Base44 app). Owns one or more OIDCClients.
export type Application = {
		id: string;
		tenantId: string;
		name: string;
		slug: string;
		status: ApplicationStatus;
		applicationKey: string;
		allowedAuthenticationMethods: AuthenticationMethod[];
		allowedIdentityProviders: string[];
		faceSetupEnabled: boolean;
		presentation: ApplicationPresentation;
		createdAt: string;
		updatedAt: string;
};
