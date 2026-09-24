export type OIDCClientTokenEndpointAuthMethod = "client_secret_post" | "client_secret_basic" | "none";

// Persisted, tenant-neutral replacement for the previously hardcoded Base44 OIDC client configuration.
export type OIDCClientRecord = {
		id: string;
		applicationId: string;
		clientId: string;
		clientSecret: string;
		redirectUris: string[];
		scopes: string[];
		grantTypes: string[];
		responseTypes: string[];
		tokenEndpointAuthMethod: OIDCClientTokenEndpointAuthMethod;
		requirePkce: boolean;
		createdAt: string;
		updatedAt: string;
};
