import type { OIDCClientRecord, OIDCClientTokenEndpointAuthMethod } from "../models/OIDCClientRecord.js";

export type UpsertOIDCClientInput = {
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
};

// Storage contract for OIDCClientRecord. Replaces the hardcoded Base44 client configuration
// previously baked into src/oidc/clients.ts (H1 foundation release).
export interface OIDCClientRepository {
		findByClientId(clientId: string): Promise<OIDCClientRecord | undefined>;
		listByApplication(applicationId: string): Promise<OIDCClientRecord[]>;
		list(): Promise<OIDCClientRecord[]>;
		// Idempotent create-or-update keyed by clientId; used by platform seeding (H1 Bookwrm backfill).
		upsert(input: UpsertOIDCClientInput): Promise<OIDCClientRecord>;
}
