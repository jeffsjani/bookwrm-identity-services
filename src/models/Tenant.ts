export type TenantStatus = "active" | "suspended";

// Top-level IDaaS customer boundary. Everything else (Application, OIDCClient, IdentitySubject) is scoped under a Tenant.
export type Tenant = {
		id: string;
		name: string;
		slug: string;
		status: TenantStatus;
		createdAt: string;
		updatedAt: string;
};
