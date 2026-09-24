export type ApplicationStatus = "active" | "suspended";

// A registered relying-party product within a Tenant (e.g. Bookwrm's Base44 app). Owns one or more OIDCClients.
export type Application = {
		id: string;
		tenantId: string;
		name: string;
		slug: string;
		status: ApplicationStatus;
		createdAt: string;
		updatedAt: string;
};
