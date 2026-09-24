import type { Application, ApplicationStatus } from "../models/Application.js";

export type UpsertApplicationInput = {
		id: string;
		tenantId: string;
		name: string;
		slug: string;
		status: ApplicationStatus;
};

// Storage contract for Application. No OIDCClient/tenant logic belongs here.
export interface ApplicationRepository {
		findById(id: string): Promise<Application | undefined>;
		findByTenantAndSlug(tenantId: string, slug: string): Promise<Application | undefined>;
		listByTenant(tenantId: string): Promise<Application[]>;
		// Idempotent create-or-update keyed by id; used by platform seeding (H1 Bookwrm backfill).
		upsert(input: UpsertApplicationInput): Promise<Application>;
}
