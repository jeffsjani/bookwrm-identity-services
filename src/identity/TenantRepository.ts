import type { Tenant, TenantStatus } from "../models/Tenant.js";

export type UpsertTenantInput = {
		id: string;
		name: string;
		slug: string;
		status: TenantStatus;
};

// Storage contract for Tenant. No application/OIDC logic belongs here.
export interface TenantRepository {
		findById(id: string): Promise<Tenant | undefined>;
		findBySlug(slug: string): Promise<Tenant | undefined>;
		list(): Promise<Tenant[]>;
		// Idempotent create-or-update keyed by id; used by platform seeding (H1 Bookwrm backfill).
		upsert(input: UpsertTenantInput): Promise<Tenant>;
}
