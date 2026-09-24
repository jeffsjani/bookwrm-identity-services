// Fixed, deterministic identifiers for Bookwrm's Tenant/Application so seeding is idempotent across
// environments and every reference to "Bookwrm" in HAPI ID Core is just these two UUIDs (H1 foundation release).
export const BOOKWRM_TENANT_ID = "00000000-0000-4000-8000-000000000001";
export const BOOKWRM_APPLICATION_ID = "00000000-0000-4000-8000-000000000002";
