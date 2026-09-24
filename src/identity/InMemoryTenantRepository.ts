import type { Tenant } from "../models/Tenant.js";
import type { TenantRepository, UpsertTenantInput } from "./TenantRepository.js";

// Test/default-driver stand-in for PostgresTenantRepository (H1 foundation release).
export class InMemoryTenantRepository implements TenantRepository {
		private readonly tenantsById = new Map<string, Tenant>();

		async findById(id: string): Promise<Tenant | undefined> {
				const tenant = this.tenantsById.get(id);
				return tenant ? { ...tenant } : undefined;
		}

		async findBySlug(slug: string): Promise<Tenant | undefined> {
				const tenant = [...this.tenantsById.values()].find((candidate) => candidate.slug === slug);
				return tenant ? { ...tenant } : undefined;
		}

		async list(): Promise<Tenant[]> {
				return [...this.tenantsById.values()].map((tenant) => ({ ...tenant }));
		}

		async upsert(input: UpsertTenantInput): Promise<Tenant> {
				const existing = this.tenantsById.get(input.id);
				const now = new Date().toISOString();
				const tenant: Tenant = {
						id: input.id,
						name: input.name,
						slug: input.slug,
						status: input.status,
						createdAt: existing?.createdAt ?? now,
						updatedAt: now
				};

				this.tenantsById.set(tenant.id, tenant);
				return { ...tenant };
		}
}

export const inMemoryTenantRepository = new InMemoryTenantRepository();
