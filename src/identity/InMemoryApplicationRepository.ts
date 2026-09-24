import type { Application } from "../models/Application.js";
import type { ApplicationRepository, UpsertApplicationInput } from "./ApplicationRepository.js";

// Test/default-driver stand-in for PostgresApplicationRepository (H1 foundation release).
export class InMemoryApplicationRepository implements ApplicationRepository {
		private readonly applicationsById = new Map<string, Application>();

		async findById(id: string): Promise<Application | undefined> {
				const application = this.applicationsById.get(id);
				return application ? { ...application } : undefined;
		}

		async findByTenantAndSlug(tenantId: string, slug: string): Promise<Application | undefined> {
				const application = [...this.applicationsById.values()].find(
						(candidate) => candidate.tenantId === tenantId && candidate.slug === slug
				);
				return application ? { ...application } : undefined;
		}

		async listByTenant(tenantId: string): Promise<Application[]> {
				return [...this.applicationsById.values()]
						.filter((candidate) => candidate.tenantId === tenantId)
						.map((application) => ({ ...application }));
		}

		async upsert(input: UpsertApplicationInput): Promise<Application> {
				const existing = this.applicationsById.get(input.id);
				const now = new Date().toISOString();
				const application: Application = {
						id: input.id,
						tenantId: input.tenantId,
						name: input.name,
						slug: input.slug,
						status: input.status,
						createdAt: existing?.createdAt ?? now,
						updatedAt: now
				};

				this.applicationsById.set(application.id, application);
				return { ...application };
		}
}

export const inMemoryApplicationRepository = new InMemoryApplicationRepository();
