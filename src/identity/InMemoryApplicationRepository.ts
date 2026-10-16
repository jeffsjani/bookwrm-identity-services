import type { Application } from "../models/Application.js";
import type { ApplicationRepository, UpsertApplicationInput } from "./ApplicationRepository.js";

// Test/default-driver stand-in for PostgresApplicationRepository (H1 foundation release).
export class InMemoryApplicationRepository implements ApplicationRepository {
		private readonly applicationsById = new Map<string, Application>();

		async findById(id: string): Promise<Application | undefined> {
				const application = this.applicationsById.get(id);
				return application ? structuredClone(application) : undefined;
		}

		async findByTenantAndSlug(tenantId: string, slug: string): Promise<Application | undefined> {
				const application = [...this.applicationsById.values()].find(
						(candidate) => candidate.tenantId === tenantId && candidate.slug === slug
				);
				return application ? structuredClone(application) : undefined;
		}

		async listByTenant(tenantId: string): Promise<Application[]> {
				return [...this.applicationsById.values()]
						.filter((candidate) => candidate.tenantId === tenantId)
						.map((application) => structuredClone(application));
		}

		async upsert(input: UpsertApplicationInput): Promise<Application> {
				const existing = this.applicationsById.get(input.id);
				const applicationKey = input.applicationKey ?? existing?.applicationKey ?? input.id;
				if ([...this.applicationsById.values()].some(app => app.id !== input.id && app.applicationKey === applicationKey)) {
						throw new Error("Application key already registered");
				}
				const now = new Date().toISOString();
				const application: Application = {
						id: input.id,
						tenantId: input.tenantId,
						name: input.name,
						slug: input.slug,
						status: input.status,
						applicationKey,
						allowedAuthenticationMethods: [...(input.allowedAuthenticationMethods ?? existing?.allowedAuthenticationMethods ?? ["HAPI_EMAIL"])],
						allowedIdentityProviders: [...(input.allowedIdentityProviders ?? existing?.allowedIdentityProviders ?? [])],
						faceSetupEnabled: input.faceSetupEnabled ?? existing?.faceSetupEnabled ?? false,
						presentation: { ...(input.presentation ?? existing?.presentation ?? {}) },
						createdAt: existing?.createdAt ?? now,
						updatedAt: now
				};

				this.applicationsById.set(application.id, application);
				return structuredClone(application);
		}
}

export const inMemoryApplicationRepository = new InMemoryApplicationRepository();
