import type { OIDCClientRecord } from "../models/OIDCClientRecord.js";
import type { OIDCClientRepository, UpsertOIDCClientInput } from "./OIDCClientRepository.js";

// Test/default-driver stand-in for PostgresOIDCClientRepository (H1 foundation release).
export class InMemoryOIDCClientRepository implements OIDCClientRepository {
		private readonly clientsById = new Map<string, OIDCClientRecord>();
		private readonly idByClientId = new Map<string, string>();

		async findByClientId(clientId: string): Promise<OIDCClientRecord | undefined> {
				const id = this.idByClientId.get(clientId);
				const record = id ? this.clientsById.get(id) : undefined;
				return record ? { ...record, redirectUris: [...record.redirectUris] } : undefined;
		}

		async listByApplication(applicationId: string): Promise<OIDCClientRecord[]> {
				return [...this.clientsById.values()]
						.filter((candidate) => candidate.applicationId === applicationId)
						.map((record) => ({ ...record, redirectUris: [...record.redirectUris] }));
		}

		async list(): Promise<OIDCClientRecord[]> {
				return [...this.clientsById.values()].map((record) => ({ ...record, redirectUris: [...record.redirectUris] }));
		}

		async upsert(input: UpsertOIDCClientInput): Promise<OIDCClientRecord> {
				const existingId = this.idByClientId.get(input.clientId);
				const existing = existingId ? this.clientsById.get(existingId) : undefined;
				const now = new Date().toISOString();
				const record: OIDCClientRecord = {
						id: existing?.id ?? input.id,
						applicationId: input.applicationId,
						clientId: input.clientId,
						clientSecret: input.clientSecret,
						redirectUris: [...input.redirectUris],
						scopes: [...input.scopes],
						grantTypes: [...input.grantTypes],
						responseTypes: [...input.responseTypes],
						tokenEndpointAuthMethod: input.tokenEndpointAuthMethod,
						requirePkce: input.requirePkce,
						createdAt: existing?.createdAt ?? now,
						updatedAt: now
				};

				this.clientsById.set(record.id, record);
				this.idByClientId.set(record.clientId, record.id);
				return { ...record, redirectUris: [...record.redirectUris] };
		}
}

export const inMemoryOIDCClientRepository = new InMemoryOIDCClientRepository();
