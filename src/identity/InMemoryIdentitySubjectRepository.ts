import type { IdentityProvider, IdentitySubject } from "../models/IdentitySubject.js";
import type {
		CreateIdentitySubjectInput,
		IdentitySubjectRepository,
		UpdateIdentitySubjectInput
} from "./IdentitySubjectRepository.js";

function providerKey(provider: IdentityProvider, providerSubject: string): string {
		return `${provider}:${providerSubject}`;
}

// Test-only stand-in for PostgresIdentitySubjectRepository; never used in production (Task 7).
export class InMemoryIdentitySubjectRepository implements IdentitySubjectRepository {
		private readonly subjectsById = new Map<string, IdentitySubject>();
		private readonly idByOidcSubject = new Map<string, string>();
		private readonly idByProviderKey = new Map<string, string>();

		async create(input: CreateIdentitySubjectInput): Promise<IdentitySubject> {
				if (this.idByOidcSubject.has(input.oidcSubject)) {
						throw new Error(`IdentitySubject oidcSubject collision: ${input.oidcSubject}`);
				}

				const key = providerKey(input.primaryProvider, input.primaryProviderSubject);
				if (this.idByProviderKey.has(key)) {
						throw new Error(`IdentitySubject provider identity already linked: ${key}`);
				}

				const now = new Date().toISOString();
				const subject: IdentitySubject = {
						...input,
						createdAt: now,
						updatedAt: now,
						lastAuthenticatedAt: now
				};

				this.subjectsById.set(subject.id, subject);
				this.idByOidcSubject.set(subject.oidcSubject, subject.id);
				this.idByProviderKey.set(key, subject.id);
				return { ...subject };
		}

		async findByOidcSubject(oidcSubject: string): Promise<IdentitySubject | undefined> {
				const id = this.idByOidcSubject.get(oidcSubject);
				const subject = id ? this.subjectsById.get(id) : undefined;
				return subject ? { ...subject } : undefined;
		}

		async findByProviderSubject(provider: IdentityProvider, providerSubject: string): Promise<IdentitySubject | undefined> {
				const id = this.idByProviderKey.get(providerKey(provider, providerSubject));
				const subject = id ? this.subjectsById.get(id) : undefined;
				return subject ? { ...subject } : undefined;
		}

		async update(oidcSubject: string, changes: UpdateIdentitySubjectInput): Promise<IdentitySubject | undefined> {
				const id = this.idByOidcSubject.get(oidcSubject);
				const subject = id ? this.subjectsById.get(id) : undefined;
				if (!subject) {
						return undefined;
				}

				Object.assign(subject, changes, { updatedAt: new Date().toISOString() });
				return { ...subject };
		}

		async touchLastAuthentication(oidcSubject: string): Promise<IdentitySubject | undefined> {
				const id = this.idByOidcSubject.get(oidcSubject);
				const subject = id ? this.subjectsById.get(id) : undefined;
				if (!subject) {
						return undefined;
				}

				const now = new Date().toISOString();
				subject.updatedAt = now;
				subject.lastAuthenticatedAt = now;
				return { ...subject };
		}

		async delete(oidcSubject: string): Promise<boolean> {
				const id = this.idByOidcSubject.get(oidcSubject);
				if (!id) {
						return false;
				}

				const subject = this.subjectsById.get(id);
				if (subject) {
						this.idByProviderKey.delete(providerKey(subject.primaryProvider, subject.primaryProviderSubject));
				}

				this.idByOidcSubject.delete(oidcSubject);
				this.subjectsById.delete(id);
				return true;
		}

		async exists(provider: IdentityProvider, providerSubject: string): Promise<boolean> {
				return this.idByProviderKey.has(providerKey(provider, providerSubject));
		}

		async relinkPrimaryProviderSubject(oidcSubject: string, newProviderSubject: string): Promise<IdentitySubject | undefined> {
				const id = this.idByOidcSubject.get(oidcSubject);
				const subject = id ? this.subjectsById.get(id) : undefined;
				if (!subject) {
						return undefined;
				}

				const newKey = providerKey(subject.primaryProvider, newProviderSubject);
				const existingOwnerId = this.idByProviderKey.get(newKey);
				if (existingOwnerId && existingOwnerId !== id) {
						throw new Error(`Provider identity already linked to a different IdentitySubject: ${newKey}`);
				}

				this.idByProviderKey.delete(providerKey(subject.primaryProvider, subject.primaryProviderSubject));
				subject.primaryProviderSubject = newProviderSubject;
				subject.updatedAt = new Date().toISOString();
				this.idByProviderKey.set(newKey, id as string);
				return { ...subject };
		}

		async list(): Promise<IdentitySubject[]> {
				return [...this.subjectsById.values()].map((subject) => ({ ...subject }));
		}

		async findByEmail(email: string): Promise<IdentitySubject[]> {
				return [...this.subjectsById.values()]
						.filter((subject) => subject.email === email)
						.map((subject) => ({ ...subject }));
		}

		// Mirrors the Postgres ON CONFLICT DO UPDATE semantics: first writer wins the row,
		// later callers only get their last-authenticated timestamp touched.
		async resolveOrCreate(input: CreateIdentitySubjectInput): Promise<IdentitySubject> {
				const key = providerKey(input.primaryProvider, input.primaryProviderSubject);
				const existingId = this.idByProviderKey.get(key);
				if (existingId) {
						const existing = this.subjectsById.get(existingId);
						if (existing) {
								const now = new Date().toISOString();
								existing.updatedAt = now;
								existing.lastAuthenticatedAt = now;
								return { ...existing };
						}
				}

				return this.create(input);
		}
}
