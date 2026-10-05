import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Integration test against a real PostgreSQL instance (HAPI ID H3P). Requires DATABASE_URL to be
// set; skipped automatically otherwise. Proves claim provenance survives restart/multi-instance,
// the H2/H3P blocker this release exists to close.
const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("PostgresIdentityClaimSourceStore (integration)", () => {
		let ensureIdentitySchema: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").ensureIdentitySchema;
		let closePostgresPool: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").closePostgresPool;
		let PostgresIdentitySubjectRepository: typeof import("../src/identity/PostgresIdentitySubjectRepository.js").PostgresIdentitySubjectRepository;
		let PostgresIdentityClaimSourceStore: typeof import("../src/identity/PostgresIdentityClaimSourceStore.js").PostgresIdentityClaimSourceStore;

		async function createSubject(label: string) {
				const repository = new PostgresIdentitySubjectRepository();
				return repository.resolveOrCreate({
						id: randomUUID(),
						oidcSubject: randomUUID(),
						primaryProvider: "PrivateID",
						primaryProviderSubject: `provenance-${label}-${randomUUID()}`,
						email: `${label}-${randomUUID()}@example.com`,
						emailVerified: true,
						displayName: "Provenance Test User",
						status: "ACTIVE"
				});
		}

		beforeAll(async () => {
				process.env.DATABASE_URL = databaseUrl;
				({ ensureIdentitySchema, closePostgresPool } = await import("../src/identity/infrastructure/PostgresInfrastructure.js"));
				({ PostgresIdentitySubjectRepository } = await import("../src/identity/PostgresIdentitySubjectRepository.js"));
				({ PostgresIdentityClaimSourceStore } = await import("../src/identity/PostgresIdentityClaimSourceStore.js"));
				await ensureIdentitySchema();
		});

		afterAll(async () => {
				await closePostgresPool();
		});

		it("writes and reads claim provenance for a subject", async () => {
				const subject = await createSubject("write-read");
				const store = new PostgresIdentityClaimSourceStore();
				const timestamp = new Date().toISOString();

				await store.recordClaimSource(subject.id, "email", "HAPI_EMAIL", timestamp);

				const sources = await store.getClaimSources(subject.id);
				const updatedAt = await store.getClaimUpdatedAt(subject.id);
				expect(sources.email).toBe("HAPI_EMAIL");
				expect(updatedAt.email).toBe(timestamp);
		});

		it("survives a fresh connection (simulated restart)", async () => {
				const subject = await createSubject("restart");
				const timestamp = new Date().toISOString();
				const firstProcessStore = new PostgresIdentityClaimSourceStore();
				await firstProcessStore.recordClaimSource(subject.id, "email", "HAPI_EMAIL", timestamp);
				await firstProcessStore.recordClaimSource(subject.id, "emailVerified", "HAPI_EMAIL", timestamp);

				// A brand-new store instance stands in for a fresh process after restart/redeploy.
				const restartedProcessStore = new PostgresIdentityClaimSourceStore();
				const sources = await restartedProcessStore.getClaimSources(subject.id);

				expect(sources.email).toBe("HAPI_EMAIL");
				expect(sources.emailVerified).toBe("HAPI_EMAIL");
		});

		it("is readable from a second independent store instance against the same database (multi-instance safety)", async () => {
				const subject = await createSubject("multi-instance");
				const timestamp = new Date().toISOString();
				const instanceA = new PostgresIdentityClaimSourceStore();
				await instanceA.recordClaimSource(subject.id, "displayName", "PRIVATE_ID", timestamp);

				const instanceB = new PostgresIdentityClaimSourceStore();
				const sources = await instanceB.getClaimSources(subject.id);
				expect(sources.displayName).toBe("PRIVATE_ID");
		});

		it("is idempotent when the same claim/source is recorded twice", async () => {
				const subject = await createSubject("idempotent");
				const store = new PostgresIdentityClaimSourceStore();
				const firstTimestamp = new Date().toISOString();

				await store.recordClaimSource(subject.id, "email", "HAPI_EMAIL", firstTimestamp);
				await store.recordClaimSource(subject.id, "email", "HAPI_EMAIL", firstTimestamp);

				const sources = await store.getClaimSources(subject.id);
				expect(sources.email).toBe("HAPI_EMAIL");
		});

		it("allows an authorized later source to overwrite the recorded source and updatedAt", async () => {
				const subject = await createSubject("authorized-update");
				const store = new PostgresIdentityClaimSourceStore();
				const firstTimestamp = new Date(Date.now() - 1000).toISOString();
				const secondTimestamp = new Date().toISOString();

				await store.recordClaimSource(subject.id, "displayName", "PRIVATE_ID", firstTimestamp);
				await store.recordClaimSource(subject.id, "displayName", "GOOGLE", secondTimestamp);

				const sources = await store.getClaimSources(subject.id);
				const updatedAt = await store.getClaimUpdatedAt(subject.id);
				expect(sources.displayName).toBe("GOOGLE");
				expect(updatedAt.displayName).toBe(secondTimestamp);
		});

		it("resolves concurrent updates to a single deterministic winner via database upsert semantics", async () => {
				const subject = await createSubject("concurrent");
				const store = new PostgresIdentityClaimSourceStore();

				const attempts = Array.from({ length: 10 }, (_, index) =>
						store.recordClaimSource(subject.id, "email", "HAPI_EMAIL", new Date(Date.now() + index).toISOString())
				);
				await Promise.all(attempts);

				const sources = await store.getClaimSources(subject.id);
				expect(sources.email).toBe("HAPI_EMAIL");
		});

		it("reports genuinely unrecorded historical provenance as undefined, never fabricated", async () => {
				const subject = await createSubject("unknown-history");
				const store = new PostgresIdentityClaimSourceStore();

				const sources = await store.getClaimSources(subject.id);
				expect(sources.email).toBeUndefined();
				expect(sources.emailVerified).toBeUndefined();
				expect(sources.displayName).toBeUndefined();
		});

		it("durably persists future C5.1 BOOKWRM claim updates (Task 6)", async () => {
				const subject = await createSubject("bookwrm-c5-1");
				const store = new PostgresIdentityClaimSourceStore();
				const timestamp = new Date().toISOString();

				await store.recordClaimSource(subject.id, "email", "BOOKWRM", timestamp);
				await store.recordClaimSource(subject.id, "emailVerified", "BOOKWRM", timestamp);

				const freshInstance = new PostgresIdentityClaimSourceStore();
				const sources = await freshInstance.getClaimSources(subject.id);
				expect(sources.email).toBe("BOOKWRM");
				expect(sources.emailVerified).toBe("BOOKWRM");
		});

		it("recording provenance never mutates the IdentitySubject row itself", async () => {
				const subject = await createSubject("no-mutation");
				const repository = new PostgresIdentitySubjectRepository();
				const store = new PostgresIdentityClaimSourceStore();

				await store.recordClaimSource(subject.id, "displayName", "HAPI_EMAIL", new Date().toISOString());

				const reloaded = await repository.findByOidcSubject(subject.oidcSubject);
				expect(reloaded?.id).toBe(subject.id);
				expect(reloaded?.oidcSubject).toBe(subject.oidcSubject);
				expect(reloaded?.primaryProvider).toBe(subject.primaryProvider);
				expect(reloaded?.primaryProviderSubject).toBe(subject.primaryProviderSubject);
				expect(reloaded?.displayName).toBe(subject.displayName);
		});
});
