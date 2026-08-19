import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Integration test against a real PostgreSQL instance. Requires DATABASE_URL to be set;
// skipped automatically otherwise (Task 6 concurrency + restart validation).
const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("PostgresIdentitySubjectRepository (integration)", () => {
		let ensureIdentitySchema: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").ensureIdentitySchema;
		let closePostgresPool: typeof import("../src/identity/infrastructure/PostgresInfrastructure.js").closePostgresPool;
		let PostgresIdentitySubjectRepository: typeof import("../src/identity/PostgresIdentitySubjectRepository.js").PostgresIdentitySubjectRepository;

		beforeAll(async () => {
				process.env.DATABASE_URL = databaseUrl;
				({ ensureIdentitySchema, closePostgresPool } = await import("../src/identity/infrastructure/PostgresInfrastructure.js"));
				({ PostgresIdentitySubjectRepository } = await import("../src/identity/PostgresIdentitySubjectRepository.js"));
				await ensureIdentitySchema();
		});

		afterAll(async () => {
				await closePostgresPool();
		});

		it("persists a new identity and reuses it on a returning login", async () => {
				const repository = new PostgresIdentitySubjectRepository();
				const providerSubject = `privateid-${randomUUID()}`;

				const created = await repository.resolveOrCreate({
						id: randomUUID(),
						oidcSubject: randomUUID(),
						primaryProvider: "PrivateID",
						primaryProviderSubject: providerSubject,
						email: "integration@example.com",
						emailVerified: true,
						displayName: "Integration User",
						status: "ACTIVE"
				});

				const returning = await repository.resolveOrCreate({
						id: randomUUID(),
						oidcSubject: randomUUID(),
						primaryProvider: "PrivateID",
						primaryProviderSubject: providerSubject,
						email: "integration@example.com",
						emailVerified: true,
						displayName: "Integration User",
						status: "ACTIVE"
				});

				expect(returning.oidcSubject).toBe(created.oidcSubject);
		});

		it("guarantees exactly one row for two concurrent logins on the same provider identity", async () => {
				const repository = new PostgresIdentitySubjectRepository();
				const providerSubject = `privateid-race-${randomUUID()}`;

				const attempts = Array.from({ length: 10 }, () =>
						repository.resolveOrCreate({
								id: randomUUID(),
								oidcSubject: randomUUID(),
								primaryProvider: "PrivateID",
								primaryProviderSubject: providerSubject,
								email: "race@example.com",
								emailVerified: true,
								displayName: "Race User",
								status: "ACTIVE"
						})
				);

				const results = await Promise.all(attempts);
				const distinctSubjects = new Set(results.map((subject) => subject.oidcSubject));
				expect(distinctSubjects.size).toBe(1);
		});

		it("survives a fresh connection (simulated restart)", async () => {
				const firstProcessRepository = new PostgresIdentitySubjectRepository();
				const providerSubject = `privateid-restart-${randomUUID()}`;

				const created = await firstProcessRepository.resolveOrCreate({
						id: randomUUID(),
						oidcSubject: randomUUID(),
						primaryProvider: "PrivateID",
						primaryProviderSubject: providerSubject,
						email: "restart@example.com",
						emailVerified: true,
						displayName: "Restart User",
						status: "ACTIVE"
				});

				// A brand-new repository/pool instance stands in for a fresh process after restart.
				const restartedProcessRepository = new PostgresIdentitySubjectRepository();
				const resolved = await restartedProcessRepository.findByOidcSubject(created.oidcSubject);

				expect(resolved?.oidcSubject).toBe(created.oidcSubject);
				expect(resolved?.primaryProviderSubject).toBe(providerSubject);
		});
});
