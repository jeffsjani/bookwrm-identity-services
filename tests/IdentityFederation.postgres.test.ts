import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { PostgresExternalIdentityRepository } from "../src/identity/PostgresExternalIdentityRepository.js";
import { IdentityFederationService } from "../src/identity/IdentityFederationService.js";
import { IdentityRegistry } from "../src/identity/IdentityRegistry.js";
import { FederatedIdentityResolutionService } from "../src/identity/federation/FederatedIdentityResolutionService.js";
import { withPostgresTransaction } from "../src/identity/infrastructure/PostgresInfrastructure.js";
import { BOOKWRM_APPLICATION_ID, BOOKWRM_TENANT_ID } from "../src/identity/WellKnownIdentities.js";

// HAPI ID V2-B integration certification against a real PostgreSQL instance. Proves the
// database-enforced invariants that the in-memory suite can only simulate: atomic uniqueness
// under concurrency, fail-closed concurrent unlink, and transactional audit integrity.
// Skipped automatically when no test database is configured.
const databaseUrl = process.env.HAPI_FEDERATION_TEST_DATABASE_URL ?? process.env.DATABASE_URL;
const schema = "v2b_" + randomUUID().replaceAll("-", "");

const APPLE_ISSUER = "https://appleid.apple.com";
const GOOGLE_ISSUER = "https://accounts.google.com";

describe.skipIf(!databaseUrl)("V2-B external identity linking (PostgreSQL integration)", () => {
		const admin = new pg.Pool({ connectionString: databaseUrl });
		const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}`, max: 10 });
		const subjects = new PostgresIdentitySubjectRepository(pool);
		const repository = new PostgresExternalIdentityRepository(pool);
		const service = new IdentityFederationService(repository);

		const identityDdl = readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8");
		const federationDdl = readFileSync(new URL("../src/identity/schema-federation.sql", import.meta.url), "utf8");

		const createSubject = async (input?: { primaryProvider?: "HAPI_EMAIL" | "PrivateID"; emailVerified?: boolean }) => {
				const id = randomUUID();
				const email = `${id}@example.com`;
				const primaryProvider = input?.primaryProvider ?? "HAPI_EMAIL";
				await subjects.create({
						id,
						oidcSubject: randomUUID(),
						primaryProvider,
						primaryProviderSubject: primaryProvider === "PrivateID" ? `privateid-${id}` : email,
						...(primaryProvider === "PrivateID" ? {} : { email }),
						emailVerified: input?.emailVerified ?? (primaryProvider !== "PrivateID"),
						status: "ACTIVE"
				});
				return id;
		};

		beforeAll(async () => {
				await admin.query(`CREATE SCHEMA ${schema}`);
				// Applied twice to certify idempotency of the additive migration.
				await pool.query(identityDdl);
				await pool.query(federationDdl);
				await pool.query(identityDdl);
				await pool.query(federationDdl);
				await pool.query(
						"INSERT INTO tenants VALUES ($1, 'Bookwrm', 'bookwrm', 'active', NOW(), NOW())",
						[BOOKWRM_TENANT_ID]
				);
				await pool.query(
						`INSERT INTO applications
							(id, tenant_id, name, slug, status, created_at, updated_at, application_key)
						 VALUES ($1, $2, 'Bookwrm', 'bookwrm', 'active', NOW(), NOW(), 'BOOKWRM')`,
						[BOOKWRM_APPLICATION_ID, BOOKWRM_TENANT_ID]
				);
		});

		afterAll(async () => {
				await admin.query(`DROP SCHEMA ${schema} CASCADE`);
				await pool.end();
				await admin.end();
		});

		it("creates the federation tables idempotently", async () => {
				const result = await pool.query(
						`SELECT table_name FROM information_schema.tables
						 WHERE table_schema = $1 AND table_name IN
								('external_identities', 'identity_authentication_methods', 'identity_link_audit')`,
						[schema]
				);
				expect(result.rows).toHaveLength(3);
		});

		it("links, persists the method, and writes the audit row in the same transaction", async () => {
				const subjectId = await createSubject();

				const result = await service.linkExternalIdentity({
						identitySubjectId: subjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: `apple-${subjectId}`,
						providerClientContext: "com.hapi.web.test", evidenceReference: "synthetic-evidence"
				});

				expect(result.status).toBe("linked");
				const identities = await pool.query(
						"SELECT status FROM external_identities WHERE identity_subject_id = $1", [subjectId]);
				const methods = await pool.query(
						"SELECT method_type, status FROM identity_authentication_methods WHERE identity_subject_id = $1",
						[subjectId]);
				const audit = await pool.query(
						"SELECT action, outcome, provider_subject_ref FROM identity_link_audit WHERE identity_subject_id = $1",
						[subjectId]);
				expect(identities.rows).toEqual([{ status: "linked" }]);
				expect(methods.rows).toEqual([{ method_type: "APPLE", status: "linked" }]);
				expect(audit.rows).toHaveLength(1);
				expect(audit.rows[0]).toMatchObject({ action: "LINK", outcome: "SUCCEEDED" });
				expect(audit.rows[0].provider_subject_ref).not.toContain(`apple-${subjectId}`);
		});

		it("enforces active provider-identity uniqueness at the database level", async () => {
				const subjectId = await createSubject();
				const otherSubjectId = await createSubject();
				const providerSubject = `apple-direct-${randomUUID()}`;

				await pool.query(
						`INSERT INTO external_identities
								(id, identity_subject_id, provider, provider_issuer, provider_subject, status,
								 linked_at, created_at, updated_at)
						 VALUES ($1, $2, 'APPLE', $3, $4, 'linked', now(), now(), now())`,
						[randomUUID(), subjectId, APPLE_ISSUER, providerSubject]
				);

				await expect(pool.query(
						`INSERT INTO external_identities
								(id, identity_subject_id, provider, provider_issuer, provider_subject, status,
								 linked_at, created_at, updated_at)
						 VALUES ($1, $2, 'APPLE', $3, $4, 'linked', now(), now(), now())`,
						[randomUUID(), otherSubjectId, APPLE_ISSUER, providerSubject]
				)).rejects.toMatchObject({ code: "23505" });
		});

		it("fails closed when two subjects race to link the same provider identity", async () => {
				const subjectA = await createSubject();
				const subjectB = await createSubject();
				const providerSubject = `google-race-${randomUUID()}`;

				const [resultA, resultB] = await Promise.all([
						service.linkExternalIdentity({
								identitySubjectId: subjectA, provider: "GOOGLE",
								providerIssuer: GOOGLE_ISSUER, providerSubject
						}),
						service.linkExternalIdentity({
								identitySubjectId: subjectB, provider: "GOOGLE",
								providerIssuer: GOOGLE_ISSUER, providerSubject
						})
				]);

				const statuses = [resultA.status, resultB.status].sort();
				expect(statuses).toEqual(["conflict", "linked"]);

				const active = await pool.query(
						`SELECT identity_subject_id FROM external_identities
						 WHERE provider = 'GOOGLE' AND provider_subject = $1 AND status = 'linked'`,
						[providerSubject]
				);
				expect(active.rows).toHaveLength(1);

				// The loser's rejection is durably audited even though its transaction rolled back.
				const loser = resultA.status === "conflict" ? subjectA : subjectB;
				const audit = await pool.query(
						`SELECT outcome FROM identity_link_audit WHERE identity_subject_id = $1`, [loser]);
				expect(audit.rows.map((row) => row.outcome)).toContain("REJECTED_CONFLICT");
		});

		it("serializes concurrent duplicate links from the same subject into one active identity", async () => {
				const subjectId = await createSubject();
				const providerSubject = `apple-same-${randomUUID()}`;

				const results = await Promise.all([1, 2, 3].map(() => service.linkExternalIdentity({
						identitySubjectId: subjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject
				})));

				expect(results.filter((result) => result.status === "linked")).toHaveLength(1);
				expect(results.every((result) => result.status === "linked" || result.status === "already_linked"))
						.toBe(true);
				const active = await pool.query(
						`SELECT id FROM external_identities WHERE identity_subject_id = $1 AND status = 'linked'`,
						[subjectId]);
				expect(active.rows).toHaveLength(1);
		});

		it("concurrent first-time federated registration resolves to one stable subject and binding", async () => {
				const resolution = new FederatedIdentityResolutionService(service, new IdentityRegistry(subjects), undefined,
						operation => withPostgresTransaction(client => operation({
								atomic: true,
								registry: new IdentityRegistry(new PostgresIdentitySubjectRepository(client)),
								federation: new IdentityFederationService(
										new PostgresExternalIdentityRepository(undefined, client))
						}), pool));
				const verified = {
						provider: "GOOGLE" as const,
						providerIssuer: GOOGLE_ISSUER,
						providerSubject: `google-registration-${randomUUID()}`,
						audience: "synthetic-google-client",
						isPrivateRelayEmail: false,
						expiresAt: Date.now() + 60_000,
						evidenceReference: "synthetic-registration-evidence"
				};

				const results = await Promise.all(Array.from({ length: 10 }, () => resolution.registerFirstTime(verified)));
				expect(results.every(result => result.status === "registered")).toBe(true);
				expect(new Set(results.map(result => result.subject.oidcSubject)).size).toBe(1);

				const subjectsForProvider = await pool.query(
						"SELECT id, oidc_subject FROM identity_subjects WHERE primary_provider='Google' AND primary_provider_subject=$1",
						[verified.providerSubject]);
				expect(subjectsForProvider.rows).toHaveLength(1);
				expect(subjectsForProvider.rows[0].oidc_subject).toBe(results[0].subject.oidcSubject);

				const bindings = await pool.query(
						"SELECT identity_subject_id FROM external_identities WHERE provider='GOOGLE' AND provider_issuer=$1 AND provider_subject=$2 AND status='linked'",
						[GOOGLE_ISSUER, verified.providerSubject]);
				expect(bindings.rows).toEqual([{ identity_subject_id: subjectsForProvider.rows[0].id }]);
		});

		it("returns the same subject and provider binding after a repeated registration submission", async () => {
				const resolution = new FederatedIdentityResolutionService(service, new IdentityRegistry(subjects), undefined,
						operation => withPostgresTransaction(client => operation({
								atomic: true,
								registry: new IdentityRegistry(new PostgresIdentitySubjectRepository(client)),
								federation: new IdentityFederationService(
										new PostgresExternalIdentityRepository(undefined, client))
						}), pool));
				const verified = {
						provider: "APPLE" as const,
						providerIssuer: APPLE_ISSUER,
						providerSubject: `apple-repeat-${randomUUID()}`,
						audience: "synthetic-apple-client",
						isPrivateRelayEmail: false,
						expiresAt: Date.now() + 60_000,
						evidenceReference: "synthetic-registration-evidence"
				};
				const first = await resolution.registerFirstTime(verified);
				const retry = await resolution.registerFirstTime(verified);
				expect(first.status).toBe("registered");
				expect(retry.status).toBe("registered");
				if (first.status !== "registered" || retry.status !== "registered") {
						throw new Error("Repeated registration did not resolve");
				}
				expect(retry.subject.oidcSubject).toBe(first.subject.oidcSubject);
				expect(retry.externalIdentity.id).toBe(first.externalIdentity.id);
		});

		it("rolls back a newly minted subject when the exact provider identity is already linked elsewhere", async () => {
				const ownerId = await createSubject();
				const providerSubject = `google-conflict-${randomUUID()}`;
				await service.linkExternalIdentity({
						identitySubjectId: ownerId,
						provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER,
						providerSubject
				});
				const resolution = new FederatedIdentityResolutionService(service, new IdentityRegistry(subjects), undefined,
						operation => withPostgresTransaction(client => operation({
								atomic: true,
								registry: new IdentityRegistry(new PostgresIdentitySubjectRepository(client)),
								federation: new IdentityFederationService(
										new PostgresExternalIdentityRepository(undefined, client))
						}), pool));
				const result = await resolution.registerFirstTime({
						provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER,
						providerSubject,
						audience: "synthetic-google-client",
						isPrivateRelayEmail: false,
						expiresAt: Date.now() + 60_000,
						evidenceReference: "synthetic-registration-evidence"
				});
				expect(result).toEqual({ status: "conflict" });
				expect((await pool.query(
						"SELECT id FROM identity_subjects WHERE primary_provider='Google' AND primary_provider_subject=$1",
						[providerSubject])).rows).toHaveLength(0);
				expect((await pool.query(
						"SELECT identity_subject_id FROM external_identities WHERE provider='GOOGLE' AND provider_issuer=$1 AND provider_subject=$2 AND status='linked'",
						[GOOGLE_ISSUER, providerSubject])).rows).toEqual([{ identity_subject_id: ownerId }]);
		});

		it("rolls back the subject when the provider binding write itself fails", async () => {
				const providerSubject = `google-failed-binding-${randomUUID()}`;
				const suffix = randomUUID().replaceAll("-", "");
				const functionName = `hapi_fail_federated_binding_${suffix}`;
				const triggerName = `hapi_fail_federated_binding_${suffix}`;
				await pool.query(`CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN
						IF NEW.provider_subject = '${providerSubject}' THEN
							RAISE EXCEPTION 'synthetic provider binding failure';
						END IF;
						RETURN NEW;
					END
				$$`);
				await pool.query(`CREATE TRIGGER ${triggerName} BEFORE INSERT ON external_identities
					FOR EACH ROW EXECUTE FUNCTION ${functionName}()`);
				const resolution = new FederatedIdentityResolutionService(service, new IdentityRegistry(subjects), undefined,
						operation => withPostgresTransaction(client => operation({
								atomic: true,
								registry: new IdentityRegistry(new PostgresIdentitySubjectRepository(client)),
								federation: new IdentityFederationService(
										new PostgresExternalIdentityRepository(undefined, client))
						}), pool));
				try {
						await expect(resolution.registerFirstTime({
								provider: "GOOGLE",
								providerIssuer: GOOGLE_ISSUER,
								providerSubject,
								audience: "synthetic-google-client",
								isPrivateRelayEmail: false,
								expiresAt: Date.now() + 60_000,
								evidenceReference: "synthetic-registration-evidence"
						})).rejects.toThrow("synthetic provider binding failure");
				} finally {
						await pool.query(`DROP TRIGGER IF EXISTS ${triggerName} ON external_identities`);
						await pool.query(`DROP FUNCTION IF EXISTS ${functionName}()`);
				}
				expect((await pool.query(
						"SELECT id FROM identity_subjects WHERE primary_provider='Google' AND primary_provider_subject=$1",
						[providerSubject])).rows).toHaveLength(0);
				expect((await pool.query(
						"SELECT id FROM external_identities WHERE provider='GOOGLE' AND provider_issuer=$1 AND provider_subject=$2",
						[GOOGLE_ISSUER, providerSubject])).rows).toHaveLength(0);
		});

		it("never races two concurrent unlinks down to zero usable methods", async () => {
				// Face-primary subject without a verified email: its only usable methods are the links.
				const subjectId = await createSubject({ primaryProvider: "PrivateID" });
				const appleLink = await service.linkExternalIdentity({
						identitySubjectId: subjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: `apple-unlink-${subjectId}`
				});
				const googleLink = await service.linkExternalIdentity({
						identitySubjectId: subjectId, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: `google-unlink-${subjectId}`
				});
				if (appleLink.status !== "linked" || googleLink.status !== "linked") {
						throw new Error("fixture links failed");
				}

				const [first, second] = await Promise.all([
						service.unlinkExternalIdentity({
								identitySubjectId: subjectId, externalIdentityId: appleLink.externalIdentity.id
						}),
						service.unlinkExternalIdentity({
								identitySubjectId: subjectId, externalIdentityId: googleLink.externalIdentity.id
						})
				]);

				const statuses = [first.status, second.status].sort();
				expect(statuses).toEqual(["rejected", "unlinked"]);
				const remaining = await pool.query(
						`SELECT id FROM identity_authentication_methods
						 WHERE identity_subject_id = $1 AND status <> 'revoked'`,
						[subjectId]
				);
				expect(remaining.rows).toHaveLength(1);
		});

		it("refuses to unlink the last usable method but allows it when the derived email method remains", async () => {
				const faceSubject = await createSubject({ primaryProvider: "PrivateID" });
				const emailSubject = await createSubject();

				for (const subjectId of [faceSubject, emailSubject]) {
						const linked = await service.linkExternalIdentity({
								identitySubjectId: subjectId, provider: "APPLE",
								providerIssuer: APPLE_ISSUER, providerSubject: `apple-last-${subjectId}`
						});
						if (linked.status !== "linked") throw new Error("fixture link failed");

						const unlink = await service.unlinkExternalIdentity({
								identitySubjectId: subjectId, externalIdentityId: linked.externalIdentity.id
						});

						if (subjectId === faceSubject) {
								expect(unlink).toEqual({ status: "rejected", reason: "last_method" });
						} else {
								expect(unlink.status).toBe("unlinked");
						}
				}
		});

		it("rejects cross-subject unlinking and preserves immutable subject identifiers throughout", async () => {
				const owner = await createSubject();
				const attacker = await createSubject();
				const before = await subjects.findById(owner);
				const linked = await service.linkExternalIdentity({
						identitySubjectId: owner, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: `google-owner-${owner}`
				});
				if (linked.status !== "linked") throw new Error("fixture link failed");

				const rejected = await service.unlinkExternalIdentity({
						identitySubjectId: attacker, externalIdentityId: linked.externalIdentity.id
				});
				expect(rejected).toEqual({ status: "rejected", reason: "not_found" });

				const after = await subjects.findById(owner);
				expect(after?.oidcSubject).toBe(before?.oidcSubject);
				expect(after?.primaryProvider).toBe(before?.primaryProvider);
				expect(after?.primaryProviderSubject).toBe(before?.primaryProviderSubject);
		});

		it("keeps a failed link fully rolled back: no identity row, no method row, only the rejection audit", async () => {
				const owner = await createSubject();
				const contender = await createSubject();
				const providerSubject = `apple-rollback-${randomUUID()}`;

				await service.linkExternalIdentity({
						identitySubjectId: owner, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject
				});
				const conflicted = await service.linkExternalIdentity({
						identitySubjectId: contender, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject
				});

				expect(conflicted.status).toBe("conflict");
				const identities = await pool.query(
						`SELECT id FROM external_identities WHERE identity_subject_id = $1`, [contender]);
				const methods = await pool.query(
						`SELECT id FROM identity_authentication_methods WHERE identity_subject_id = $1`, [contender]);
				const audit = await pool.query(
						`SELECT action, outcome FROM identity_link_audit WHERE identity_subject_id = $1`, [contender]);
				expect(identities.rows).toHaveLength(0);
				expect(methods.rows).toHaveLength(0);
				expect(audit.rows).toEqual([{ action: "LINK", outcome: "REJECTED_CONFLICT" }]);
		});
});
