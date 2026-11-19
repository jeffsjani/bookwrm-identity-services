import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { PostgresHapiSessionRepository } from "../src/identity/sessions/PostgresHapiSessionRepository.js";
import { HapiSessionService, hashSessionToken } from "../src/identity/sessions/HapiSessionService.js";

// HAPI ID V2-C Phase 1/5 integration certification against a real PostgreSQL instance: proves the
// database-enforced session invariants (hash-only persistence, LEAST() absolute ceiling, terminal
// revocation under row locks, cross-subject fail-closed revocation, token-hash uniqueness).
// Skipped automatically when no test database is configured.
const databaseUrl = process.env.HAPI_SESSIONS_TEST_DATABASE_URL ?? process.env.DATABASE_URL;
const schema = "v2c_sessions_" + randomUUID().replaceAll("-", "");

describe.skipIf(!databaseUrl)("V2-C persistent HAPI sessions (PostgreSQL integration)", () => {
		const admin = new pg.Pool({ connectionString: databaseUrl });
		const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}`, max: 10 });
		const subjects = new PostgresIdentitySubjectRepository(pool);
		const repository = new PostgresHapiSessionRepository(pool);

		const identityDdl = readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8");
		const sessionsDdl = readFileSync(new URL("../src/identity/schema-sessions.sql", import.meta.url), "utf8");

		const createSubject = async (): Promise<string> => {
				const id = randomUUID();
				const email = `${id}@example.com`;
				await subjects.create({
						id,
						oidcSubject: randomUUID(),
						primaryProvider: "HAPI_EMAIL",
						primaryProviderSubject: email,
						email,
						emailVerified: true,
						status: "ACTIVE"
				});
				return id;
		};

		const createSession = async (subjectId: string, overrides: Record<string, string> = {}) => {
				const token = `hsid_test_${randomUUID()}`;
				const csrf = `hcsrf_test_${randomUUID()}`;
				const now = new Date();
				const session = await repository.create({
						id: randomUUID(),
						identitySubjectId: subjectId,
						tokenHash: hashSessionToken(token),
						csrfTokenHash: hashSessionToken(csrf),
						clientId: "bookwrm-web",
						authenticationMethod: "HAPI_EMAIL",
						authenticatedAt: now.toISOString(),
						idleExpiresAt: overrides.idleExpiresAt ?? new Date(now.getTime() + 60_000).toISOString(),
						absoluteExpiresAt: overrides.absoluteExpiresAt ?? new Date(now.getTime() + 120_000).toISOString(),
						lastSeenAt: now.toISOString()
				});
				return { session, token, csrf };
		};

		beforeAll(async () => {
				await admin.query(`CREATE SCHEMA ${schema}`);
				// Applied twice to certify idempotency of the additive migration.
				await pool.query(identityDdl);
				await pool.query(sessionsDdl);
				await pool.query(identityDdl);
				await pool.query(sessionsDdl);
		});

		afterAll(async () => {
				await admin.query(`DROP SCHEMA ${schema} CASCADE`);
				await pool.end();
				await admin.end();
		});

		it("creates the sessions table idempotently", async () => {
				const result = await pool.query(
						`SELECT table_name FROM information_schema.tables
						 WHERE table_schema = $1 AND table_name = 'hapi_sessions'`,
						[schema]
				);
				expect(result.rows).toHaveLength(1);
		});

		it("persists only hashes and resolves sessions by exact token hash", async () => {
				const subjectId = await createSubject();
				const { session, token, csrf } = await createSession(subjectId);

				const raw = await pool.query("SELECT * FROM hapi_sessions WHERE id = $1", [session.id]);
				expect(JSON.stringify(raw.rows[0])).not.toContain(token);
				expect(JSON.stringify(raw.rows[0])).not.toContain(csrf);

				const found = await repository.findByTokenHash(hashSessionToken(token));
				expect(found?.id).toBe(session.id);
				expect(await repository.findByTokenHash(hashSessionToken("hsid_other"))).toBeUndefined();
		});

		it("enforces token-hash uniqueness in the database", async () => {
				const subjectId = await createSubject();
				const { session } = await createSession(subjectId);

				await expect(pool.query(
						`INSERT INTO hapi_sessions
								(id, identity_subject_id, token_hash, csrf_token_hash, authentication_method,
								 authenticated_at, status, idle_expires_at, absolute_expires_at, last_seen_at,
								 created_at, updated_at)
						 VALUES ($1, $2, $3, $4, 'HAPI_EMAIL', now(), 'active', now() + interval '1 minute',
								 now() + interval '2 minutes', now(), now(), now())`,
						[randomUUID(), subjectId, session.tokenHash, hashSessionToken("x")]
				)).rejects.toMatchObject({ code: "23505" });
		});

		it("caps the sliding idle window at the absolute ceiling inside the database (LEAST)", async () => {
				const subjectId = await createSubject();
				const { session } = await createSession(subjectId);

				const farBeyondAbsolute = new Date(Date.parse(session.absoluteExpiresAt) + 3_600_000).toISOString();
				const touched = await repository.touch(session.id, new Date().toISOString(), farBeyondAbsolute);
				expect(touched).toBeDefined();
				expect(Date.parse(touched!.idleExpiresAt)).toBe(Date.parse(session.absoluteExpiresAt));
		});

		it("makes revocation terminal: a revoked session can no longer be touched or re-revoked", async () => {
				const subjectId = await createSubject();
				const { session } = await createSession(subjectId);

				const revoked = await repository.revoke(session.id, "logout", new Date().toISOString());
				expect(revoked?.status).toBe("revoked");
				expect(revoked?.revocationReason).toBe("logout");

				expect(await repository.touch(session.id, new Date().toISOString(),
						new Date(Date.now() + 60_000).toISOString())).toBeUndefined();
				expect(await repository.revoke(session.id, "again", new Date().toISOString())).toBeUndefined();
		});

		it("fails closed when a subject tries to revoke another subject's session", async () => {
				const victim = await createSubject();
				const attacker = await createSubject();
				const { session, token } = await createSession(victim);

				const result = await repository.revokeForSubject(
						attacker, session.id, "user_revoked", new Date().toISOString());
				expect(result).toEqual({ status: "rejected", reason: "wrong_subject" });

				const untouched = await repository.findByTokenHash(hashSessionToken(token));
				expect(untouched?.status).toBe("active");
		});

		it("revokes all of one subject's sessions without touching another subject's", async () => {
				const subjectA = await createSubject();
				const subjectB = await createSubject();
				await createSession(subjectA);
				await createSession(subjectA);
				const { session: bSession } = await createSession(subjectB);

				const count = await repository.revokeAllForSubject(subjectA, "global_signout", new Date().toISOString());
				expect(count).toBe(2);
				expect((await repository.findById(bSession.id))?.status).toBe("active");
		});

		it("rejects sessions whose subject row does not exist (foreign key)", async () => {
				await expect(createSession(randomUUID())).rejects.toMatchObject({ code: "23503" });
		});

		it("runs the full service lifecycle against PostgreSQL (establish, resolve, fixation, logout)", async () => {
				const subjectId = await createSubject();
				const service = new HapiSessionService(repository);

				const preAuth = await service.establishSession({
						identitySubjectId: subjectId,
						authenticationMethod: "HAPI_EMAIL"
				});
				const postAuth = await service.establishSession({
						identitySubjectId: subjectId,
						authenticationMethod: "PRIVATEID_FACE",
						supersedesSessionToken: preAuth.sessionToken
				});

				await expect(service.resolveSession(preAuth.sessionToken))
						.rejects.toMatchObject({ code: "session_revoked" });
				const resolved = await service.resolveSession(postAuth.sessionToken);
				expect(resolved.authenticationMethod).toBe("PRIVATEID_FACE");

				const { revoked } = await service.logout(postAuth.sessionToken);
				expect(revoked).toBe(true);
				await expect(service.resolveSession(postAuth.sessionToken))
						.rejects.toMatchObject({ code: "session_revoked" });
		});
});
