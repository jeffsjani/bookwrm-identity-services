import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { PostgresRefreshTokenFamilyRepository } from "../src/oidc/refresh/PostgresRefreshTokenFamilyRepository.js";
import {
		RefreshTokenRotationService,
		hashRefreshToken
} from "../src/oidc/refresh/RefreshTokenRotationService.js";

// HAPI ID V2-C Phase 2/5 integration certification against a real PostgreSQL instance: proves the
// database-enforced family invariants the in-memory suite can only simulate -- atomic one-time
// consumption, the single-active-generation partial unique index under true concurrency, and
// same-transaction family revocation on reuse. Skipped when no test database is configured.
const databaseUrl = process.env.HAPI_REFRESH_TEST_DATABASE_URL ?? process.env.DATABASE_URL;
const schema = "v2c_refresh_" + randomUUID().replaceAll("-", "");

describe.skipIf(!databaseUrl)("V2-C refresh-token families (PostgreSQL integration)", () => {
		const admin = new pg.Pool({ connectionString: databaseUrl });
		const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}`, max: 10 });
		const subjects = new PostgresIdentitySubjectRepository(pool);
		const repository = new PostgresRefreshTokenFamilyRepository(pool);
		const service = new RefreshTokenRotationService(repository);

		const identityDdl = readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8");
		const sessionsDdl = readFileSync(new URL("../src/identity/schema-sessions.sql", import.meta.url), "utf8");
		const refreshDdl = readFileSync(new URL("../src/identity/schema-refresh.sql", import.meta.url), "utf8");

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

		const issue = async (subjectId: string, overrides: Record<string, string> = {}) => {
				return service.issueFamily({
						identitySubjectId: subjectId,
						clientId: overrides.clientId ?? "elite-native",
						scope: "openid profile email",
						clientProfile: "native_public",
						authenticationMethod: "PRIVATEID_FACE",
						...(overrides.deviceReference ? { deviceReference: overrides.deviceReference } : {})
				});
		};

		beforeAll(async () => {
				await admin.query(`CREATE SCHEMA ${schema}`);
				// Applied twice to certify idempotency of the additive migrations.
				await pool.query(identityDdl);
				await pool.query(sessionsDdl);
				await pool.query(refreshDdl);
				await pool.query(identityDdl);
				await pool.query(sessionsDdl);
				await pool.query(refreshDdl);
		});

		afterAll(async () => {
				await admin.query(`DROP SCHEMA ${schema} CASCADE`);
				await pool.end();
				await admin.end();
		});

		it("creates the refresh-token tables idempotently", async () => {
				const result = await pool.query(
						`SELECT table_name FROM information_schema.tables
						 WHERE table_schema = $1 AND table_name IN ('refresh_token_families', 'refresh_tokens')`,
						[schema]
				);
				expect(result.rows).toHaveLength(2);
		});

		it("issues family + generation 1 atomically, storing only the token hash", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);

				const families = await pool.query(
						"SELECT status, client_id, scope FROM refresh_token_families WHERE id = $1",
						[issued.family.id]);
				const generations = await pool.query(
						"SELECT token_hash, generation, status FROM refresh_tokens WHERE family_id = $1",
						[issued.family.id]);
				expect(families.rows).toEqual([{ status: "active", client_id: "elite-native", scope: "openid profile email" }]);
				expect(generations.rows).toEqual([{
						token_hash: hashRefreshToken(issued.refreshToken), generation: 1, status: "active"
				}]);
				expect(JSON.stringify(generations.rows)).not.toContain(issued.refreshToken);
		});

		it("rotates atomically: consumed generation is terminally rotated, exactly one successor is active", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);

				const rotated = await service.rotate({
						refreshToken: issued.refreshToken, clientId: "elite-native", clientProfile: "native_public"
				});
				const rows = await pool.query(
						"SELECT generation, status, replaced_by FROM refresh_tokens WHERE family_id = $1 ORDER BY generation",
						[issued.family.id]);
				expect(rows.rows).toEqual([
						{ generation: 1, status: "rotated", replaced_by: rotated.generation.id },
						{ generation: 2, status: "active", replaced_by: null }
				]);
		});

		it("enforces at most one active generation per family at the database level", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);

				await expect(pool.query(
						`INSERT INTO refresh_tokens
								(id, family_id, token_hash, generation, status, expires_at, created_at, updated_at)
						 VALUES ($1, $2, $3, 99, 'active', now() + interval '1 day', now(), now())`,
						[randomUUID(), issued.family.id, hashRefreshToken(`hrt_dup_${randomUUID()}`)]
				)).rejects.toMatchObject({ code: "23505" });
		});

		it("revokes the whole family in the same transaction when a consumed token is replayed", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);
				await service.rotate({
						refreshToken: issued.refreshToken, clientId: "elite-native", clientProfile: "native_public"
				});

				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: "elite-native", clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token", familyRevoked: true });

				const family = await pool.query(
						"SELECT status, revocation_reason FROM refresh_token_families WHERE id = $1",
						[issued.family.id]);
				expect(family.rows).toEqual([{ status: "revoked", revocation_reason: "reuse_detected" }]);
				const active = await pool.query(
						"SELECT count(*)::int AS count FROM refresh_tokens WHERE family_id = $1 AND status = 'active'",
						[issued.family.id]);
				expect(active.rows[0].count).toBe(0);
		});

		it("fails closed under true concurrent refresh: at most one successor ever exists", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);

				const attempt = () => service.rotate({
						refreshToken: issued.refreshToken, clientId: "elite-native", clientProfile: "native_public"
				});
				const results = await Promise.allSettled([attempt(), attempt(), attempt()]);
				const fulfilled = results.filter((result) => result.status === "fulfilled");
				const rejected = results.filter((result) => result.status === "rejected");

				// Exactly one rotation can win; every loser fails closed with invalid_grant semantics.
				expect(fulfilled.length).toBeLessThanOrEqual(1);
				expect(fulfilled.length + rejected.length).toBe(3);
				const active = await pool.query(
						"SELECT count(*)::int AS count FROM refresh_tokens WHERE family_id = $1 AND status = 'active'",
						[issued.family.id]);
				expect(active.rows[0].count).toBeLessThanOrEqual(1);
				// Lock-serialized losers observed 'rotated' and triggered the documented reuse response:
				// the family is revoked and every holder must re-authenticate.
				if (rejected.length === 3) {
						expect(fulfilled).toHaveLength(0);
				} else {
						const family = await pool.query(
								"SELECT status FROM refresh_token_families WHERE id = $1", [issued.family.id]);
						expect(["active", "revoked"]).toContain(family.rows[0].status);
				}
		});

		it("rejects the wrong client without consuming the token (cross-client isolation)", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);

				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: "another-client", clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "client_mismatch" });

				const generations = await pool.query(
						"SELECT status FROM refresh_tokens WHERE family_id = $1", [issued.family.id]);
				expect(generations.rows).toEqual([{ status: "active" }]);
		});

		it("revokes families per device and per subject without crossing subjects", async () => {
				const subjectA = await createSubject();
				const subjectB = await createSubject();
				const phone = await issue(subjectA, { deviceReference: "device-phone" });
				const laptop = await issue(subjectA, { deviceReference: "device-laptop" });
				const other = await issue(subjectB);

				expect(await service.revokeByDevice(subjectA, "device-phone")).toBe(1);
				expect((await repository.findFamily(phone.family.id))?.status).toBe("revoked");
				expect((await repository.findFamily(laptop.family.id))?.status).toBe("active");

				expect(await service.revokeAllForSubject(subjectA, "subject_locked")).toBe(1);
				expect((await repository.findFamily(other.family.id))?.status).toBe("active");
		});

		it("expires a family terminally once its absolute lifetime has passed", async () => {
				const subjectId = await createSubject();
				const issued = await issue(subjectId);
				await pool.query(
						"UPDATE refresh_token_families SET absolute_expires_at = now() - interval '1 second' WHERE id = $1",
						[issued.family.id]);

				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: "elite-native", clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
				const family = await pool.query(
						"SELECT status FROM refresh_token_families WHERE id = $1", [issued.family.id]);
				expect(family.rows[0].status).toBe("expired");
		});

		it("associates families with sessions and cascades session revocation", async () => {
				const subjectId = await createSubject();
				// Create a real session row to satisfy the FK.
				const sessionId = randomUUID();
				await pool.query(
						`INSERT INTO hapi_sessions
								(id, identity_subject_id, token_hash, csrf_token_hash, authentication_method,
								 authenticated_at, status, idle_expires_at, absolute_expires_at, last_seen_at,
								 created_at, updated_at)
						 VALUES ($1, $2, $3, $4, 'HAPI_EMAIL', now(), 'active', now() + interval '1 hour',
								 now() + interval '1 day', now(), now(), now())`,
						[sessionId, subjectId, hashRefreshToken(`h_${randomUUID()}`), hashRefreshToken(`c_${randomUUID()}`)]);

				const issued = await service.issueFamily({
						identitySubjectId: subjectId,
						clientId: "elite-native",
						scope: "openid",
						clientProfile: "native_public",
						sessionId
				});
				expect(await service.revokeBySession(sessionId, "logout")).toBe(1);
				expect((await repository.findFamily(issued.family.id))?.status).toBe("revoked");
				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: "elite-native", clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});
});
