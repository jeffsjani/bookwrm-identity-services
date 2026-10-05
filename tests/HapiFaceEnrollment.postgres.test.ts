import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { Writable } from "node:stream";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import pg from "pg";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PostgresFaceEnrollmentRepository } from "../src/authenticators/PostgresFaceEnrollmentRepository.js";
import { HapiFaceEnrollmentService } from "../src/authenticators/HapiFaceEnrollmentService.js";
import type { FaceEnrollmentAuthority } from "../src/authenticators/FaceEnrollmentTypes.js";
import { configureFaceEnrollment } from "../src/authenticators/FaceEnrollmentComposition.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { UserAuthenticatorRepository } from "../src/identity/UserAuthenticatorRepository.js";
import { AuthenticatorLoginResolver, authenticatorLoginResolver } from "../src/identity/AuthenticatorLoginResolver.js";
import { AuthenticatorLoginTransactionRepository } from "../src/identity/AuthenticatorLoginTransactionRepository.js";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { PostgresRegistrationRepository } from "../src/registration/PostgresRegistrationRepository.js";
import { PostgresEmailAuthenticationRepository } from "../src/authentication/email/PostgresEmailAuthenticationRepository.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import { PostgresOIDCClientRepository } from "../src/identity/PostgresOIDCClientRepository.js";
import { PostgresApplicationRepository } from "../src/identity/PostgresApplicationRepository.js";
import { PostgresTenantRepository } from "../src/identity/PostgresTenantRepository.js";
import { authorizeH1Client } from "../src/identity/H1ClientAuthority.js";
import { RedisOIDCStore } from "../src/oidc/infrastructure/RedisOIDCStore.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { registerHapiFaceEnrollmentRoutes } from "../src/routes/hapiFaceEnrollment.js";
import { registerPrivateIdRoutes } from "../src/routes/privateid.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { identityService } from "../src/identity/IdentityService.js";
import { privateIdWebhookDiagnosticsRepository } from "../src/identity/infrastructure/PrivateIdWebhookDiagnosticsRepository.js";
import * as infrastructure from "../src/identity/infrastructure/PostgresInfrastructure.js";
import { getCurrentPrivateIDSessionRecord, findPrivateIDSession, markHapiFaceEnrollmentSession, storePrivateIDSession } from "../src/privateid/PrivateIDSessionStore.js";
import { ensureOidcTestEnvironment } from "./oidcTestHarness.js";

const databaseUrl = process.env.HAPI_FACE_ENROLLMENT_TEST_DATABASE_URL;
const schema = "h5_" + randomUUID().replaceAll("-", "");

describe.skipIf(!databaseUrl)("H5 isolated PostgreSQL attachment, concurrency and email/Face/OIDC continuity", () => {
	const admin = new pg.Pool({ connectionString: databaseUrl });
	const pool = new pg.Pool({ connectionString: databaseUrl, max: 16, options: `-c search_path=${schema}` });
	const subjects = new PostgresIdentitySubjectRepository(pool);
	const authenticators = new UserAuthenticatorRepository(pool);
	const repository = new PostgresFaceEnrollmentRepository(pool);
	const login = new AuthenticatorLoginResolver(authenticators, subjects, new AuthenticatorLoginTransactionRepository(pool));
	const provider = new InMemoryEmailDeliveryProvider();
	const challenges = new PostgresVerificationChallengeRepository(pool);
	const h2 = new EmailVerificationService(challenges, provider, new VerificationSecrets("h5-fixture-secret".repeat(4)), defaultVerificationPolicy);
	const registration = new PostgresRegistrationRepository(pool);
	const authenticationRepository = new PostgresEmailAuthenticationRepository(pool);
	const h4 = new EmailAuthenticationService(h2, challenges, authenticationRepository);
	const tenantId = randomUUID(), applicationId = randomUUID(), otherApplication = randomUUID(), otherTenant = randomUUID();
	const context = { tenantId, applicationId };
	const clientId = "h5-fixture-" + randomUUID(), otherClientId = "h5-other-" + randomUUID();
	const h1 = { clients: new PostgresOIDCClientRepository(pool), applications: new PostgresApplicationRepository(pool),
		tenants: new PostgresTenantRepository(pool) };
	const headers = { authorization: "Basic " + Buffer.from(clientId + ":fixture-secret").toString("base64") };
	const createSession = vi.fn(async (transactionId: string) => ({
		sessionId: randomUUID(), transactionId, launchUrl: "https://privateid.example.test/enroll",
		expires: Date.now() + 300_000, created: Date.now(), status: "created" as const
	}));
	const service = new HapiFaceEnrollmentService(repository, createSession);

	async function seed() {
		const email = `${randomUUID()}@example.test`;
		const challenge = await h2.start(context, email, "REGISTRATION");
		const code = provider.messages.findLast(message => message.destination === email)!.code;
		await h2.verify(context, challenge.challengeId, code, "REGISTRATION");
		const registered = await registration.complete({ context, verificationId: challenge.challengeId });
		return (await subjects.findByOidcSubject(registered.subject))!;
	}
	function authority(sub: string, overrides: Partial<FaceEnrollmentAuthority> = {}): FaceEnrollmentAuthority {
		return { sub, clientId, scope: "openid email", expiresAt: Date.now() + 600_000,
			authenticatedAt: new Date().toISOString(), authenticationMethod: "HAPI_EMAIL", ...overrides };
	}
	async function pending(sub: string) {
		const started = await service.start(authority(sub));
		expect(started.enrolled).toBe(false);
		const transactionId = started.enrollmentId!;
		const session = (await pool.query<{ session_id: string }>(`SELECT b.session_id FROM hapi_face_enrollment_bindings b
			JOIN privateid_enrollment_transactions e ON e.id=b.enrollment_id WHERE e.provider_transaction_id=$1`, [transactionId])).rows[0];
		return { transactionId, sessionId: session.session_id };
	}
	async function complete(flow: { transactionId: string; sessionId: string }, puid = randomUUID()) {
		return service.webhook(flow.transactionId, flow.sessionId, "SUCCESS", puid);
	}
	async function statusApp(sub: string, captureLogs = false, overrides: Partial<FaceEnrollmentAuthority> = {}) {
		const logs: string[] = [];
		const stream = new Writable({ write(chunk, _encoding, next) { logs.push(chunk.toString()); next(); } });
		const app = Fastify(captureLogs ? { logger: { stream } } : {});
		const tokens = new RedisOIDCStore();
		const token = randomUUID();
		const { expiresAt, ...record } = authority(sub, overrides);
		await tokens.storeAccessToken(token, { ...record, nonce: randomUUID() }, expiresAt - Date.now());
		await registerHapiFaceEnrollmentRoutes(app, service, tokens);
		await registerPrivateIdRoutes(app, service);
		return { app, logs, tokens, token, headers: { authorization: `Bearer ${token}` } };
	}
	async function snapshot(subjectId: string) {
		return {
			identity: (await pool.query("SELECT * FROM identity_subjects WHERE id=$1", [subjectId])).rows,
			provenance: (await pool.query("SELECT * FROM identity_claim_provenance WHERE identity_subject_id=$1 ORDER BY claim_name", [subjectId])).rows,
			evidence: (await pool.query("SELECT * FROM registration_evidence WHERE identity_subject_id=$1", [subjectId])).rows,
			identities: (await pool.query("SELECT count(*)::int AS n FROM identity_subjects")).rows[0].n,
			links: (await pool.query("SELECT count(*)::int AS n FROM identity_account_links")).rows[0].n
		};
	}
	beforeAll(async () => {
		ensureOidcTestEnvironment();
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		await challenges.ensureSchema();
		await registration.ensureSchema();
		await authenticationRepository.ensureSchema();
		await repository.ensureSchema();
		for (const id of [tenantId, otherTenant]) await pool.query("INSERT INTO tenants VALUES ($1,'H5',$2,'active',NOW(),NOW())", [id, id]);
		for (const [id, tenant] of [[applicationId, tenantId], [otherApplication, otherTenant]]) {
			await pool.query("INSERT INTO applications VALUES ($1,$2,'H5',$3,'active',NOW(),NOW())", [id, tenant, id]);
		}
		for (const [id, application] of [[clientId, applicationId], [otherClientId, otherApplication]]) {
			await h1.clients.upsert({ id: randomUUID(), applicationId: application, clientId: id,
				clientSecret: "fixture-secret", redirectUris: ["https://rp.example/callback"], scopes: ["openid", "email"],
				grantTypes: ["authorization_code"], responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
		}
	});
	afterAll(async () => {
		await pool.end();
		await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
		await admin.end();
	});

	it("attaches to the H3 canonical subject without altering any identity, claims, provenance, evidence or links", async () => {
		const subject = await seed(), before = await snapshot(subject.id);
		const flow = await pending(subject.oidcSubject), puid = randomUUID();
		expect(await complete(flow, puid)).toMatchObject({ statusCode: 200, body: { enrolled: true, alreadyEnrolled: false } });
		expect(await authenticators.findByProviderSubject("privateid", puid)).toMatchObject({
			userId: subject.id, status: "active", authenticatorType: "face", verifiedAt: expect.any(String)
		});
		expect(await snapshot(subject.id)).toEqual(before);
		expect(before.identity[0]).toMatchObject({ primary_provider: "HAPI_EMAIL", oidc_subject: subject.oidcSubject,
			email: subject.email, email_verified: true });
		expect(before.links).toBe(0);
		expect(before.provenance.map(row => [row.claim_name, row.source])).toEqual([["email", "HAPI_EMAIL"], ["emailVerified", "HAPI_EMAIL"]]);
		const audits = (await pool.query("SELECT * FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 ORDER BY occurred_at", [subject.id])).rows;
		expect(audits.map(row => row.type)).toEqual(["AUTHENTICATOR_ENROLLMENT_STARTED", "AUTHENTICATOR_ENROLLED"]);
		for (const audit of audits) expect(audit).toMatchObject({ tenant_id: tenantId, application_id: applicationId, client_id: clientId,
			identity_subject_id: subject.id, provider: "privateid", occurred_at: expect.any(Date) });
		expect(JSON.stringify(audits)).not.toContain(puid);
	});
	it("makes repeated completion and repeated enrollment idempotent without another provider ceremony", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), puid = randomUUID();
		await complete(flow, puid);
		expect(await complete(flow, puid)).toMatchObject({ statusCode: 200, body: { enrolled: true, alreadyEnrolled: true } });
		createSession.mockClear();
		expect(await service.start(authority(subject.oidcSubject))).toEqual({ enrolled: true, alreadyEnrolled: true });
		expect(createSession).not.toHaveBeenCalled();
		expect(await authenticators.findByUser(subject.id)).toHaveLength(1);
	});
	it("rejects a PUID belonging to another subject without moving or changing either identity", async () => {
		const first = await seed(), second = await seed(), puid = randomUUID();
		await complete(await pending(first.oidcSubject), puid);
		const before = await authenticators.findByProviderSubject("privateid", puid);
		const secondSnapshot = await snapshot(second.id);
		const secondFlow = await pending(second.oidcSubject);
		expect(await complete(secondFlow, puid)).toMatchObject({ statusCode: 409, body: { error: "ENROLLMENT_CONFLICT" } });
		expect(await authenticators.findByProviderSubject("privateid", puid)).toEqual(before);
		expect(await authenticators.findByUser(second.id)).toHaveLength(0);
		expect(await snapshot(second.id)).toEqual(secondSnapshot);
		expect((await pool.query("SELECT type FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 ORDER BY occurred_at DESC LIMIT 1",
			[second.id])).rows[0].type).toBe("AUTHENTICATOR_ENROLLMENT_CONFLICT");
		expect((await pool.query("SELECT outcome FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 ORDER BY occurred_at DESC LIMIT 1",
			[second.id])).rows[0].outcome).toBe("AUTHENTICATOR_OWNED_BY_OTHER_SUBJECT");
	});
	it("serializes concurrent completion of the same ceremony to exactly one authenticator", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), puid = randomUUID();
		const results = await Promise.all(Array.from({ length: 6 }, () => complete(flow, puid)));
		expect(results.every(result => result?.statusCode === 200)).toBe(true);
		expect(results.filter(result => result?.body.alreadyEnrolled === false)).toHaveLength(1);
		expect(await authenticators.findByUser(subject.id)).toHaveLength(1);
		expect((await pool.query("SELECT count(*)::int AS n FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 AND type='AUTHENTICATOR_ENROLLED'", [subject.id])).rows[0].n).toBe(1);
	});
	it("rejects a PUID already owned by a legacy PrivateID identity even without an authenticator row", async () => {
		const subject = await seed(), puid = randomUUID();
		const legacy = await subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: "PrivateID", primaryProviderSubject: puid, status: "ACTIVE" });
		const flow = await pending(subject.oidcSubject);
		expect(await complete(flow, puid)).toMatchObject({ statusCode: 409 });
		expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		expect(await subjects.findById(legacy.id)).toEqual(legacy);
		expect((await pool.query("SELECT outcome FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 ORDER BY occurred_at DESC LIMIT 1",
			[subject.id])).rows[0].outcome).toBe("LEGACY_PROVIDER_SUBJECT_EXISTS");
	});
	it("rejects another active Face attached during a pending ceremony", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		const existing = await authenticators.create({ id: randomUUID(), userId: subject.id, provider: "privateid",
			providerSubject: randomUUID(), authenticatorType: "face", status: "active" });
		expect(await complete(flow)).toMatchObject({ statusCode: 409 });
		expect(await authenticators.findByUser(subject.id)).toEqual([existing]);
		expect((await pool.query("SELECT outcome FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 ORDER BY occurred_at DESC LIMIT 1",
			[subject.id])).rows[0].outcome).toBe("TARGET_HAS_DIFFERENT_ACTIVE_AUTHENTICATOR");
	});
	it("reuses the same active PUID attached to the same subject during a pending ceremony", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), puid = randomUUID();
		const existing = await authenticators.create({ id: randomUUID(), userId: subject.id, provider: "privateid",
			providerSubject: puid, authenticatorType: "face", status: "active" });
		expect(await complete(flow, puid)).toMatchObject({ statusCode: 200, body: { enrolled: true, alreadyEnrolled: true } });
		expect(await authenticators.findByUser(subject.id)).toEqual([existing]);
	});
	it("serializes cross-subject concurrent PUID claims with one winner and one conflict", async () => {
		const first = await seed(), second = await seed();
		const flows = await Promise.all([pending(first.oidcSubject), pending(second.oidcSubject)]);
		const puid = randomUUID();
		const results = await Promise.all(flows.map(flow => complete(flow, puid)));
		expect(results.map(result => result?.statusCode).sort()).toEqual([200, 409]);
		expect((await authenticators.findByUser(first.id)).length + (await authenticators.findByUser(second.id)).length).toBe(1);
	});
	it("reserves only one pending enrollment during concurrent starts, without multiple provider calls", async () => {
		const subject = await seed();
		createSession.mockClear();
		const results = await Promise.allSettled(Array.from({ length: 4 }, () => service.start(authority(subject.oidcSubject))));
		expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
		expect(results.filter(result => result.status === "rejected")).toHaveLength(3);
		expect(createSession).toHaveBeenCalledOnce();
	});
	it("rejects a changed PUID after completion and never creates another authenticator", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		await complete(flow);
		expect(await complete(flow)).toMatchObject({ statusCode: 409 });
		expect(await authenticators.findByUser(subject.id)).toHaveLength(1);
	});
	it("refuses revoked PUIDs even for the same subject rather than silently reactivating them", async () => {
		const subject = await seed(), puid = randomUUID();
		await complete(await pending(subject.oidcSubject), puid);
		const authenticator = (await authenticators.findByProviderSubject("privateid", puid))!;
		await authenticators.revoke(authenticator.id);
		expect(await complete(await pending(subject.oidcSubject), puid)).toMatchObject({ statusCode: 409 });
		expect((await authenticators.findByProviderSubject("privateid", puid))?.status).toBe("revoked");
		expect((await pool.query("SELECT outcome FROM authenticator_enrollment_audit WHERE identity_subject_id=$1 ORDER BY occurred_at DESC LIMIT 1",
			[subject.id])).rows[0].outcome).toBe("AUTHENTICATOR_NOT_ACTIVE");
	});
	it("rejects unknown, non-HAPI, unverified and inactive subjects before provider invocation", async () => {
		const subject = await seed();
		createSession.mockClear();
		await expect(service.start(authority(randomUUID()))).rejects.toMatchObject({ statusCode: 403 });
		for (const mutation of ["status='DISABLED'", "email_verified=false", "primary_provider='PrivateID'", "email='different@example.test'"]) {
			await pool.query(`UPDATE identity_subjects SET ${mutation} WHERE id=$1`, [subject.id]);
			await expect(service.start(authority(subject.oidcSubject))).rejects.toMatchObject({ statusCode: 403 });
			await pool.query("UPDATE identity_subjects SET status='ACTIVE',email_verified=true,primary_provider='HAPI_EMAIL',email=primary_provider_subject WHERE id=$1", [subject.id]);
		}
		expect(createSession).not.toHaveBeenCalled();
	});
	it("rejects wrong application/tenant, deleted client and suspended authorities", async () => {
		const subject = await seed();
		createSession.mockClear();
		for (const id of [otherClientId, "unknown-client"]) await expect(service.start(authority(subject.oidcSubject, { clientId: id }))).rejects.toMatchObject({ statusCode: 403 });
		for (const [table, id] of [["applications", applicationId], ["tenants", tenantId]] as const) {
			await pool.query(`UPDATE ${table} SET status='suspended' WHERE id=$1`, [id]);
			await expect(service.start(authority(subject.oidcSubject))).rejects.toMatchObject({ statusCode: 403 });
			await pool.query(`UPDATE ${table} SET status='active' WHERE id=$1`, [id]);
		}
		expect(createSession).not.toHaveBeenCalled();
	});
	it("revalidates identity and tenant/application binding at completion", async () => {
		for (const mutation of ["status='DISABLED'", "email_verified=false", "application_id='" + otherApplication + "'"]) {
			const subject = await seed(), flow = await pending(subject.oidcSubject);
			await pool.query(`UPDATE identity_subjects SET ${mutation} WHERE id=$1`, [subject.id]);
			expect(await complete(flow)).toMatchObject({ statusCode: 409 });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		}
	});
	it("rejects suspended tenant or application authority at completion without a Face attachment", async () => {
		for (const [table, id] of [["tenants", tenantId], ["applications", applicationId]] as const) {
			const subject = await seed(), flow = await pending(subject.oidcSubject);
			await pool.query(`UPDATE ${table} SET status='suspended' WHERE id=$1`, [id]);
			try {
				expect(await complete(flow)).toMatchObject({ statusCode: 409 });
				expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
			} finally { await pool.query(`UPDATE ${table} SET status='active' WHERE id=$1`, [id]); }
		}
	});
	it("rejects expired ceremonies and allows a fresh start after expiration", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		await pool.query("UPDATE privateid_enrollment_transactions SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE provider_transaction_id=$1", [flow.transactionId]);
		expect(await complete(flow)).toMatchObject({ statusCode: 409 });
		expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		expect((await service.start(authority(subject.oidcSubject))).enrolled).toBe(false);
	});
	it("rechecks freshness after waiting for the identity lock", async () => {
		const subject = await seed(), blocker = await pool.connect();
		try {
			await blocker.query("BEGIN");
			await blocker.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [subject.id]);
			const waiting = service.start(authority(subject.oidcSubject, { authenticatedAt: new Date(Date.now() - 299_850).toISOString() }));
			const settled = waiting.catch(error => error);
			await new Promise(resolve => setTimeout(resolve, 250));
			await blocker.query("COMMIT");
			expect(await settled).toMatchObject({ statusCode: 401 });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		} finally { await blocker.query("ROLLBACK"); blocker.release(); }
	});
	it("rechecks expiry after waiting for the subject lock before completion", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), blocker = await pool.connect();
		try {
			await pool.query("UPDATE privateid_enrollment_transactions SET expires_at=clock_timestamp()+INTERVAL '150 milliseconds' WHERE provider_transaction_id=$1", [flow.transactionId]);
			await blocker.query("BEGIN");
			await blocker.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [subject.id]);
			const waiting = complete(flow);
			await new Promise(resolve => setTimeout(resolve, 250));
			await blocker.query("COMMIT");
			expect(await waiting).toMatchObject({ statusCode: 409 });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		} finally { await blocker.query("ROLLBACK"); blocker.release(); }
	});
	it("rechecks expiry after waiting for the cross-subject PUID lock", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), blocker = await pool.connect(), puid = randomUUID();
		try {
			await blocker.query("BEGIN");
			await blocker.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", ["hapi-face:" + puid]);
			await pool.query("UPDATE privateid_enrollment_transactions SET expires_at=clock_timestamp()+INTERVAL '150 milliseconds' WHERE provider_transaction_id=$1", [flow.transactionId]);
			const waiting = complete(flow, puid);
			await new Promise(resolve => setTimeout(resolve, 250));
			await blocker.query("COMMIT");
			expect(await waiting).toMatchObject({ statusCode: 409 });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		} finally { await blocker.query("ROLLBACK"); blocker.release(); }
	});
	it("rechecks expiry after waiting for a legacy unique-key writer and never deletes its authenticator", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), blocker = await pool.connect(), puid = randomUUID();
		const legacyAuthenticatorId = randomUUID();
		try {
			await blocker.query("BEGIN");
			await new UserAuthenticatorRepository(blocker).create({ id: legacyAuthenticatorId, userId: subject.id,
				provider: "privateid", providerSubject: puid, authenticatorType: "face", status: "active" });
			await pool.query("UPDATE privateid_enrollment_transactions SET expires_at=clock_timestamp()+INTERVAL '150 milliseconds' WHERE provider_transaction_id=$1", [flow.transactionId]);
			const waiting = complete(flow, puid);
			await new Promise(resolve => setTimeout(resolve, 250));
			await blocker.query("COMMIT");
			expect(await waiting).toMatchObject({ statusCode: 409 });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(1);
			expect((await authenticators.findByUser(subject.id))[0].id).toBe(legacyAuthenticatorId);
			const binding = (await pool.query(`SELECT b.authenticator_id,e.status FROM hapi_face_enrollment_bindings b
				JOIN privateid_enrollment_transactions e ON e.id=b.enrollment_id WHERE e.provider_transaction_id=$1`, [flow.transactionId])).rows[0];
			expect(binding).toMatchObject({ authenticator_id: null, status: "expired" });
		} finally { await blocker.query("ROLLBACK"); blocker.release(); }
	});
	it("does not attach for in-progress, failed, or expired provider events", async () => {
		for (const status of ["PENDING", "REQUIRES_INPUT", "FAILURE", "EXPIRED"]) {
			const subject = await seed(), flow = await pending(subject.oidcSubject);
			expect(await service.webhook(flow.transactionId, flow.sessionId, status, undefined)).toMatchObject({ statusCode: 200, body: { enrolled: false } });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		}
	});
	it("requires exact provider transaction and, when supplied, session correlation; PUID never comes from callback", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		expect(await service.webhook(undefined, flow.sessionId, "SUCCESS", randomUUID())).toMatchObject({ statusCode: 400 });
		expect(await service.webhook(randomUUID(), flow.sessionId, "SUCCESS", randomUUID())).toMatchObject({ statusCode: 400 });
		expect(await service.webhook(flow.transactionId, randomUUID(), "SUCCESS", randomUUID())).toMatchObject({ statusCode: 400 });
		expect(await service.webhook(flow.transactionId, flow.sessionId, "SUCCESS", undefined)).toMatchObject({ statusCode: 400 });
		expect(await service.callback(flow.transactionId, flow.sessionId)).toMatchObject({ body: { enrolled: false, status: "pending" } });
		expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
	});
	it("persists completion across process replacement without the process-local session map", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), puid = randomUUID();
		const fresh = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}` });
		try {
			const restartedRepository = new PostgresFaceEnrollmentRepository(fresh);
			expect(await restartedRepository.webhook(flow.transactionId, undefined, "SUCCESS", puid, true)).toMatchObject({ statusCode: 200 });
			expect(await restartedRepository.callback(flow.transactionId, undefined)).toMatchObject({ body: { enrolled: true } });
			expect((await login.resolveLogin("privateid", randomUUID(), puid)).oidcSubject).toBe(subject.oidcSubject);
		} finally { await fresh.end(); }
	});
	it("fails closed when disabled and preserves legacy transactions rather than consuming them", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		expect(await repository.webhook(flow.transactionId, flow.sessionId, "SUCCESS", randomUUID(), false)).toMatchObject({ statusCode: 503 });
		expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		const legacyTransaction = randomUUID();
		await pool.query("INSERT INTO privateid_enrollment_transactions VALUES ($1,$2,'face_enrollment',$3,'pending',NOW(),NOW()+INTERVAL '5 minutes',NULL)",
			[randomUUID(), "legacy-user", legacyTransaction]);
		expect(await repository.webhook(legacyTransaction, undefined, "SUCCESS", randomUUID(), true)).toBeUndefined();
	});
	it("does not fall back to the current session for unknown or missing H5 correlation", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		storePrivateIDSession({ sessionId: flow.sessionId, transactionId: flow.transactionId, launchUrl: "https://privateid.example.test/enroll",
			status: "created", created: Date.now(), expires: Date.now() + 300_000 });
		markHapiFaceEnrollmentSession(flow.sessionId);
		const base44 = vi.spyOn(identityService, "resolveIdentity").mockRejectedValue(new Error("Forbidden Base44 call"));
		const diagnostics = vi.spyOn(privateIdWebhookDiagnosticsRepository, "capture");
		const app = Fastify();
		await registerPrivateIdRoutes(app, service);
		try {
			const missing = await app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", puid: randomUUID() } });
			expect(missing.statusCode).toBe(400);
			const unknown = await app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", transactionID: randomUUID(), puid: randomUUID() } });
			expect(unknown.statusCode).toBe(202);
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
			expect(base44).not.toHaveBeenCalled();
			expect(diagnostics).not.toHaveBeenCalled();
		} finally { await app.close(); base44.mockRestore(); diagnostics.mockRestore(); }
	});
	it("atomically rolls back authenticator creation and completion if audit persistence fails", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), puid = randomUUID();
		await pool.query(`CREATE FUNCTION reject_h5_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN IF NEW.type='AUTHENTICATOR_ENROLLED' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$`);
		await pool.query("CREATE TRIGGER reject_h5_audit BEFORE INSERT ON authenticator_enrollment_audit FOR EACH ROW EXECUTE FUNCTION reject_h5_audit()");
		try {
			await expect(complete(flow, puid)).rejects.toThrow("fixture audit failure");
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
			expect(await service.callback(flow.transactionId, flow.sessionId)).toMatchObject({ body: { status: "pending" } });
		} finally { await pool.query("DROP TRIGGER reject_h5_audit ON authenticator_enrollment_audit"); }
		expect(await complete(flow, puid)).toMatchObject({ statusCode: 200 });
	});
	it("prepares additive schema while disabled and leaves canonical H3 evidence unchanged", async () => {
		const subject = await seed(), before = await snapshot(subject.id);
		const override = vi.spyOn(infrastructure, "getPostgresPool").mockReturnValue(pool);
		const app = Fastify();
		try {
			const callbacks = await configureFaceEnrollment(app, { HAPI_FACE_ENROLLMENT_ENABLED: "false" });
			expect(callbacks).toBeDefined();
			expect((await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll", payload: {} })).statusCode).toBe(404);
			await repository.ensureSchema();
			await repository.ensureSchema();
			expect(await snapshot(subject.id)).toEqual(before);
		} finally { override.mockRestore(); await app.close(); }
	});
	it("requires an authenticated provider webhook and never lets browser redirects enroll or authenticate", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		const base44 = vi.spyOn(identityService, "resolveIdentity").mockRejectedValue(new Error("Forbidden Base44 call"));
		const legacyRegistration = vi.spyOn(identityRegistry, "resolveOrCreate").mockRejectedValue(new Error("Forbidden identity creation"));
		const diagnostics = vi.spyOn(privateIdWebhookDiagnosticsRepository, "capture");
		const app = Fastify();
		await registerPrivateIdRoutes(app, service);
		try {
			const payload = { status: "SUCCESS", transactionID: flow.transactionId, sessionId: flow.sessionId, puid: randomUUID() };
			expect((await app.inject({ method: "POST", url: "/privateid/webhook", payload })).statusCode).toBe(401);
			const callback = await app.inject({ method: "GET", url: `/privateid/callback?reason=success&transactionID=${flow.transactionId}&puid=untrusted` });
			expect(callback.headers["content-type"]).toContain("text/html");
			expect(callback.body).not.toContain("untrusted");
			expect((await app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" }, payload })).json()).toMatchObject({ enrolled: true });
			expect(base44).not.toHaveBeenCalled();
			expect(legacyRegistration).not.toHaveBeenCalled();
			expect(diagnostics).not.toHaveBeenCalled();
		} finally { await app.close(); base44.mockRestore(); legacyRegistration.mockRestore(); diagnostics.mockRestore(); }
	});
	it.each([false, true])("H5.1 status observes completion when webhook-before-redirect=%s without callback attachment", async webhookFirst => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), before = await snapshot(subject.id);
		const decoy = { sessionId: randomUUID(), transactionId: randomUUID(), launchUrl: "https://privateid.example.test/other",
			status: "created" as const, created: Date.now(), expires: Date.now() + 300_000 };
		storePrivateIDSession(decoy);
		const fixture = await statusApp(subject.oidcSubject, true);
		const puid = randomUUID();
		try {
			const url = `/v1/authenticators/privateid/enroll/${flow.transactionId}/status`;
			const providerEvent = () => fixture.app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", transactionID: flow.transactionId, sessionId: flow.sessionId, puid } });
			if (webhookFirst) expect((await providerEvent()).statusCode).toBe(200);
			const redirect = await fixture.app.inject({ url: "/privateid/callback?reason=success" });
			expect(redirect.statusCode).toBe(200);
			expect(redirect.headers["content-type"]).toContain("text/html");
			expect(redirect.headers["cache-control"]).toBe("no-store");
			expect(redirect.body).toContain('sessionStorage.getItem("hapi.faceEnrollment")');
			expect(redirect.body).toContain("Unable to resume enrollment");
			expect(getCurrentPrivateIDSessionRecord()!.session).toEqual(decoy);
			const status = await fixture.app.inject({ url, headers: fixture.headers });
			expect(status.json().status).toBe(webhookFirst ? "COMPLETED" : "PENDING");
			expect(Object.keys(status.json()).sort()).toEqual(["guidance", "status"]);
			expect(await authenticators.findByUser(subject.id)).toHaveLength(webhookFirst ? 1 : 0);
			if (!webhookFirst) expect((await providerEvent()).statusCode).toBe(200);
			for (let poll = 0; poll < 3; poll += 1) {
				const response = await fixture.app.inject({ url, headers: fixture.headers });
				expect(response.json()).toMatchObject({ status: "COMPLETED" });
				expect(response.body).not.toContain(puid);
				expect(response.body).not.toContain(subject.id);
			}
			expect((await providerEvent()).json()).toMatchObject({ alreadyEnrolled: true });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(1);
			expect(await snapshot(subject.id)).toEqual(before);
			const audit = (await pool.query("SELECT * FROM authenticator_enrollment_audit WHERE identity_subject_id=$1", [subject.id])).rows;
			expect(JSON.stringify(audit)).not.toContain(puid);
			expect(fixture.logs.join("")).not.toContain(puid);
		} finally { await fixture.app.close(); }
	});
	it("H5.1 concurrent status reads and authenticated webhook completion commit exactly one attachment", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), fixture = await statusApp(subject.oidcSubject);
		const url = `/v1/authenticators/privateid/enroll/${flow.transactionId}/status`;
		try {
			const reads = Array.from({ length: 8 }, () => fixture.app.inject({ url, headers: fixture.headers }));
			const webhook = fixture.app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", transactionID: flow.transactionId, puid: randomUUID() } });
			const results = await Promise.all([...reads, webhook]);
			for (const response of results.slice(0, -1)) {
				expect(response.statusCode).toBe(200);
				expect(["PENDING", "COMPLETED"]).toContain(response.json().status);
			}
			expect(results.at(-1)!.statusCode).toBe(200);
			expect((await fixture.app.inject({ url, headers: fixture.headers })).json().status).toBe("COMPLETED");
			expect(await authenticators.findByUser(subject.id)).toHaveLength(1);
		} finally { await fixture.app.close(); }
	});
	it("H5.1 rejects another subject, client, tenant or application reading a binding", async () => {
		const target = await seed(), other = await seed(), flow = await pending(target.oidcSubject);
		const otherBrowser = await statusApp(other.oidcSubject);
		const targetBrowser = await statusApp(target.oidcSubject);
		const url = `/v1/authenticators/privateid/enroll/${flow.transactionId}/status`;
		try {
			expect((await otherBrowser.app.inject({ url, headers: otherBrowser.headers })).statusCode).toBe(404);
			const wrongClient = await statusApp(target.oidcSubject, false, { clientId: otherClientId });
			try { expect((await wrongClient.app.inject({ url, headers: wrongClient.headers })).statusCode).toBe(403); }
			finally { await wrongClient.app.close(); }
		} finally { await otherBrowser.app.close(); }
		await expect(service.status(flow.transactionId, authority(other.oidcSubject))).rejects.toMatchObject({ statusCode: 404 });
		await expect(service.status(flow.transactionId, authority(target.oidcSubject, { clientId: otherClientId }))).rejects.toMatchObject({ statusCode: 403 });
		const sameApplicationClient = "same-app-" + randomUUID();
		await h1.clients.upsert({ id: randomUUID(), applicationId, clientId: sameApplicationClient, clientSecret: "fixture-secret",
			redirectUris: ["https://rp.example/callback"], scopes: ["openid"], grantTypes: ["authorization_code"],
			responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
		await expect(service.status(flow.transactionId, authority(target.oidcSubject, { clientId: sameApplicationClient }))).rejects.toMatchObject({ statusCode: 403 });
		for (const [column, wrong, original] of [["tenant_id", otherTenant, tenantId], ["application_id", otherApplication, applicationId]]) {
			await pool.query(`UPDATE hapi_face_enrollment_bindings SET ${column}=$2 WHERE session_id=$1`, [flow.sessionId, wrong]);
			try {
				await expect(service.status(flow.transactionId, authority(target.oidcSubject))).rejects.toMatchObject({ statusCode: 403 });
				expect((await targetBrowser.app.inject({ url, headers: targetBrowser.headers })).statusCode).toBe(403);
			}
			finally { await pool.query(`UPDATE hapi_face_enrollment_bindings SET ${column}=$2 WHERE session_id=$1`, [flow.sessionId, original]); }
		}
		await targetBrowser.app.close();
		expect(await authenticators.findByUser(target.id)).toHaveLength(0);
	});
	it("H5.1 revalidates suspended tenant, application and canonical subject on status reads", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		for (const [table, id, disabled, active] of [["tenants", tenantId, "suspended", "active"],
			["applications", applicationId, "suspended", "active"], ["identity_subjects", subject.id, "DISABLED", "ACTIVE"]]) {
			await pool.query(`UPDATE ${table} SET status=$2 WHERE id=$1`, [id, disabled]);
			try { await expect(service.status(flow.transactionId, authority(subject.oidcSubject))).rejects.toMatchObject({ statusCode: 403 }); }
			finally { await pool.query(`UPDATE ${table} SET status=$2 WHERE id=$1`, [id, active]); }
		}
	});
	it("H5.1 expiry and repeated polling are read-only and cannot attach an authenticator", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), before = await snapshot(subject.id);
		const beforeAudit = (await pool.query("SELECT * FROM authenticator_enrollment_audit WHERE identity_subject_id=$1", [subject.id])).rows;
		for (let poll = 0; poll < 3; poll += 1) expect(await service.status(flow.transactionId, authority(subject.oidcSubject))).toMatchObject({ body: { status: "PENDING" } });
		await pool.query("UPDATE privateid_enrollment_transactions SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE provider_transaction_id=$1", [flow.transactionId]);
		expect(await service.status(flow.transactionId, authority(subject.oidcSubject))).toMatchObject({ statusCode: 410, body: { status: "EXPIRED" } });
		expect((await pool.query("SELECT status FROM privateid_enrollment_transactions WHERE provider_transaction_id=$1", [flow.transactionId])).rows[0].status).toBe("pending");
		expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		expect(await snapshot(subject.id)).toEqual(before);
		expect((await pool.query("SELECT * FROM authenticator_enrollment_audit WHERE identity_subject_id=$1", [subject.id])).rows).toEqual(beforeAudit);
	});
	it("H5.1 status rechecks expiry after waiting for a completion lock", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject), blocker = await pool.connect();
		try {
			await pool.query("UPDATE privateid_enrollment_transactions SET expires_at=clock_timestamp()+INTERVAL '150 milliseconds' WHERE provider_transaction_id=$1", [flow.transactionId]);
			await blocker.query("BEGIN");
			await blocker.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [subject.id]);
			const waiting = service.status(flow.transactionId, authority(subject.oidcSubject));
			await new Promise(resolve => setTimeout(resolve, 250));
			await blocker.query("COMMIT");
			expect(await waiting).toMatchObject({ statusCode: 410, body: { status: "EXPIRED" } });
			expect(await authenticators.findByUser(subject.id)).toHaveLength(0);
		} finally { await blocker.query("ROLLBACK"); blocker.release(); }
	});
	it("H5.1 terminal failure, conflict and completion stay immutable under later callbacks or webhooks", async () => {
		const subject = await seed(), flow = await pending(subject.oidcSubject);
		await service.webhook(flow.transactionId, flow.sessionId, "FAILURE", undefined);
		expect(await service.status(flow.transactionId, authority(subject.oidcSubject))).toMatchObject({ body: { status: "FAILED" } });
		await service.webhook(flow.transactionId, randomUUID(), "SUCCESS", randomUUID());
		expect(await complete(flow)).toMatchObject({ statusCode: 409 });
		expect(await service.status(flow.transactionId, authority(subject.oidcSubject))).toMatchObject({ body: { status: "FAILED" } });
		const owner = await seed(), target = await seed(), puid = randomUUID();
		await complete(await pending(owner.oidcSubject), puid);
		const conflict = await pending(target.oidcSubject);
		await complete(conflict, puid);
		expect(await service.status(conflict.transactionId, authority(target.oidcSubject))).toMatchObject({ body: { status: "CONFLICT" } });
		expect(await complete(conflict, randomUUID())).toMatchObject({ statusCode: 409 });
		expect(await service.status(conflict.transactionId, authority(target.oidcSubject))).toMatchObject({ body: { status: "CONFLICT" } });
		expect(await authenticators.findByUser(target.id)).toHaveLength(0);
		const completed = await pending(subject.oidcSubject);
		await complete(completed);
		expect(await service.webhook(completed.transactionId, completed.sessionId, "FAILURE", undefined)).toMatchObject({ statusCode: 409 });
		expect(await service.status(completed.transactionId, authority(subject.oidcSubject))).toMatchObject({ body: { status: "COMPLETED" } });
	});
	it("email login, real enrollment, Face login, token and userinfo all resolve the identical canonical subject", async () => {
		const subject = await seed();
		const lookup = vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
		const resolveLogin = vi.spyOn(authenticatorLoginResolver, "resolveLogin").mockImplementation((provider, transaction, puid) => login.resolveLogin(provider, transaction, puid));
		const base44 = vi.spyOn(identityService, "resolveIdentity").mockRejectedValue(new Error("Forbidden Base44 call"));
		const createIdentity = vi.spyOn(identityRegistry, "resolveOrCreate").mockRejectedValue(new Error("Forbidden identity creation"));
		const h3Calls = vi.spyOn(registration, "complete");
		const diagnostics = vi.spyOn(privateIdWebhookDiagnosticsRepository, "capture").mockResolvedValue(undefined);
		const client = {
			client_id: clientId, client_secret: "fixture-secret", redirect_uris: ["https://rp.example/callback"],
			grant_types: ["authorization_code"], response_types: ["code"], scope: "openid email",
			token_endpoint_auth_method: "client_secret_basic", require_pkce: true
		};
		const oidc = new OIDCService({ authenticationProvider: new PrivateIDAuthenticationProvider(), clients: [client], oidcClients: h1.clients });
		oidc.configureEmailAuthentication({ async consume(request, result, expectedClient) {
			const authority = await authorizeH1Client(request, h1);
			expect(authority.clientId).toBe(expectedClient);
			return authenticationRepository.consumeResult(authority, result);
		} });
		const actualService = new HapiFaceEnrollmentService(repository, async transactionId => {
			const session = await createSession(transactionId);
			storePrivateIDSession(session);
			markHapiFaceEnrollmentSession(session.sessionId);
			return session;
		});
		const app = Fastify();
		await app.register(formbody);
		await registerHapiFaceEnrollmentRoutes(app, actualService, new RedisOIDCStore());
		await registerPrivateIdRoutes(app, actualService);
		await oidc.registerEndpoints(app);
		async function emailTokens() {
			const challenge = await h4.start({ context, clientId }, subject.email!);
			const otp = provider.messages.findLast(message => message.destination === subject.email)!.code;
			const result = await h4.verify({ context, clientId }, challenge.challengeId, otp);
			const verifier = "h5-email-pkce-" + randomUUID();
			const authorized = await app.inject({ method: "POST", url: "/authorize", headers, payload: {
				client_id: clientId, redirect_uri: "https://rp.example/callback", response_type: "code",
				scope: "openid email", nonce: randomUUID(), code_challenge_method: "S256",
				code_challenge: createHash("sha256").update(verifier).digest("base64url"), authentication_result: result.authenticationResult
			} });
			expect(authorized.statusCode, authorized.body).toBe(200);
			const code = new URL(authorized.json().redirectUri).searchParams.get("code")!;
			const response = await app.inject({ method: "POST", url: "/token", headers, payload: {
				grant_type: "authorization_code", code, redirect_uri: "https://rp.example/callback", code_verifier: verifier
			} });
			expect(response.statusCode, response.body).toBe(200);
			expect(decodeJwt(response.json().id_token)).toMatchObject({ sub: subject.oidcSubject, amr: ["email"], auth_time: expect.any(Number) });
			return response.json();
		}
		try {
			const email = await emailTokens();
			const before = await snapshot(subject.id);
			const started = await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll",
				headers: { authorization: "Bearer " + email.access_token }, payload: {} });
			expect(started.statusCode, started.body).toBe(200);
			const enrollmentId = started.json().enrollmentId;
			const puid = randomUUID();
			const webhook = await app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", transactionID: enrollmentId, puid } });
			expect(webhook.statusCode, webhook.body).toBe(200);
			expect(await snapshot(subject.id)).toEqual(before);
			const verifier = "h5-face-pkce-" + randomUUID(), nonce = randomUUID();
			const authorized = await app.inject({ method: "GET", url: "/authorize?" + new URLSearchParams({
				response_type: "code", client_id: clientId, redirect_uri: "https://rp.example/callback", scope: "openid email",
				nonce, state: randomUUID(), code_challenge_method: "S256",
				code_challenge: createHash("sha256").update(verifier).digest("base64url")
			}) });
			expect(authorized.statusCode, authorized.body).toBe(302);
			const browserCookie = String(authorized.headers["set-cookie"]).split(";")[0];
			expect(authorized.headers["set-cookie"]).toContain("HttpOnly");
			expect(authorized.headers["set-cookie"]).toContain("Secure");
			const faceSession = getCurrentPrivateIDSessionRecord()!.session;
			const faceWebhook = await app.inject({ method: "POST", url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": "privateid-webhook-secret" },
				payload: { status: "SUCCESS", sessionId: faceSession.sessionId, transactionID: faceSession.transactionId, puid } });
			expect(faceWebhook.statusCode, faceWebhook.body).toBe(200);
			const faceAuthenticatedAt = getCurrentPrivateIDSessionRecord()!.authenticatedUser!.authenticatedAt!;
			const unrelated = { sessionId: randomUUID(), transactionId: randomUUID(), launchUrl: "https://privateid.example.test/unrelated",
				status: "created" as const, created: Date.now(), expires: Date.now() + 300_000 };
			storePrivateIDSession(unrelated);
			markHapiFaceEnrollmentSession(unrelated.sessionId);
			const callback = await app.inject({ method: "GET", url: "/privateid/callback?reason=success", headers: { cookie: browserCookie } });
			expect(callback.statusCode, callback.body).toBe(302);
			expect(callback.headers["set-cookie"]).toContain("Max-Age=0");
			expect(findPrivateIDSession(faceSession.sessionId)!.authenticatedUser!.authenticatedAt).toBe(faceAuthenticatedAt);
			expect(getCurrentPrivateIDSessionRecord()!.session).toEqual(unrelated);
			const code = new URL(String(callback.headers.location)).searchParams.get("code")!;
			const tokens = await app.inject({ method: "POST", url: "/token", headers, payload: {
				grant_type: "authorization_code", code, redirect_uri: "https://rp.example/callback", code_verifier: verifier
			} });
			expect(tokens.statusCode, tokens.body).toBe(200);
			expect(decodeJwt(tokens.json().id_token)).toMatchObject({ sub: subject.oidcSubject, email: subject.email,
				email_verified: true, amr: ["face", "privateid"], auth_time: Math.floor(Date.parse(faceAuthenticatedAt) / 1000), nonce });
			const userinfo = await app.inject({ method: "GET", url: "/userinfo", headers: { authorization: "Bearer " + tokens.json().access_token } });
			expect(userinfo.statusCode).toBe(200);
			expect(userinfo.json()).toMatchObject({ sub: subject.oidcSubject, email: subject.email, email_verified: true });
			expect(await snapshot(subject.id)).toEqual(before);
			// Face cannot authorize adding another authenticator; recent email step-up is required.
			expect((await app.inject({ method: "POST", url: "/v1/authenticators/privateid/enroll",
				headers: { authorization: "Bearer " + tokens.json().access_token }, payload: {} })).statusCode).toBe(401);
			const emailAgain = await emailTokens();
			expect(decodeJwt(emailAgain.id_token).sub).toBe(subject.oidcSubject);
			expect(base44).not.toHaveBeenCalled();
			expect(createIdentity).not.toHaveBeenCalled();
			expect(h3Calls).not.toHaveBeenCalled();
			expect((await authenticators.findByUser(subject.id))).toHaveLength(1);
		} finally {
			await app.close(); lookup.mockRestore(); resolveLogin.mockRestore(); base44.mockRestore();
			createIdentity.mockRestore(); h3Calls.mockRestore(); diagnostics.mockRestore();
		}
	});
});
