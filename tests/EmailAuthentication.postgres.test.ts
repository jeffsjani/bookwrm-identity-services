import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { PostgresEmailAuthenticationRepository } from "../src/authentication/email/PostgresEmailAuthenticationRepository.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import { PostgresRegistrationRepository } from "../src/registration/PostgresRegistrationRepository.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { PostgresOIDCClientRepository } from "../src/identity/PostgresOIDCClientRepository.js";
import { PostgresApplicationRepository } from "../src/identity/PostgresApplicationRepository.js";
import { PostgresTenantRepository } from "../src/identity/PostgresTenantRepository.js";
import { authorizeH1Client } from "../src/identity/H1ClientAuthority.js";
import { EmailAuthenticationError } from "../src/authentication/email/EmailAuthenticationTypes.js";
import { registerEmailAuthenticationRoutes } from "../src/routes/emailAuthentication.js";
import { configureEmailVerification, interactiveEmailAuthentication } from "../src/adapters/email/EmailVerificationComposition.js";
import * as postgresInfrastructure from "../src/identity/infrastructure/PostgresInfrastructure.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { IdentityRegistry, identityRegistry } from "../src/identity/IdentityRegistry.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";
import { ensureOidcTestEnvironment } from "./oidcTestHarness.js";
import type { AuthenticationProvider } from "../src/authentication/AuthenticationProvider.js";
import type { IdentityProvider, IdentitySubjectStatus } from "../src/models/IdentitySubject.js";

const databaseUrl = process.env.HAPI_AUTHENTICATION_TEST_DATABASE_URL;
const schema = "h4_" + randomUUID().replaceAll("-", "");

describe.skipIf(!databaseUrl)("H4 isolated PostgreSQL identity resolution and single-use artifacts", () => {
	const admin = new pg.Pool({ connectionString: databaseUrl });
	const pool = new pg.Pool({ connectionString: databaseUrl, max: 16, options: `-c search_path=${schema}` });
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const otherApplication = randomUUID();
	const otherTenant = randomUUID();
	const otherTenantApplication = randomUUID();
	const context = { tenantId, applicationId };
	const clientId = "h4-" + randomUUID();
	const authority = { context, clientId };
	const provider = new InMemoryEmailDeliveryProvider();
	const challenges = new PostgresVerificationChallengeRepository(pool);
	const h2 = new EmailVerificationService(challenges, provider,
		new VerificationSecrets("h4-pg-test-secret".repeat(3)), defaultVerificationPolicy);
	const repository = new PostgresEmailAuthenticationRepository(pool);
	const service = new EmailAuthenticationService(h2, challenges, repository);
	const subjects = new PostgresIdentitySubjectRepository(pool);
	const registrationService = new RegistrationService(new PostgresRegistrationRepository(pool));
	const h1 = {
		clients: new PostgresOIDCClientRepository(pool),
		applications: new PostgresApplicationRepository(pool),
		tenants: new PostgresTenantRepository(pool)
	};
	const interactive = interactiveEmailAuthentication(service, h1, {
		verification: h2,
		challenges,
		registration: registrationService,
		subjects: new IdentityRegistry(subjects)
	});
	const headers = { authorization: "Basic " + Buffer.from(clientId + ":h4-test-secret").toString("base64") };
	let app: ReturnType<typeof Fastify>;

	async function seed(email = `${randomUUID()}@example.com`, overrides: {
		provider?: IdentityProvider; status?: IdentitySubjectStatus; emailVerified?: boolean; applicationId?: string
	} = {}) {
		return subjects.create({ id: randomUUID(), oidcSubject: randomUUID(),
			primaryProvider: overrides.provider ?? "HAPI_EMAIL", primaryProviderSubject: email,
			applicationId: overrides.applicationId ?? applicationId, email,
			emailVerified: overrides.emailVerified ?? true, status: overrides.status ?? "ACTIVE" });
	}
	async function start(email: string) {
		const result = await service.start(authority, email);
		const code = provider.messages.findLast(message => message.destination === email)!.code;
		return { ...result, code };
	}
	async function authenticated(email: string) {
		const challenge = await start(email);
		const result = await service.verify(authority, challenge.challengeId, challenge.code);
		return { ...challenge, result };
	}
	async function count(table: "identity_subjects" | "user_authenticators" | "identity_account_links" |
		"privateid_enrollment_transactions" | "authenticator_login_transactions" | "registration_evidence") {
		return (await pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM ${table}`)).rows[0].count;
	}

	beforeAll(async () => {
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
		await challenges.ensureSchema();
		await pool.query(readFileSync(new URL("../src/registration/schema.sql", import.meta.url), "utf8"));
		await repository.ensureSchema();
		await pool.query("INSERT INTO tenants VALUES ($1,'H4 test',$2,'active',NOW(),NOW())", [tenantId, schema]);
		await pool.query("INSERT INTO tenants VALUES ($1,'H4 other',$2,'active',NOW(),NOW())", [otherTenant, schema + "_other"]);
		await pool.query("INSERT INTO applications VALUES ($1,$2,'H4 other','other','active',NOW(),NOW())", [otherTenantApplication, otherTenant]);
		for (const id of [applicationId, otherApplication]) {
			await pool.query("INSERT INTO applications VALUES ($1,$2,'H4 test',$3,'active',NOW(),NOW())", [id, tenantId, id]);
		}
		await h1.clients.upsert({ id: randomUUID(), applicationId, clientId,
			clientSecret: "h4-test-secret", redirectUris: ["https://rp.example/callback"],
			scopes: ["openid", "email"], grantTypes: ["authorization_code"], responseTypes: ["code"],
			requirePkce: true, tokenEndpointAuthMethod: "client_secret_basic" });
		app = Fastify();
		await registerEmailAuthenticationRoutes(app, service, h1);
		await app.ready();
	});

	afterAll(async () => {
		if (app) await app.close();
		await pool.end();
		await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
		await admin.end();
	});

	it("returns the real canonical stable subject without creating any subject or downstream artifact", async () => {
		const subject = await seed();
		const before = await count("identity_subjects");
		const flow = await authenticated(subject.email!);
		expect(flow.result).toMatchObject({ authenticated: true, subject: subject.oidcSubject,
			authenticationMethod: "HAPI_EMAIL", assurance: "email_otp", expiresIn: 60 });
		expect(await count("identity_subjects")).toBe(before);
		for (const table of ["user_authenticators", "identity_account_links", "privateid_enrollment_transactions",
			"authenticator_login_transactions", "registration_evidence"] as const) expect(await count(table)).toBe(0);
		expect(await challenges.findById(flow.challengeId)).toMatchObject({ status: "CONSUMED", consumedAt: expect.any(String) });
		const stored = (await pool.query("SELECT * FROM email_authentication_results WHERE verification_challenge_id=$1", [flow.challengeId])).rows;
		expect(stored).toHaveLength(1);
		expect(stored[0].token_hash).not.toBe(flow.result.authenticationResult);
		expect(stored[0].token_hash).toBe(createHash("sha256").update(flow.result.authenticationResult).digest("hex"));
		const audits = (await pool.query("SELECT type FROM email_authentication_audit WHERE challenge_id=$1 ORDER BY occurred_at", [flow.challengeId])).rows;
		expect(audits.map(row => row.type)).toEqual(["EMAIL_AUTHENTICATION_STARTED", "EMAIL_AUTHENTICATION_VERIFIED", "EMAIL_AUTHENTICATION_SUCCEEDED"]);
	});

	describe("H6.8 unified Universal Login email with PostgreSQL", () => {
		async function startInteractive(email: string) {
			const authorized = await interactive.authority(clientId);
			const started = await interactive.start(authorized, email);
			const code = provider.messages.findLast(message => message.destination === email)!.code;
			return { authorized, ...started, code };
		}

		it("uses H2 registration and H3 to create exactly one verified canonical identity", async () => {
			const email = `${randomUUID()}@example.com`;
			const before = await count("identity_subjects");
			const flow = await startInteractive(email);
			expect(flow.mode).toBe("REGISTRATION");
			expect((await challenges.findById(flow.challengeId))?.purpose).toBe("REGISTRATION");
			const result = await interactive.verify(flow.authorized, flow.challengeId, flow.code, flow.mode);
			expect(result.mode).toBe("REGISTRATION");
			if (result.mode !== "REGISTRATION") throw new Error("Expected H3 registration continuation");
			const subject = await subjects.findByOidcSubject(result.principal.sub);
			expect(subject).toMatchObject({ primaryProvider: "HAPI_EMAIL", email, emailVerified: true, status: "ACTIVE",
				applicationId });
			expect(subject?.oidcSubject).toBeTruthy();
			expect(await subjects.findByEmail(email)).toHaveLength(1);
			expect(await count("identity_subjects")).toBe(before + 1);
			expect(await challenges.findById(flow.challengeId)).toMatchObject({ purpose: "REGISTRATION", status: "CONSUMED" });
			expect((await pool.query("SELECT identity_subject_id FROM registration_evidence WHERE verification_challenge_id=$1",
				[flow.challengeId])).rows).toEqual([{ identity_subject_id: subject!.id }]);
			await expect(interactive.verify(flow.authorized, flow.challengeId, flow.code, flow.mode)).rejects.toThrow();
			expect(await subjects.findByEmail(email)).toHaveLength(1);
		});

		it("uses H4 for returning HAPI_EMAIL users without creating a second subject", async () => {
			const subject = await seed();
			const before = await count("identity_subjects");
			const flow = await startInteractive(subject.email!);
			expect(flow.mode).toBe("AUTHENTICATION");
			expect((await challenges.findById(flow.challengeId))?.purpose).toBe("AUTHENTICATION");
			const result = await interactive.verify(flow.authorized, flow.challengeId, flow.code, flow.mode);
			expect(result.mode).toBe("AUTHENTICATION");
			if (result.mode !== "AUTHENTICATION") throw new Error("Expected H4 authentication result");
			const principal = await interactive.consumeResult(flow.authorized, result.authenticationResult);
			expect(principal).toMatchObject({ id: subject.id, sub: subject.oidcSubject, email: subject.email,
				emailVerified: true, authenticationMethod: "HAPI_EMAIL" });
			expect(await count("identity_subjects")).toBe(before);
		});

		it("fails closed for a PrivateID-primary identity without changing or duplicating it", async () => {
			const email = `${randomUUID()}@example.com`;
			const subject = await subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId,
				primaryProvider: "PrivateID", primaryProviderSubject: `privateid-${randomUUID()}`,
				email, emailVerified: true, status: "ACTIVE" });
			const before = await count("identity_subjects");
			const flow = await startInteractive(email);
			expect(flow.mode).toBe("INELIGIBLE");
			expect((await challenges.findById(flow.challengeId))?.purpose).toBe("AUTHENTICATION");
			await expect(interactive.verify(flow.authorized, flow.challengeId, flow.code, flow.mode))
				.rejects.toThrow(EmailAuthenticationError);
			expect(await count("identity_subjects")).toBe(before);
			expect(await subjects.findByOidcSubject(subject.oidcSubject)).toMatchObject({
				id: subject.id, oidcSubject: subject.oidcSubject, primaryProvider: "PrivateID",
				primaryProviderSubject: subject.primaryProviderSubject, email
			});
			expect(await subjects.findByProviderSubject("HAPI_EMAIL", email)).toBeUndefined();
			expect(await challenges.findById(flow.challengeId)).toMatchObject({ status: "CONSUMED" });
		});

		it("rejects ambiguous email ownership and resolves concurrent registrations to one identity", async () => {
			const ambiguousEmail = `${randomUUID()}@example.com`;
			for (const providerName of ["PrivateID", "Enterprise"] as const) {
				await subjects.create({ id: randomUUID(), oidcSubject: randomUUID(), applicationId,
					primaryProvider: providerName, primaryProviderSubject: `${providerName}-${randomUUID()}`,
					email: ambiguousEmail, emailVerified: true, status: "ACTIVE" });
			}
			const ambiguous = await startInteractive(ambiguousEmail);
			expect(ambiguous.mode).toBe("INELIGIBLE");
			await expect(interactive.verify(ambiguous.authorized, ambiguous.challengeId, ambiguous.code, ambiguous.mode))
				.rejects.toThrow(EmailAuthenticationError);
			expect(await subjects.findByProviderSubject("HAPI_EMAIL", ambiguousEmail)).toBeUndefined();

			const email = `${randomUUID()}@example.com`;
			const first = await startInteractive(email);
			const second = await startInteractive(email);
			expect([first.mode, second.mode]).toEqual(["REGISTRATION", "REGISTRATION"]);
			const results = await Promise.all([
				interactive.verify(first.authorized, first.challengeId, first.code, first.mode),
				interactive.verify(second.authorized, second.challengeId, second.code, second.mode)
			]);
			expect(results.every(result => result.mode === "REGISTRATION")).toBe(true);
			const matches = await subjects.findByEmail(email);
			expect(matches).toHaveLength(1);
			expect(await subjects.findByProviderSubject("HAPI_EMAIL", email)).toMatchObject({
				id: matches[0].id, oidcSubject: matches[0].oidcSubject,
				status: "ACTIVE", primaryProvider: "HAPI_EMAIL", emailVerified: true
			});
		});
	});

	it("existing and unknown email start responses are indistinguishable before email proof", async () => {
		const existing = await seed();
		const unknown = `${randomUUID()}@example.com`;
		for (const email of [existing.email!, unknown]) {
			const response = await app.inject({ method: "POST", url: "/v1/authentication/email/start", headers, payload: { email } });
			expect(response.statusCode).toBe(200);
			expect(response.json()).toEqual({ challengeId: expect.any(String), expiresIn: 600, resendAfter: 60 });
			expect(response.headers["cache-control"]).toBe("no-store");
		}
		expect(await subjects.findByProviderSubject("HAPI_EMAIL", unknown)).toBeUndefined();
	});
	it.each(["unknown", "inactive", "unverified", "other-provider", "other-application"] as const)(
		"%s email proof receives the same generic failure and no result/identity creation", async kind => {
			const email = `${randomUUID()}@example.com`;
			const existing = kind !== "unknown" ? await seed(email, {
				...(kind === "inactive" ? { status: "DISABLED" } : {}),
				...(kind === "unverified" ? { emailVerified: false } : {}),
				...(kind === "other-provider" ? { provider: "PrivateID" } : {}),
				...(kind === "other-application" ? { applicationId: otherApplication } : {})
			}) : undefined;
			const before = await count("identity_subjects");
			const flow = await start(email);
			const response = await app.inject({ method: "POST", url: "/v1/authentication/email/verify", headers,
				payload: { challengeId: flow.challengeId, code: flow.code } });
			expect(response.statusCode).toBe(401);
			expect(response.json()).toEqual({ error: "AUTHENTICATION_FAILED" });
			expect(await count("identity_subjects")).toBe(before);
			if (existing) expect(await subjects.findById(existing.id)).toEqual(existing);
			expect(await challenges.findById(flow.challengeId)).toMatchObject({ status: "CONSUMED" });
			expect((await pool.query("SELECT * FROM email_authentication_results WHERE verification_challenge_id=$1", [flow.challengeId])).rows).toHaveLength(0);
			const audit = (await pool.query("SELECT outcome FROM email_authentication_audit WHERE challenge_id=$1 AND type='EMAIL_AUTHENTICATION_FAILED'", [flow.challengeId])).rows;
			expect(audit).toEqual([{ outcome: kind === "unknown" || kind === "other-provider" ? "NO_ELIGIBLE_IDENTITY" : "IDENTITY_NOT_ELIGIBLE" }]);
		});
	it("allows exactly one concurrent OTP verification and one single-use principal handoff", async () => {
		const subject = await seed();
		const flow = await start(subject.email!);
		const attempts = await Promise.allSettled(Array.from({ length: 10 }, () =>
			service.verify(authority, flow.challengeId, flow.code)));
		const winners = attempts.filter(result => result.status === "fulfilled");
		expect(winners).toHaveLength(1);
		const result = winners[0].value;
		const consumed = await Promise.allSettled(Array.from({ length: 10 }, () =>
			new PostgresEmailAuthenticationRepository(pool).consumeResult(authority, result.authenticationResult)));
		const principal = consumed.filter(result => result.status === "fulfilled");
		expect(principal).toHaveLength(1);
		expect(principal[0].value).toMatchObject({ id: subject.id, sub: subject.oidcSubject, authenticationMethod: "HAPI_EMAIL" });
		await expect(service.verify(authority, flow.challengeId, flow.code)).rejects.toThrow("INVALID_CHALLENGE");
		await expect(repository.establish(authority, flow.challengeId)).rejects.toThrow("AUTHENTICATION_FAILED");
		expect((await pool.query("SELECT * FROM email_authentication_results WHERE verification_challenge_id=$1", [flow.challengeId])).rows).toHaveLength(1);
	});
	it("rejects wrong tenant/application/purpose without verification or consumption", async () => {
		const subject = await seed();
		const flow = await start(subject.email!);
		for (const wrong of [{ tenantId: otherTenant, applicationId: otherTenantApplication }, { applicationId: otherApplication }]) {
			const other = { ...authority, context: { ...context, ...wrong } };
			await expect(service.verify(other, flow.challengeId, flow.code)).rejects.toThrow("INVALID_CHALLENGE");
			await expect(service.resend(other, flow.challengeId)).rejects.toThrow("INVALID_CHALLENGE");
		}
		const registration = await h2.start(context, subject.email!, "REGISTRATION");
		const code = provider.messages.at(-1)!.code;
		await expect(service.verify(authority, registration.challengeId, code)).rejects.toThrow("INVALID_CHALLENGE");
		await expect(service.resend(authority, registration.challengeId)).rejects.toThrow("INVALID_CHALLENGE");
		await h2.verify(context, registration.challengeId, code);
		await expect(repository.establish(authority, registration.challengeId)).rejects.toThrow("AUTHENTICATION_FAILED");
		expect((await challenges.findById(registration.challengeId))?.status).toBe("VERIFIED");
		expect((await challenges.findById(flow.challengeId))?.status).toBe("PENDING");
	});
	it("binds result to the exact client, tenant and application without burning valid result on mismatch", async () => {
		const subject = await seed();
		const { result } = await authenticated(subject.email!);
		for (const wrong of [
			{ ...authority, clientId: "other-client" },
			{ ...authority, context: { ...context, applicationId: otherApplication } },
			{ ...authority, context: { tenantId: otherTenant, applicationId: otherTenantApplication } }
		]) await expect(repository.consumeResult(wrong, result.authenticationResult)).rejects.toThrow("AUTHENTICATION_FAILED");
		expect(await repository.consumeResult(authority, result.authenticationResult)).toMatchObject({ sub: subject.oidcSubject });
	});
	it("expires the authentication result at 60 seconds and cannot re-mint it from consumed H2 evidence", async () => {
		const subject = await seed();
		const flow = await authenticated(subject.email!);
		await pool.query("UPDATE email_authentication_results SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE verification_challenge_id=$1", [flow.challengeId]);
		await expect(repository.consumeResult(authority, flow.result.authenticationResult)).rejects.toThrow("AUTHENTICATION_FAILED");
		await expect(repository.establish(authority, flow.challengeId)).rejects.toThrow("AUTHENTICATION_FAILED");
	});
	it("rejects verified-but-expired evidence", async () => {
		const subject = await seed();
		const flow = await start(subject.email!);
		await h2.verify(context, flow.challengeId, flow.code, "AUTHENTICATION");
		await pool.query("UPDATE verification_challenges SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1", [flow.challengeId]);
		await expect(repository.establish(authority, flow.challengeId)).rejects.toThrow("AUTHENTICATION_FAILED");
		expect((await challenges.findById(flow.challengeId))?.status).toBe("VERIFIED");
	});
	it("rechecks eligibility at handoff and consumes an ineligible result", async () => {
		const subject = await seed();
		const flow = await authenticated(subject.email!);
		await pool.query("UPDATE identity_subjects SET status='LOCKED' WHERE id=$1", [subject.id]);
		await expect(repository.consumeResult(authority, flow.result.authenticationResult)).rejects.toThrow("AUTHENTICATION_FAILED");
		await pool.query("UPDATE identity_subjects SET status='ACTIVE' WHERE id=$1", [subject.id]);
		await expect(repository.consumeResult(authority, flow.result.authenticationResult)).rejects.toThrow("AUTHENTICATION_FAILED");
	});
	it("rejects an identity whose canonical email changed after email proof", async () => {
		const subject = await seed();
		const flow = await authenticated(subject.email!);
		const changedEmail = `${randomUUID()}@example.com`;
		await pool.query("UPDATE identity_subjects SET email=$2,primary_provider_subject=$2 WHERE id=$1", [subject.id, changedEmail]);
		await expect(repository.consumeResult(authority, flow.result.authenticationResult)).rejects.toThrow("AUTHENTICATION_FAILED");
	});
	it("consumes verified evidence once even when result issuance is invoked concurrently", async () => {
		const subject = await seed();
		const flow = await start(subject.email!);
		await h2.verify(context, flow.challengeId, flow.code, "AUTHENTICATION");
		const outcomes = await Promise.allSettled(Array.from({ length: 8 }, () =>
			new PostgresEmailAuthenticationRepository(pool).establish(authority, flow.challengeId)));
		expect(outcomes.filter(outcome => outcome.status === "fulfilled")).toHaveLength(1);
		expect((await pool.query("SELECT * FROM email_authentication_results WHERE verification_challenge_id=$1", [flow.challengeId])).rows).toHaveLength(1);
	});
	it.each(["evidence", "result"] as const)("rechecks %s expiration after waiting for an identity row lock", async kind => {
		const subject = await seed();
		const flow = await start(subject.email!);
		await h2.verify(context, flow.challengeId, flow.code, "AUTHENTICATION");
		const result = kind === "result" ? await repository.establish(authority, flow.challengeId) : undefined;
		const blocker = await pool.connect();
		try {
			await blocker.query("BEGIN");
			const pid = (await blocker.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0].pid;
			await blocker.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [subject.id]);
			if (kind === "evidence") {
				await pool.query("UPDATE verification_challenges SET expires_at=clock_timestamp()+INTERVAL '1 second' WHERE id=$1", [flow.challengeId]);
			} else {
				await pool.query("UPDATE email_authentication_results SET expires_at=clock_timestamp()+INTERVAL '1 second' WHERE verification_challenge_id=$1", [flow.challengeId]);
			}
			const pending = kind === "evidence" ? repository.establish(authority, flow.challengeId)
				: repository.consumeResult(authority, result!.authenticationResult);
			const outcome = pending.then(() => "unexpected_success",
				error => error instanceof Error ? error.message : "unexpected_failure");
			let waiting = false;
			for (let attempt = 0; attempt < 40; attempt++) {
				const blocked = (await pool.query<{ waiting: boolean }>(
					"SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))) AS waiting", [pid])).rows[0].waiting;
				if (blocked) { waiting = true; break; }
				await new Promise(resolve => setTimeout(resolve, 10));
			}
			expect(waiting).toBe(true);
			await pool.query("SELECT pg_sleep(1.1)");
			await blocker.query("COMMIT");
			expect(await outcome).toBe("AUTHENTICATION_FAILED");
		} finally { await blocker.query("ROLLBACK"); blocker.release(); }
	});
	it("rolls back consumption and result issuance together on a PostgreSQL insert failure", async () => {
		const subject = await seed();
		const flow = await start(subject.email!);
		await h2.verify(context, flow.challengeId, flow.code, "AUTHENTICATION");
		// A nonexistent authenticated client forces the result FK to fail after challenge consumption.
		await expect(repository.establish({ ...authority, clientId: "missing-client" }, flow.challengeId)).rejects.toThrow();
		expect((await challenges.findById(flow.challengeId))?.status).toBe("VERIFIED");
		expect((await pool.query("SELECT * FROM email_authentication_results WHERE verification_challenge_id=$1", [flow.challengeId])).rows).toHaveLength(0);
	});
	it("migrates an existing H2 purpose constraint without changing registration evidence and is repeatable", async () => {
		// Exercise the upgrade in a separate schema containing no AUTHENTICATION rows.
		const migrationSchema = schema + "_migration";
		await admin.query(`CREATE SCHEMA ${migrationSchema}`);
		const isolated = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${migrationSchema}` });
		try {
			await isolated.query(readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8"));
			await isolated.query(readFileSync(new URL("../src/email/schema.sql", import.meta.url), "utf8")
				.split("-- Expand only")[0].replaceAll(", 'AUTHENTICATION'", ""));
			const upgraded = new PostgresVerificationChallengeRepository(isolated);
			await isolated.query("INSERT INTO tenants VALUES ($1,'Migration',$2,'active',NOW(),NOW())", [tenantId, migrationSchema]);
			await isolated.query("INSERT INTO applications VALUES ($1,$2,'Migration','migration','active',NOW(),NOW())", [applicationId, tenantId]);
			const legacyH2 = new EmailVerificationService(upgraded, provider,
				new VerificationSecrets("h4-migration-test-secret".repeat(3)), defaultVerificationPolicy);
			const flow = await legacyH2.start(context, `${randomUUID()}@example.com`, "REGISTRATION");
			const old = await upgraded.findById(flow.challengeId);
			await upgraded.ensureSchema();
			await upgraded.ensureSchema();
			const constraint = (await isolated.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='verification_challenges'::regclass AND conname='verification_challenges_purpose_check'")).rows[0].definition;
			expect(constraint).toContain("AUTHENTICATION");
			expect(await upgraded.findById(flow.challengeId)).toEqual(old);
			await expect(legacyH2.start(context, `${randomUUID()}@example.com`, "AUTHENTICATION")).resolves.toBeDefined();
			const poolOverride = vi.spyOn(postgresInfrastructure, "getPostgresPool").mockReturnValue(isolated);
			const disabledApp = Fastify();
			try {
				expect(await configureEmailVerification(disabledApp, {
					HAPI_EMAIL_PROVIDER: "resend",
					HAPI_EMAIL_VERIFICATION_SECRET: "h4-disabled-migration-secret".repeat(3),
					RESEND_API_KEY: "unused-test-provider-key", HAPI_EMAIL_FROM: "verify@example.com",
					DATABASE_URL: databaseUrl!, HAPI_EMAIL_AUTHENTICATION_ENABLED: "false"
				})).toBeUndefined();
				const tables = (await isolated.query(`SELECT table_name FROM information_schema.tables
					WHERE table_schema=$1 AND table_name IN ('email_authentication_results','email_authentication_audit')
					ORDER BY table_name`, [migrationSchema])).rows;
				expect(tables.map(row => row.table_name)).toEqual(["email_authentication_audit", "email_authentication_results"]);
				for (const operation of ["start", "resend", "verify"]) {
					expect((await disabledApp.inject({ method: "POST",
						url: `/v1/authentication/email/${operation}`, payload: {} })).statusCode).toBe(404);
				}
				expect(await upgraded.findById(flow.challengeId)).toEqual(old);
			} finally { await disabledApp.close(); poolOverride.mockRestore(); }
		} finally {
			await isolated.end();
			await admin.query(`DROP SCHEMA ${migrationSchema} CASCADE`);
		}
	});
	it("feeds the existing PKCE/OIDC token and userinfo flow without invoking the face provider", async () => {
		ensureOidcTestEnvironment();
		const subject = await seed();
		const flow = await authenticated(subject.email!);
		const providerMock: AuthenticationProvider = {
			authenticate: vi.fn(async () => { throw new Error("Must not authenticate through another provider"); }),
			cancel: vi.fn(async () => {}), status: vi.fn(async () => ({ state: "idle" as const })),
			logout: vi.fn(async () => {}), beginAsyncAuthentication: vi.fn(async () => { throw new Error("Must not launch face"); })
		};
		const oidc = new OIDCService({ authenticationProvider: providerMock, oidcClients: h1.clients });
		const disabledApp = Fastify();
		await oidc.registerEndpoints(disabledApp);
		try {
			expect((await disabledApp.inject({ method: "POST", url: "/authorize", payload: {} })).statusCode).toBe(404);
		} finally { await disabledApp.close(); }
		oidc.configureEmailAuthentication({
			async consume(request, token, expectedClient) {
				const authenticatedClient = await authorizeH1Client(request, h1);
				if (authenticatedClient.clientId !== expectedClient) throw new EmailAuthenticationError();
				return repository.consumeResult(authenticatedClient, token);
			}
		});
		const oidcApp = Fastify();
		await oidcApp.register(formbody);
		await oidc.registerEndpoints(oidcApp);
		const lookup = vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
		try {
			const verifier = "h4-valid-pkce-verifier-" + randomUUID();
			const payload = { client_id: clientId, redirect_uri: "https://rp.example/callback",
				response_type: "code", scope: "openid email", nonce: "h4-nonce", state: "h4-state",
				code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url"),
				authentication_result: flow.result.authenticationResult };
			const malformed = await oidcApp.inject({ method: "POST", url: "/authorize",
				headers: { ...headers, "content-type": "application/json" },
				payload: '{"authentication_result":"not-for-output",' });
			expect(malformed.statusCode).toBe(400);
			expect(malformed.json()).toEqual({ error: "invalid_request" });
			expect(malformed.headers["cache-control"]).toBe("no-store");
			const invalid = await oidcApp.inject({ method: "POST", url: "/authorize", headers,
				payload: { ...payload, redirect_uri: "https://evil.example/callback" } });
			expect(invalid.statusCode).toBe(400);
			for (const invalidFields of [
				{ nonce: "" }, { scope: "email" }, { code_challenge_method: "plain" },
				{ code_challenge: "short" }, { response_type: "token" }, { scope: "openid forbidden" }
			]) {
				expect((await oidcApp.inject({ method: "POST", url: "/authorize", headers,
					payload: { ...payload, ...invalidFields } })).statusCode).toBe(400);
			}
			expect((await oidcApp.inject({ method: "POST", url: "/authorize", payload })).statusCode).toBe(401);
			const authorized = await oidcApp.inject({ method: "POST", url: "/authorize", headers, payload });
			expect(authorized.statusCode, authorized.body).toBe(200);
			const redirect = new URL(authorized.json().redirectUri);
			expect(redirect.searchParams.get("state")).toBe("h4-state");
			const replay = await oidcApp.inject({ method: "POST", url: "/authorize", headers, payload });
			expect(replay.statusCode).toBe(401);
			expect(providerMock.beginAsyncAuthentication).not.toHaveBeenCalled();
			const code = redirect.searchParams.get("code")!;
			const tokenResponse = await oidcApp.inject({ method: "POST", url: "/token", headers,
				payload: { grant_type: "authorization_code", code, redirect_uri: payload.redirect_uri, code_verifier: verifier } });
			expect(tokenResponse.statusCode).toBe(200);
			const tokens = tokenResponse.json();
			const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf8"));
			expect(claims).toMatchObject({ sub: subject.oidcSubject, email: subject.email, email_verified: true,
				amr: ["email"], auth_time: Math.floor(Date.parse(flow.result.authenticatedAt) / 1000) });
			const userinfo = await oidcApp.inject({ method: "GET", url: "/userinfo",
				headers: { authorization: `Bearer ${tokens.access_token}` } });
			expect(userinfo.json()).toMatchObject({ sub: subject.oidcSubject, email: subject.email, email_verified: true });
			expect((await oidcApp.inject({ method: "POST", url: "/token", headers,
				payload: { grant_type: "authorization_code", code, redirect_uri: payload.redirect_uri, code_verifier: verifier } })).statusCode).toBe(400);
			const second = await authenticated(subject.email!);
			const secondAuthorization = await oidcApp.inject({ method: "POST", url: "/authorize", headers,
				payload: { ...payload, authentication_result: second.result.authenticationResult } });
			expect(secondAuthorization.statusCode).toBe(200);
			const secondCode = new URL(secondAuthorization.json().redirectUri).searchParams.get("code")!;
			await pool.query("UPDATE identity_subjects SET status='DISABLED' WHERE id=$1", [subject.id]);
			const inactiveToken = await oidcApp.inject({ method: "POST", url: "/token", headers,
				payload: { grant_type: "authorization_code", code: secondCode, redirect_uri: payload.redirect_uri, code_verifier: verifier } });
			expect(inactiveToken.statusCode).toBe(400);
			expect(inactiveToken.json()).toEqual({ error: "invalid_grant" });
		} finally { lookup.mockRestore(); await oidcApp.close(); }
	});
});
