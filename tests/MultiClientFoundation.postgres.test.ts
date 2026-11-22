import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import Fastify from "fastify";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PostgresApplicationRepository } from "../src/identity/PostgresApplicationRepository.js";
import { PostgresOIDCClientRepository } from "../src/identity/PostgresOIDCClientRepository.js";
import { PostgresTenantRepository } from "../src/identity/PostgresTenantRepository.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { PostgresApplicationAccountLinks, ApplicationAccountLinkConflict } from "../src/identity/ApplicationAccountLinks.js";
import {
	ApplicationAccountLinkCeremony,
	ApplicationAccountLinkTransactionStore,
	ApplicationOwnershipProofRejected,
	APPLICATION_OWNERSHIP_PROOF_AUDIENCE,
	type ApplicationOwnershipProofVerifier,
	type VerifiedApplicationOwnershipProof
} from "../src/identity/ApplicationAccountLinkCeremony.js";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { PostgresEmailAuthenticationRepository } from "../src/authentication/email/PostgresEmailAuthenticationRepository.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { authorizeH1Client, resolveH1ClientAuthority } from "../src/identity/H1ClientAuthority.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { ensureOidcTestEnvironment, pkceChallengeFromVerifier } from "./oidcTestHarness.js";
import type { AuthenticationProvider } from "../src/authentication/AuthenticationProvider.js";
import { ensureBookwrmApplicationSeed } from "../src/adapters/base44/Base44ApplicationSeed.js";
import { BOOKWRM_APPLICATION_ID } from "../src/identity/WellKnownIdentities.js";
import { configuration } from "../src/config/ConfigurationService.js";

const databaseUrl = process.env.HAPI_AUTHENTICATION_TEST_DATABASE_URL;
const schema = "p4_" + randomUUID().replaceAll("-", "");

class PostgresTestOwnershipProofVerifier implements ApplicationOwnershipProofVerifier {
	private readonly issued = new Map<string, VerifiedApplicationOwnershipProof>();
	issue(claims: VerifiedApplicationOwnershipProof): string {
		const proof = randomUUID();
		this.issued.set(proof, claims);
		return proof;
	}
	async verify(proof: string, expected: { applicationId: string; clientId: string }) {
		const claims = this.issued.get(proof);
		if (!claims || claims.applicationId !== expected.applicationId || claims.clientId !== expected.clientId) {
			throw new ApplicationOwnershipProofRejected();
		}
		return claims;
	}
}

describe.skipIf(!databaseUrl)("Phase 4 durable multi-client identity and link invariants", () => {
	const admin = new pg.Pool({ connectionString: databaseUrl });
	const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}` });
	const applications = new PostgresApplicationRepository(pool), clients = new PostgresOIDCClientRepository(pool);
	const tenants = new PostgresTenantRepository(pool), subjects = new PostgresIdentitySubjectRepository(pool);
	const authority = { applications, clients, tenants }, tenantId = randomUUID();
	const bookwrm = randomUUID(), elite = randomUUID(), subjectId = randomUUID(), otherSubjectId = randomUUID();
	const challenges = new PostgresVerificationChallengeRepository(pool);
	const delivery = new InMemoryEmailDeliveryProvider();
	const verification = new EmailVerificationService(challenges, delivery,
		new VerificationSecrets("multi-client-fixture-secret".repeat(3)), defaultVerificationPolicy);
	const authenticationRepository = new PostgresEmailAuthenticationRepository(pool);
	const authentication = new EmailAuthenticationService(verification, challenges, authenticationRepository);
	const links = new PostgresApplicationAccountLinks(pool);
	const email = `${randomUUID()}@example.com`, oidcSubject = randomUUID();
	const app = Fastify();
	const createLinkSubject = async () => {
		const id = randomUUID(), subjectEmail = `${randomUUID()}@example.com`;
		await subjects.create({ id, oidcSubject: randomUUID(), applicationId: bookwrm,
			primaryProvider: "HAPI_EMAIL", primaryProviderSubject: subjectEmail,
			email: subjectEmail, emailVerified: true, status: "ACTIVE" });
		return id;
	};
	const provider: AuthenticationProvider = {
		authenticate: vi.fn(async () => { throw new Error("Provider must not run"); }),
		cancel: vi.fn(async () => {}), logout: vi.fn(async () => {}), status: vi.fn(async () => ({ state: "idle" as const }))
	};
	let lookup: ReturnType<typeof vi.spyOn>;
	const ddl = readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8");

	beforeAll(async () => {
		ensureOidcTestEnvironment();
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(ddl);
		await pool.query(ddl);
		await challenges.ensureSchema();
		await authenticationRepository.ensureSchema();
		await tenants.upsert({ id: tenantId, name: "Synthetic", slug: tenantId, status: "active" });
		for (const [id, key] of [[bookwrm, "BOOKWRM_TEST"], [elite, "ELITE_TEST"]]) {
			await applications.upsert({ id, tenantId, name: key, slug: key, applicationKey: key, status: "active",
				allowedAuthenticationMethods: ["HAPI_EMAIL"] });
			await clients.upsert({ id: randomUUID(), applicationId: id, clientId: key, clientSecret: "test-secret",
				redirectUris: ["https://rp.example/callback"], scopes: ["openid", "email"], grantTypes: ["authorization_code"],
				responseTypes: ["code"], tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
		}
		for (const [id, providerSubject] of [[subjectId, email], [otherSubjectId, `other-${email}`]]) {
			await subjects.create({ id, oidcSubject: id === subjectId ? oidcSubject : randomUUID(), applicationId: bookwrm,
				primaryProvider: "HAPI_EMAIL", primaryProviderSubject: providerSubject, email: providerSubject,
				emailVerified: true, status: "ACTIVE" });
		}
		lookup = vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
		const oidc = new OIDCService({ authenticationProvider: provider, oidcClients: clients, clientAuthority: authority });
		oidc.configureEmailAuthentication({
			async consume(request, result, clientId) {
				const authorized = await authorizeH1Client(request, authority);
				if (authorized.clientId !== clientId) throw new Error("Client mismatch");
				return authentication.consumeResult(authorized, result);
			}
		});
		await oidc.registerEndpoints(app);
	});
	afterAll(async () => {
		lookup?.mockRestore();
		await app.close();
		await pool.end();
		await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
		await admin.end();
	});

	it("authenticates the same canonical person through both clients with separate OTP proofs, codes and tokens", async () => {
		const before = (await pool.query("SELECT count(*)::int AS n FROM identity_subjects")).rows[0].n;
		for (const clientId of ["BOOKWRM_TEST", "ELITE_TEST"]) {
			const authorized = await resolveH1ClientAuthority(clientId, authority);
			const flow = await authentication.start(authorized, email);
			const result = await authentication.verify(authorized, flow.challengeId, delivery.messages.at(-1)!.code);
			const verifier = "v".repeat(43), headers = { authorization: "Basic " + Buffer.from(`${clientId}:test-secret`).toString("base64") };
			const authorizedResponse = await app.inject({ method: "POST", url: "/authorize", headers, payload: {
				client_id: clientId, redirect_uri: "https://rp.example/callback", response_type: "code",
				scope: "openid email", nonce: "test-nonce", code_challenge: pkceChallengeFromVerifier(verifier),
				code_challenge_method: "S256", authentication_result: result.authenticationResult
			} });
			expect(authorizedResponse.statusCode, authorizedResponse.body).toBe(200);
			const code = new URL(authorizedResponse.json().redirectUri).searchParams.get("code");
			const token = await app.inject({ method: "POST", url: "/token", headers, payload: {
				grant_type: "authorization_code", code, redirect_uri: "https://rp.example/callback", code_verifier: verifier
			} });
			expect(token.statusCode, token.body).toBe(200);
			const claims = JSON.parse(Buffer.from(token.json().id_token.split(".")[1], "base64url").toString());
			expect(claims.sub).toBe(oidcSubject);
			expect(claims.aud).toBe(clientId);
			for (const field of ["roles", "membership", "entitlements"]) expect(claims).not.toHaveProperty(field);
			expect((await pool.query("SELECT count(*)::int AS n FROM identity_subjects")).rows[0].n).toBe(before);
		}
		expect((await subjects.findById(subjectId))?.applicationId).toBe(bookwrm);
	});
	it("persists independent links, audits results and enforces both uniqueness constraints under concurrency", async () => {
		const evidence = { authority: "OIDC_CONTINUITY" as const, clientId: "BOOKWRM_TEST",
			requestId: randomUUID(), authenticationMethod: "HAPI_EMAIL" as const };
		const input = { identitySubjectId: subjectId, applicationId: bookwrm, externalAccountId: "BW-1", evidence };
		const races = await Promise.all(Array.from({ length: 8 }, () => links.reconcile(input)));
		expect(races.filter(result => result.created)).toHaveLength(1);
		expect(new Set(races.map(result => result.link.id)).size).toBe(1);
		await links.reconcile({ ...input, applicationId: elite, externalAccountId: "EL-1",
			evidence: { ...evidence, clientId: "ELITE_TEST" } });
		await expect(links.reconcile({ ...input, applicationId: elite, externalAccountId: "EL-1",
			identitySubjectId: otherSubjectId, evidence: { ...evidence, clientId: "ELITE_TEST" } })).rejects.toBeInstanceOf(ApplicationAccountLinkConflict);
		await expect(links.reconcile({ ...input, externalAccountId: "BW-2" })).rejects.toBeInstanceOf(ApplicationAccountLinkConflict);
		await expect(links.reconcile({ ...input, applicationId: elite })).rejects.toThrow("authority");
		expect((await pool.query("SELECT count(*)::int AS n FROM application_account_links")).rows[0].n).toBe(2);
		expect((await pool.query("SELECT count(*)::int AS n FROM application_account_link_audit WHERE result='conflict'")).rows[0].n).toBe(2);
	});
	it("persists a proof-bound application association and rejects cross-application authority", async () => {
		const verifier = new PostgresTestOwnershipProofVerifier();
		const ceremony = new ApplicationAccountLinkCeremony(links, new ApplicationAccountLinkTransactionStore(), verifier);
		const linkSubjectId = await createLinkSubject();
		const sessionId = randomUUID();
		const started = await ceremony.start({ identitySubjectId: linkSubjectId, sessionId,
			authenticationMethod: "HAPI_EMAIL", applicationId: bookwrm, clientId: "BOOKWRM_TEST", consent: true });
		const issuedAt = Date.now();
		const proof = verifier.issue({ applicationId: bookwrm, clientId: "BOOKWRM_TEST",
			externalAccountId: "proof-owned-account", audience: APPLICATION_OWNERSHIP_PROOF_AUDIENCE,
			transactionId: started.id, nonce: started.nonce, proofId: randomUUID(), issuedAt,
			expiresAt: issuedAt + 60_000 });
		const result = await ceremony.complete({ identitySubjectId: linkSubjectId, sessionId,
			authenticationMethod: "HAPI_EMAIL", transactionId: started.id, ownershipProof: proof });
		expect(result.created).toBe(true);
		expect(result.link).toMatchObject({ identitySubjectId: linkSubjectId, applicationId: bookwrm,
			externalAccountId: "proof-owned-account" });
		expect((await pool.query(
			"SELECT authority, client_id, request_id, authentication_method, result FROM application_account_link_audit WHERE external_account_id=$1",
			["proof-owned-account"])).rows).toEqual([{
				authority: "APPLICATION_OWNERSHIP_PROOF", client_id: "BOOKWRM_TEST",
				request_id: started.id, authentication_method: "HAPI_EMAIL", result: "created"
			}]);

		const tenant2 = randomUUID(), app2 = randomUUID(), otherClientId = `OTHER_${randomUUID()}`;
		await tenants.upsert({ id: tenant2, name: "Other", slug: tenant2, status: "active" });
		await applications.upsert({ id: app2, tenantId: tenant2, name: "Other", slug: app2,
			applicationKey: app2, status: "active", allowedAuthenticationMethods: ["HAPI_EMAIL"] });
		await clients.upsert({ id: randomUUID(), applicationId: app2, clientId: otherClientId,
			clientSecret: "test-secret", redirectUris: ["https://rp.example/callback"],
			scopes: ["openid"], grantTypes: ["authorization_code"], responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_basic", requirePkce: true });
		await expect(ceremony.start({ identitySubjectId: linkSubjectId, sessionId,
			authenticationMethod: "HAPI_EMAIL", applicationId: bookwrm, clientId: otherClientId, consent: true }))
			.rejects.toMatchObject({ code: "APPLICATION_UNAUTHORIZED" });
	});

	it("rejects cross-account claims and rolls back a link if its audit write fails", async () => {
		const verifier = new PostgresTestOwnershipProofVerifier();
		const ceremony = new ApplicationAccountLinkCeremony(links, new ApplicationAccountLinkTransactionStore(), verifier);
		const ownerSubjectId = await createLinkSubject();
		const attackerSubjectId = await createLinkSubject();
		const sessionId = randomUUID();
		const startFor = async (identitySubjectId: string, externalAccountId: string) => {
			const transaction = await ceremony.start({ identitySubjectId, sessionId,
				authenticationMethod: "HAPI_EMAIL", applicationId: bookwrm, clientId: "BOOKWRM_TEST", consent: true });
			const issuedAt = Date.now();
			return {
				transaction,
				proof: verifier.issue({ applicationId: bookwrm, clientId: "BOOKWRM_TEST", externalAccountId,
					audience: APPLICATION_OWNERSHIP_PROOF_AUDIENCE, transactionId: transaction.id,
					nonce: transaction.nonce, proofId: randomUUID(), issuedAt, expiresAt: issuedAt + 60_000 })
			};
		};
		const owner = await startFor(ownerSubjectId, "cross-account-owned");
		await ceremony.complete({ identitySubjectId: ownerSubjectId, sessionId, authenticationMethod: "HAPI_EMAIL",
			transactionId: owner.transaction.id, ownershipProof: owner.proof });
		const attacker = await startFor(attackerSubjectId, "cross-account-owned");
		await expect(ceremony.complete({ identitySubjectId: attackerSubjectId, sessionId,
			authenticationMethod: "HAPI_EMAIL", transactionId: attacker.transaction.id,
			ownershipProof: attacker.proof })).rejects.toMatchObject({ code: "LINK_CONFLICT" });
		expect(await links.find(bookwrm, "cross-account-owned")).toMatchObject({ identitySubjectId: ownerSubjectId });

		const failureSubjectId = await createLinkSubject();
		const externalAccountId = `write-failure-${randomUUID()}`;
		const suffix = randomUUID().replaceAll("-", "");
		const functionName = `hapi_fail_app_link_audit_${suffix}`;
		const triggerName = `hapi_fail_app_link_audit_${suffix}`;
		await pool.query(`CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.external_account_id = '${externalAccountId}' THEN
					RAISE EXCEPTION 'synthetic account-link audit failure';
				END IF;
				RETURN NEW;
			END
		$$`);
		await pool.query(`CREATE TRIGGER ${triggerName} BEFORE INSERT ON application_account_link_audit
			FOR EACH ROW EXECUTE FUNCTION ${functionName}()`);
		const failed = await startFor(failureSubjectId, externalAccountId);
		try {
			await expect(ceremony.complete({ identitySubjectId: failureSubjectId, sessionId,
				authenticationMethod: "HAPI_EMAIL", transactionId: failed.transaction.id,
				ownershipProof: failed.proof })).rejects.toThrow("synthetic account-link audit failure");
		} finally {
			await pool.query(`DROP TRIGGER IF EXISTS ${triggerName} ON application_account_link_audit`);
			await pool.query(`DROP FUNCTION IF EXISTS ${functionName}()`);
		}
		expect(await links.find(bookwrm, externalAccountId)).toBeUndefined();
		expect((await pool.query("SELECT id FROM application_account_link_audit WHERE external_account_id=$1",
			[externalAccountId])).rows).toHaveLength(0);
	});

	it("keeps schema migration idempotent and preserves canonical identities and link meaning", async () => {
		const before = (await pool.query("SELECT * FROM identity_subjects ORDER BY id")).rows;
		const linkRows = (await pool.query("SELECT * FROM application_account_links ORDER BY id")).rows;
		await pool.query(ddl);
		await pool.query(ddl);
		expect((await pool.query("SELECT * FROM identity_subjects ORDER BY id")).rows).toEqual(before);
		expect((await pool.query("SELECT * FROM application_account_links ORDER BY id")).rows).toEqual(linkRows);
	});
	it("deterministically copies only existing Bookwrm relationships and bridges future legacy writes", async () => {
		const previousDriver = process.env.IDENTITY_REGISTRY_DRIVER;
		process.env.IDENTITY_REGISTRY_DRIVER = "postgres"; configuration.reload();
		try {
			const deps = { applications, tenants, oidcClients: clients, postgresClient: pool };
			await ensureBookwrmApplicationSeed(deps);
			const id = randomUUID(), external = "legacy-" + randomUUID();
			await pool.query("ALTER TABLE identity_account_links DISABLE TRIGGER USER");
			try {
				await pool.query(`INSERT INTO identity_account_links VALUES ($1,'bookwrm',$2,$3,'active',NOW(),NOW())`,
					[id, external, subjectId]);
			} finally { await pool.query("ALTER TABLE identity_account_links ENABLE TRIGGER USER"); }
			const legacyBefore = (await pool.query("SELECT * FROM identity_account_links ORDER BY id")).rows;
			const canonicalBefore = (await pool.query("SELECT * FROM identity_subjects ORDER BY id")).rows;
			await ensureBookwrmApplicationSeed(deps);
			await ensureBookwrmApplicationSeed(deps);
			const migrated = await links.find(BOOKWRM_APPLICATION_ID, external);
			expect(migrated).toMatchObject({ id, identitySubjectId: subjectId, externalAccountId: external });
			expect((await pool.query("SELECT * FROM identity_account_links ORDER BY id")).rows).toEqual(legacyBefore);
			expect((await pool.query("SELECT * FROM identity_subjects ORDER BY id")).rows).toEqual(canonicalBefore);
			expect((await pool.query("SELECT count(*)::int AS n FROM application_account_link_audit WHERE id=$1", [id])).rows[0].n).toBe(1);
			const futureId = randomUUID(), futureAccount = "future-" + randomUUID();
			await pool.query(`INSERT INTO identity_account_links VALUES ($1,'bookwrm',$2,$3,'active',NOW(),NOW())`,
				[futureId, futureAccount, otherSubjectId]);
			expect(await links.find(BOOKWRM_APPLICATION_ID, futureAccount)).toMatchObject({ identitySubjectId: otherSubjectId });
			await expect(pool.query(`INSERT INTO identity_account_links VALUES ($1,'bookwrm',$2,$3,'active',NOW(),NOW())`,
				[randomUUID(), "second-account", otherSubjectId])).rejects.toMatchObject({ code: "23505" });
			expect((await pool.query("SELECT * FROM identity_account_links WHERE external_user_id='second-account'")).rows).toHaveLength(0);
		} finally {
			if (previousDriver === undefined) delete process.env.IDENTITY_REGISTRY_DRIVER;
			else process.env.IDENTITY_REGISTRY_DRIVER = previousDriver;
			configuration.reload();
		}
	});
});
