import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import Fastify from "fastify";
import IORedisModule from "ioredis";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import {
		ApplicationAccountLinkCeremony,
		ApplicationAccountLinkTransactionStore,
		ApplicationOwnershipProofRejected,
		APPLICATION_OWNERSHIP_PROOF_AUDIENCE,
		type ApplicationOwnershipProofVerifier,
		type VerifiedApplicationOwnershipProof
} from "../src/identity/ApplicationAccountLinkCeremony.js";
import { PostgresApplicationAccountLinks } from "../src/identity/ApplicationAccountLinks.js";
import { PostgresApplicationRepository } from "../src/identity/PostgresApplicationRepository.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { PostgresOIDCClientRepository } from "../src/identity/PostgresOIDCClientRepository.js";
import { PostgresTenantRepository } from "../src/identity/PostgresTenantRepository.js";
import { HapiSessionService, HAPI_SESSION_COOKIE } from "../src/identity/sessions/HapiSessionService.js";
import { InMemoryHapiSessionRepository } from "../src/identity/sessions/InMemoryHapiSessionRepository.js";
import { HAPI_CSRF_HEADER, registerAccountAuthenticationMethodRoutes } from "../src/routes/accountAuthenticationMethods.js";
import type { RedisClient } from "../src/oidc/infrastructure/RedisInfrastructure.js";

const databaseUrl = process.env.HAPI_STAGING_LINK_TEST_DATABASE_URL;
const redisUrl = process.env.HAPI_STAGING_LINK_TEST_REDIS_URL;
const schema = `stage_link_${randomUUID().replaceAll("-", "")}`;
const IORedis = IORedisModule as unknown as { new(url: string): RedisClient };

class StagingTestOwnershipProofVerifier implements ApplicationOwnershipProofVerifier {
	private readonly issued = new Map<string, VerifiedApplicationOwnershipProof>();

	issue(claims: VerifiedApplicationOwnershipProof): string {
		const proof = `test-only-${randomUUID()}`;
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

function assertLoopbackUrl(value: string, label: string): void {
	const hostname = new URL(value).hostname;
	if (!["localhost", "127.0.0.1", "::1", "[::1]"].includes(hostname)) {
		throw new Error(`${label} must point to a loopback-only disposable service`);
	}
}

describe.skipIf(!databaseUrl || !redisUrl)("HAPI_STAGING application-link acceptance (disposable integration)", () => {
	const admin = new pg.Pool({ connectionString: databaseUrl });
	const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}` });
	const redis = new IORedis(redisUrl!);
	const tenants = new PostgresTenantRepository(pool);
	const applications = new PostgresApplicationRepository(pool);
	const clients = new PostgresOIDCClientRepository(pool);
	const subjects = new PostgresIdentitySubjectRepository(pool);
	const links = new PostgresApplicationAccountLinks(pool);
	const tenantId = randomUUID();
	const applicationId = randomUUID();
	const clientId = "staging-web";
	const ownerSubjectId = randomUUID();
	const otherSubjectId = randomUUID();
	const ownerOidcSubject = randomUUID();
	let now = Date.now();
	const clock = () => new Date(now);
	const sessions = new HapiSessionService(new InMemoryHapiSessionRepository(), undefined, clock);
	const verifier = new StagingTestOwnershipProofVerifier();
	const transactions = new ApplicationAccountLinkTransactionStore(redis, () => now);
	const ceremony = new ApplicationAccountLinkCeremony(links, transactions, verifier, () => now);
	const app = Fastify();
	const identityDdl = readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8");
	const previousFeatureFlag = process.env.HAPI_ACCOUNT_LINKING_API_ENABLED;

	beforeAll(async () => {
		assertLoopbackUrl(databaseUrl!, "HAPI_STAGING_LINK_TEST_DATABASE_URL");
		assertLoopbackUrl(redisUrl!, "HAPI_STAGING_LINK_TEST_REDIS_URL");
		await redis.ping();
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(identityDdl);
		await tenants.upsert({ id: tenantId, name: "HAPI staging test tenant", slug: "hapi-staging", status: "active" });
		await applications.upsert({
			id: applicationId,
			tenantId,
			name: "HAPI_STAGING",
			slug: "hapi-staging-app",
			applicationKey: "HAPI_STAGING",
			status: "active",
			allowedAuthenticationMethods: ["HAPI_EMAIL", "EXTERNAL_OIDC"]
		});
		await clients.upsert({
			id: randomUUID(),
			applicationId,
			clientId,
			clientSecret: "disposable-stage-test-client-secret",
			redirectUris: ["https://staging-test.invalid/callback"],
			scopes: ["openid", "profile", "email"],
			grantTypes: ["authorization_code"],
			responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_basic",
			requirePkce: true
		});
		for (const [id, oidcSubject, email] of [
			[ownerSubjectId, ownerOidcSubject, `owner-${randomUUID()}@example.invalid`],
			[otherSubjectId, randomUUID(), `other-${randomUUID()}@example.invalid`]
		]) {
			await subjects.create({
				id,
				oidcSubject,
				applicationId,
				primaryProvider: "HAPI_EMAIL",
				primaryProviderSubject: email,
				email,
				emailVerified: true,
				status: "ACTIVE"
			});
		}
		process.env.HAPI_ACCOUNT_LINKING_API_ENABLED = "true";
		configuration.reload();
		await registerAccountAuthenticationMethodRoutes(app, { sessions, applicationAccountLinkCeremony: ceremony });
		await app.ready();
	});

	afterAll(async () => {
		if (previousFeatureFlag === undefined) delete process.env.HAPI_ACCOUNT_LINKING_API_ENABLED;
		else process.env.HAPI_ACCOUNT_LINKING_API_ENABLED = previousFeatureFlag;
		configuration.reload();
		await app.close();
		await redis.quit();
		await pool.end();
		await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
		await admin.end();
	});

	it("runs one consent-, session-, application-, and proof-bound association acceptance", async () => {
		const establish = (identitySubjectId: string, authenticatedAt?: string) =>
			sessions.establishSession({
				identitySubjectId,
				authenticationMethod: "HAPI_EMAIL",
				...(authenticatedAt ? { authenticatedAt } : {})
			});
		const fresh = await establish(ownerSubjectId);
		const other = await establish(otherSubjectId);
		const stale = await establish(ownerSubjectId, new Date(now - 600_001).toISOString());
		const headers = (session: typeof fresh) => ({
			cookie: `${HAPI_SESSION_COOKIE}=${session.sessionToken}`,
			[HAPI_CSRF_HEADER]: session.csrfToken
		});
		const payload = (consent = true) => ({ applicationId, clientId, consent });
		const start = (session: typeof fresh, consent = true) =>
			app.inject({ method: "POST", url: "/account/application-links/start", headers: headers(session), payload: payload(consent) });
		const complete = (session: typeof fresh, transactionId: string, proof: string) =>
			app.inject({
				method: "POST",
				url: "/account/application-links/complete",
				headers: headers(session),
				payload: { transactionId, ownershipProof: proof }
			});
		const issue = (input: {
			transactionId: string;
			nonce: string;
			externalAccountId: string;
			proofId?: string;
			applicationId?: string;
			clientId?: string;
			audience?: string;
			issuedAt?: number;
			expiresAt?: number;
		}) => verifier.issue({
			applicationId: input.applicationId ?? applicationId,
			clientId: input.clientId ?? clientId,
			externalAccountId: input.externalAccountId,
			audience: input.audience ?? APPLICATION_OWNERSHIP_PROOF_AUDIENCE,
			transactionId: input.transactionId,
			nonce: input.nonce,
			proofId: input.proofId ?? randomUUID(),
			issuedAt: input.issuedAt ?? now,
			expiresAt: input.expiresAt ?? now + 60_000
		});

		expect((await start(stale)).statusCode).toBe(428);
		expect((await start(fresh, false)).statusCode).toBe(400);
		expect((await app.inject({ method: "POST", url: "/account/application-links/start",
			headers: { cookie: headers(fresh).cookie }, payload: payload() })).statusCode).toBe(403);

		const started = await start(fresh);
		expect(started.statusCode, started.body).toBe(200);
		expect(started.json().audience).toBe(APPLICATION_OWNERSHIP_PROOF_AUDIENCE);
		const transactionId = started.json().transactionId as string;
		const transaction = await transactions.findById(transactionId);
		if (!transaction) throw new Error("Expected an active HAPI_STAGING link transaction");

		const validAccountId = `staging-test-${randomUUID()}`;
		const wrongSubjectProof = issue({ transactionId, nonce: transaction.nonce, externalAccountId: validAccountId });
		expect((await complete(other, transactionId, wrongSubjectProof)).statusCode).toBe(400);
		expect((await complete(fresh, transactionId, issue({
			transactionId,
			nonce: "wrong-nonce",
			externalAccountId: validAccountId
		}))).statusCode).toBe(400);
		expect((await complete(fresh, transactionId, issue({
			transactionId,
			nonce: transaction.nonce,
			externalAccountId: validAccountId,
			audience: "urn:wrong-audience"
		}))).statusCode).toBe(400);
		expect((await complete(fresh, transactionId, issue({
			transactionId,
			nonce: transaction.nonce,
			externalAccountId: validAccountId,
			applicationId: randomUUID()
		}))).statusCode).toBe(400);
		expect((await complete(fresh, transactionId, issue({
			transactionId,
			nonce: transaction.nonce,
			externalAccountId: validAccountId,
			clientId: "staging-native"
		}))).statusCode).toBe(400);
		expect((await complete(fresh, transactionId, issue({
			transactionId: randomUUID(),
			nonce: transaction.nonce,
			externalAccountId: validAccountId
		}))).statusCode).toBe(400);

		now += 60_001;
		expect((await complete(fresh, transactionId, issue({
			transactionId,
			nonce: transaction.nonce,
			externalAccountId: validAccountId,
			issuedAt: transaction.createdAt,
			expiresAt: transaction.createdAt + 60_000
		}))).statusCode).toBe(400);

		const prelinkedAccountId = `owned-by-other-${randomUUID()}`;
		await links.reconcile({
			identitySubjectId: otherSubjectId,
			applicationId,
			externalAccountId: prelinkedAccountId,
			evidence: {
				authority: "APPLICATION_OWNERSHIP_PROOF",
				clientId,
				requestId: randomUUID(),
				authenticationMethod: "HAPI_EMAIL"
			}
		});
		const wrongAccountTransaction = await start(fresh);
		const wrongAccountId = wrongAccountTransaction.json().transactionId as string;
		const wrongAccountState = await transactions.findById(wrongAccountId);
		if (!wrongAccountState) throw new Error("Expected a second HAPI_STAGING link transaction");
		expect((await complete(fresh, wrongAccountId, issue({
			transactionId: wrongAccountId,
			nonce: wrongAccountState.nonce,
			externalAccountId: prelinkedAccountId
		}))).statusCode).toBe(409);
		expect(await links.find(applicationId, prelinkedAccountId)).toMatchObject({ identitySubjectId: otherSubjectId });

		const validProofId = randomUUID();
		const acceptedProof = issue({
			transactionId,
			nonce: transaction.nonce,
			externalAccountId: validAccountId,
			proofId: validProofId
		});
		const accepted = await complete(fresh, transactionId, acceptedProof);
		expect(accepted.statusCode, accepted.body).toBe(200);
		expect(accepted.json()).toMatchObject({
			created: true,
			link: { identitySubjectId: ownerSubjectId, applicationId, externalAccountId: validAccountId }
		});
		expect(await pool.query(
			"SELECT authority, client_id, request_id, authentication_method, result FROM application_account_link_audit WHERE external_account_id=$1",
			[validAccountId]
		)).toMatchObject({
			rows: [{
				authority: "APPLICATION_OWNERSHIP_PROOF",
				client_id: clientId,
				request_id: transactionId,
				authentication_method: "HAPI_EMAIL",
				result: "created"
			}]
		});
		expect((await complete(fresh, transactionId, acceptedProof)).statusCode).toBe(400);

		const replayTransaction = await start(fresh);
		const replayTransactionId = replayTransaction.json().transactionId as string;
		const replayState = await transactions.findById(replayTransactionId);
		if (!replayState) throw new Error("Expected replay test transaction");
		const replayOnlyAccountId = `must-not-link-${randomUUID()}`;
		const reusedProofId = issue({
			transactionId: replayTransactionId,
			nonce: replayState.nonce,
			externalAccountId: replayOnlyAccountId,
			proofId: validProofId
		});
		expect((await complete(fresh, replayTransactionId, reusedProofId)).statusCode).toBe(400);
		expect(await links.find(applicationId, replayOnlyAccountId)).toBeUndefined();

		const repeatTransaction = await start(fresh);
		const repeatTransactionId = repeatTransaction.json().transactionId as string;
		const repeatState = await transactions.findById(repeatTransactionId);
		if (!repeatState) throw new Error("Expected repeat-link transaction");
		const repeated = await complete(fresh, repeatTransactionId, issue({
			transactionId: repeatTransactionId,
			nonce: repeatState.nonce,
			externalAccountId: validAccountId
		}));
		expect(repeated.statusCode, repeated.body).toBe(200);
		expect(repeated.json().created).toBe(false);
		expect(repeated.json().link.id).toBe(accepted.json().link.id);
		expect((await subjects.findById(ownerSubjectId))?.oidcSubject).toBe(ownerOidcSubject);
	});
});
