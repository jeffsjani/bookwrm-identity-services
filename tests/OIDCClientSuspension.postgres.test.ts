import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { featureFlags } from "../src/config/FeatureFlagService.js";
import { EmailAuthenticationService } from "../src/authentication/email/EmailAuthenticationService.js";
import type { AuthenticationProvider } from "../src/authentication/AuthenticationProvider.js";
import { PostgresEmailAuthenticationRepository } from "../src/authentication/email/PostgresEmailAuthenticationRepository.js";
import { InMemoryEmailDeliveryProvider } from "../src/email/EmailDeliveryProvider.js";
import { EmailVerificationService } from "../src/email/EmailVerificationService.js";
import { defaultVerificationPolicy } from "../src/email/VerificationPolicy.js";
import { VerificationSecrets } from "../src/email/VerificationSecrets.js";
import { PostgresVerificationChallengeRepository } from "../src/adapters/email/PostgresVerificationChallengeRepository.js";
import { PostgresApplicationRepository } from "../src/identity/PostgresApplicationRepository.js";
import { PostgresOIDCClientRepository } from "../src/identity/PostgresOIDCClientRepository.js";
import { PostgresTenantRepository } from "../src/identity/PostgresTenantRepository.js";
import { PostgresIdentitySubjectRepository } from "../src/identity/PostgresIdentitySubjectRepository.js";
import { authorizeH1Client, resolveH1ClientAuthority } from "../src/identity/H1ClientAuthority.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { PostgresRefreshTokenFamilyRepository } from "../src/oidc/refresh/PostgresRefreshTokenFamilyRepository.js";
import { RefreshTokenRotationService } from "../src/oidc/refresh/RefreshTokenRotationService.js";
import { DependencyHealthMonitor } from "../src/infrastructure/DependencyHealthMonitor.js";
import { registerHealthRoutes } from "../src/routes/health.js";
import { registerRegistrationRoutes } from "../src/routes/registration.js";
import { RegistrationService } from "../src/registration/RegistrationService.js";
import { PostgresRegistrationRepository } from "../src/registration/PostgresRegistrationRepository.js";
import { ensureOidcTestEnvironment, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

const databaseUrl = process.env.HAPI_AUTHENTICATION_TEST_DATABASE_URL;
const schema = `suspension_${randomUUID().replaceAll("-", "")}`;

describe.skipIf(!databaseUrl)("OIDC client suspension with disposable PostgreSQL", () => {
	const admin = new pg.Pool({ connectionString: databaseUrl });
	const pool = new pg.Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}` });
	const tenants = new PostgresTenantRepository(pool);
	const applications = new PostgresApplicationRepository(pool);
	const clients = new PostgresOIDCClientRepository(pool);
	const subjects = new PostgresIdentitySubjectRepository(pool);
	const authority = { clients, applications, tenants };
	const tenantId = randomUUID();
	const pilotApplicationId = randomUUID();
	const unrelatedApplicationId = randomUUID();
	const pilotClientId = `PILOT_${randomUUID()}`;
	const unrelatedClientId = `ACTIVE_${randomUUID()}`;
	const email = `${randomUUID()}@example.com`;
	const subjectId = randomUUID();
	const challengeRepository = new PostgresVerificationChallengeRepository(pool);
	const emailAuthenticationRepository = new PostgresEmailAuthenticationRepository(pool);
	const delivery = new InMemoryEmailDeliveryProvider();
	const verification = new EmailVerificationService(
		challengeRepository,
		delivery,
		new VerificationSecrets("synthetic-suspension-test-secret".repeat(3)),
		defaultVerificationPolicy
	);
	const authentication = new EmailAuthenticationService(verification, challengeRepository, emailAuthenticationRepository);
	const provider: AuthenticationProvider = {
		authenticate: vi.fn(async () => { throw new Error("Provider must not run"); }),
		cancel: vi.fn(async () => {}),
		logout: vi.fn(async () => {}),
		status: vi.fn(async () => ({ state: "idle" as const }))
	};
	const app = Fastify();
	let oidc: OIDCService;
	let findByOidcSubject: ReturnType<typeof vi.spyOn>;
	let findById: ReturnType<typeof vi.spyOn>;
	const schemaDdl = readFileSync(new URL("../src/identity/schema.sql", import.meta.url), "utf8");
	const sessionDdl = readFileSync(new URL("../src/identity/schema-sessions.sql", import.meta.url), "utf8");
	const refreshDdl = readFileSync(new URL("../src/identity/schema-refresh.sql", import.meta.url), "utf8");

	beforeAll(async () => {
		ensureOidcTestEnvironment();
		process.env.HAPI_REFRESH_GRANT_ENABLED = "true";
		configuration.reload();
		await admin.query(`CREATE SCHEMA ${schema}`);
		await pool.query(schemaDdl);
		await pool.query(sessionDdl);
		await pool.query(refreshDdl);
		await challengeRepository.ensureSchema();
		await emailAuthenticationRepository.ensureSchema();
		const registrationRepository = new PostgresRegistrationRepository(pool);
		await registrationRepository.ensureSchema();
		await tenants.upsert({ id: tenantId, name: "Synthetic", slug: tenantId, status: "active" });
		for (const [id, key] of [[pilotApplicationId, "PILOT_TEST"], [unrelatedApplicationId, "ACTIVE_TEST"]]) {
			await applications.upsert({
				id,
				tenantId,
				name: key,
				slug: key,
				applicationKey: key,
				status: "active",
				allowedAuthenticationMethods: ["HAPI_EMAIL"]
			});
		}
		await clients.upsert({
			id: randomUUID(),
			applicationId: pilotApplicationId,
			clientId: pilotClientId,
			clientSecret: "synthetic-pilot-secret",
			redirectUris: ["https://rp.example/callback"],
			scopes: ["openid", "email"],
			grantTypes: ["authorization_code", "refresh_token"],
			responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_basic",
			requirePkce: true
		});
		await clients.upsert({
			id: randomUUID(),
			applicationId: unrelatedApplicationId,
			clientId: unrelatedClientId,
			clientSecret: "synthetic-active-secret",
			redirectUris: ["https://rp.example/callback"],
			scopes: ["openid", "email"],
			grantTypes: ["authorization_code", "refresh_token"],
			responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_basic",
			requirePkce: true
		});
		await subjects.create({
			id: subjectId,
			oidcSubject: randomUUID(),
			applicationId: pilotApplicationId,
			primaryProvider: "HAPI_EMAIL",
			primaryProviderSubject: email,
			email,
			emailVerified: true,
			status: "ACTIVE"
		});
		findByOidcSubject = vi.spyOn(identityRegistry, "findByOidcSubject").mockImplementation(sub => subjects.findByOidcSubject(sub));
		findById = vi.spyOn(identityRegistry, "findById").mockImplementation(id => subjects.findById(id));

		oidc = new OIDCService({
			authenticationProvider: provider,
			oidcClients: clients,
			clientAuthority: authority,
			refreshTokenRotation: new RefreshTokenRotationService(new PostgresRefreshTokenFamilyRepository(pool))
		});
		oidc.configureEmailAuthentication({
			async consume(request, result, clientId) {
				const authorized = await authorizeH1Client(request, authority);
				if (authorized.clientId !== clientId) throw new Error("Client mismatch");
				return authentication.consumeResult(authorized, result);
			}
		});
		await app.register(formbody);
		await oidc.registerEndpoints(app);
		await registerRegistrationRoutes(app, new RegistrationService(registrationRepository), authority);
		await registerHealthRoutes(app, {
			configurationLoaded: () => Boolean(configuration.getEnvironment()),
			redisRequired: () => featureFlags.isRedisEnabled(),
			pingRedis: async () => true,
			pingDatabase: async () => { await pool.query("SELECT 1"); return true; },
			signingKeysLoaded: () => oidc.hasSigningKeysAvailable(),
			providerReady: () => oidc.isProviderReady(),
			base44: new DependencyHealthMonitor({ name: "synthetic-base44", probe: async () => {} })
		});
		await app.ready();
	});

	afterAll(async () => {
		findByOidcSubject?.mockRestore();
		findById?.mockRestore();
		await app.close();
		await pool.end();
		await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
		await admin.end();
		delete process.env.HAPI_REFRESH_GRANT_ENABLED;
		configuration.reload();
	});

	async function issueCode(clientId: string, secret: string): Promise<{ code: string; verifier: string }> {
		const authorized = await resolveH1ClientAuthority(clientId, authority);
		const flow = await authentication.start(authorized, email);
		const result = await authentication.verify(authorized, flow.challengeId, delivery.messages.at(-1)!.code);
		const verifier = `synthetic-pg-verifier-${randomUUID()}`;
		const response = await app.inject({
			method: "POST",
			url: "/authorize",
			headers: { authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}` },
			payload: {
				client_id: clientId,
				redirect_uri: "https://rp.example/callback",
				response_type: "code",
				scope: "openid email",
				nonce: randomUUID(),
				code_challenge: pkceChallengeFromVerifier(verifier),
				code_challenge_method: "S256",
				authentication_result: result.authenticationResult
			}
		});
		expect(response.statusCode, response.body).toBe(200);
		const code = new URL(response.json().redirectUri).searchParams.get("code");
		if (!code) throw new Error("Authorization response omitted code");
		return { code, verifier };
	}

	async function exchangeCode(clientId: string, secret: string, code: string, verifier: string) {
		return app.inject({
			method: "POST",
			url: "/token",
			headers: {
				authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`,
				"content-type": "application/x-www-form-urlencoded"
			},
			payload: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://rp.example/callback",
				code_verifier: verifier
			}).toString()
		});
	}

	it("enforces suspension immediately across OAuth paths without affecting readiness or another active client", async () => {
		expect((await resolveH1ClientAuthority(pilotClientId, authority)).clientId).toBe(pilotClientId);
		const alreadyIssued = await issueCode(pilotClientId, "synthetic-pilot-secret");
		const issued = await exchangeCode(pilotClientId, "synthetic-pilot-secret", alreadyIssued.code, alreadyIssued.verifier);
		expect(issued.statusCode, issued.body).toBe(200);
		const issuedTokens = issued.json() as { access_token: string; refresh_token: string };
		expect(issuedTokens.refresh_token).toBeTruthy();
		const activeRefresh = await app.inject({
			method: "POST",
			url: "/token",
			headers: {
				authorization: `Basic ${Buffer.from(`${pilotClientId}:synthetic-pilot-secret`).toString("base64")}`,
				"content-type": "application/x-www-form-urlencoded"
			},
			payload: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: issuedTokens.refresh_token
			}).toString()
		});
		expect(activeRefresh.statusCode, activeRefresh.body).toBe(200);
		const refreshTokenToReject = activeRefresh.json().refresh_token as string;

		const pending = await issueCode(pilotClientId, "synthetic-pilot-secret");
		const activeUserInfo = await app.inject({
			method: "GET",
			url: "/userinfo",
			headers: { authorization: `Bearer ${issuedTokens.access_token}` }
		});
		expect(activeUserInfo.statusCode).toBe(200);

		await pool.query("UPDATE oidc_clients SET status='suspended' WHERE client_id=$1", [pilotClientId]);

		const query = new URLSearchParams({
			response_type: "code",
			client_id: pilotClientId,
			redirect_uri: "https://rp.example/callback",
			scope: "openid email",
			state: "suspension-test",
			nonce: "suspension-test",
			code_challenge_method: "S256",
			code_challenge: pkceChallengeFromVerifier("synthetic-pg-new-flow-verifier")
		});
		const authorization = await app.inject({ method: "GET", url: `/authorize?${query}` });
		expect(authorization.statusCode).toBe(400);
		expect(authorization.json()).toMatchObject({ error: "invalid_client" });

		await expect(resolveH1ClientAuthority(pilotClientId, authority)).rejects.toMatchObject({ statusCode: 401 });
		await expect(authorizeH1Client(
			{ headers: { authorization: `Basic ${Buffer.from(`${pilotClientId}:synthetic-pilot-secret`).toString("base64")}` } } as import("fastify").FastifyRequest,
			authority
		)).rejects.toMatchObject({ statusCode: 401 });
		const suspendedRegistration = await app.inject({
			method: "POST", url: "/v1/registration/complete",
			headers: { authorization: `Basic ${Buffer.from(`${pilotClientId}:synthetic-pilot-secret`).toString("base64")}` },
			payload: { verificationId: randomUUID() }
		});
		expect(suspendedRegistration.statusCode).toBe(401);

		const codeExchange = await exchangeCode(pilotClientId, "synthetic-pilot-secret", pending.code, pending.verifier);
		expect(codeExchange.statusCode).toBe(400);
		expect(codeExchange.json()).toMatchObject({ error: "invalid_client" });

		const refresh = await app.inject({
			method: "POST",
			url: "/token",
			headers: {
				authorization: `Basic ${Buffer.from(`${pilotClientId}:synthetic-pilot-secret`).toString("base64")}`,
				"content-type": "application/x-www-form-urlencoded"
			},
			payload: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshTokenToReject
			}).toString()
		});
		expect(refresh.statusCode).toBe(400);
		expect(refresh.json()).toMatchObject({ error: "invalid_client" });

		const userInfo = await app.inject({
			method: "GET",
			url: "/userinfo",
			headers: { authorization: `Bearer ${issuedTokens.access_token}` }
		});
		expect(userInfo.statusCode).toBe(401);
		expect(userInfo.json()).toMatchObject({ error: "invalid_token" });
		expect((await app.inject({ method: "GET", url: "/health/ready" })).statusCode).toBe(200);

		const unrelated = await issueCode(unrelatedClientId, "synthetic-active-secret");
		const unrelatedToken = await exchangeCode(
			unrelatedClientId, "synthetic-active-secret", unrelated.code, unrelated.verifier
		);
		expect(unrelatedToken.statusCode, unrelatedToken.body).toBe(200);
		const unrelatedUserInfo = await app.inject({
			method: "GET",
			url: "/userinfo",
			headers: { authorization: `Bearer ${unrelatedToken.json().access_token}` }
		});
		expect(unrelatedUserInfo.statusCode).toBe(200);
	});

	it("blocks a client across OAuth and registration, including previously issued credentials", async () => {
		await pool.query("UPDATE oidc_clients SET status='active' WHERE client_id=$1", [pilotClientId]);
		const issued = await issueCode(pilotClientId, "synthetic-pilot-secret");
		const token = await exchangeCode(pilotClientId, "synthetic-pilot-secret", issued.code, issued.verifier);
		expect(token.statusCode).toBe(200);
		const pending = await issueCode(pilotClientId, "synthetic-pilot-secret");
		const previous = process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS;
		try {
			process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS = pilotClientId;
			configuration.reload();
			const query = new URLSearchParams({
				response_type: "code", client_id: pilotClientId, redirect_uri: "https://rp.example/callback",
				scope: "openid email", state: "blocked-test", nonce: "blocked-test", code_challenge_method: "S256",
				code_challenge: pkceChallengeFromVerifier("synthetic-pg-new-flow-verifier")
			});
			expect((await app.inject({ method: "GET", url: `/authorize?${query}` })).statusCode).toBe(400);
			expect((await exchangeCode(pilotClientId, "synthetic-pilot-secret", pending.code, pending.verifier)).statusCode).toBe(400);
			expect((await app.inject({ method: "POST", url: "/token",
				headers: { authorization: `Basic ${Buffer.from(`${pilotClientId}:synthetic-pilot-secret`).toString("base64")}`,
					"content-type": "application/x-www-form-urlencoded" },
				payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: token.json().refresh_token }).toString()
			})).statusCode).toBe(400);
			expect((await app.inject({ method: "GET", url: "/userinfo",
				headers: { authorization: `Bearer ${token.json().access_token}` } })).statusCode).toBe(401);
			expect((await app.inject({ method: "POST", url: "/v1/registration/complete",
				headers: { authorization: `Basic ${Buffer.from(`${pilotClientId}:synthetic-pilot-secret`).toString("base64")}` },
				payload: { verificationId: randomUUID() } })).statusCode).toBe(401);
			const unrelated = await issueCode(unrelatedClientId, "synthetic-active-secret");
			expect((await exchangeCode(unrelatedClientId, "synthetic-active-secret", unrelated.code, unrelated.verifier)).statusCode).toBe(200);
		} finally {
			if (previous === undefined) delete process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS;
			else process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS = previous;
			configuration.reload();
		}
	});
});
