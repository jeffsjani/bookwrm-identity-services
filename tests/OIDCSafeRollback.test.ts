import { randomBytes, scryptSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { inMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { inMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { inMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { authorizeH1Client } from "../src/identity/H1ClientAuthority.js";
import { verifyOIDCClientSecret } from "../src/security/OIDCClientSecret.js";
import { authorizeAndGetCode, buildOidcTestApp, exchangeAuthorizationCode, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

const clientId = "base44-web";
const legacySecret = "base44-secret";
const redirectUri = "https://example.com/callback";
const originalBlockedIds = process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS;

function storedHash(secret: string): string {
	const salt = randomBytes(16);
	const derived = scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
	return `scrypt$16384$8$1$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

async function setClientSecret(secret: string): Promise<void> {
	const client = await inMemoryOIDCClientRepository.findByClientId(clientId);
	if (!client) throw new Error("Missing synthetic OIDC test client");
	await inMemoryOIDCClientRepository.upsert({ ...client, clientSecret: secret });
}

function basicHeader(secret: string): string {
	return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}

afterEach(() => {
	if (originalBlockedIds === undefined) delete process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS;
	else process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS = originalBlockedIds;
	configuration.reload();
});

beforeEach(() => {
	delete process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS;
	configuration.reload();
});

describe("safe rollback client authentication", () => {
	it("verifies scrypt secrets, rejects the stored hash as a credential, and keeps legacy plaintext", async () => {
		const secret = "synthetic-rollback-secret";
		const hash = storedHash(secret);

		expect(await verifyOIDCClientSecret(hash, secret)).toBe(true);
		expect(await verifyOIDCClientSecret(hash, hash)).toBe(false);
		expect(await verifyOIDCClientSecret(hash, "incorrect synthetic secret")).toBe(false);
		expect(await verifyOIDCClientSecret(legacySecret, legacySecret)).toBe(true);
		expect(await verifyOIDCClientSecret(legacySecret, "incorrect")).toBe(false);
	});

	it("accepts a legacy plaintext secret at the token endpoint", async () => {
		const { app } = await buildOidcTestApp();
		try {
			const verifier = "legacy-token-verifier-123456";
			const code = await authorizeAndGetCode(app, verifier);
			const response = await exchangeAuthorizationCode(app, code, verifier);
			expect(response.statusCode).toBe(200);
		} finally {
			await app.close();
		}
	});

	it("accepts the original scrypt-backed secret and rejects the stored hash at the token endpoint", async () => {
		const { app } = await buildOidcTestApp();
		try {
			const secret = "synthetic-rollback-secret";
			const hash = storedHash(secret);
			await setClientSecret(hash);

			const rejectedVerifier = "hash-as-secret-verifier-123456";
			const rejectedCode = await authorizeAndGetCode(app, rejectedVerifier);
			const rejected = await exchangeAuthorizationCode(app, rejectedCode, rejectedVerifier, { clientSecret: hash });
			expect(rejected.statusCode).toBe(400);
			expect(rejected.json()).toMatchObject({ error: "invalid_client" });

			const acceptedVerifier = "original-secret-verifier-123456";
			const acceptedCode = await authorizeAndGetCode(app, acceptedVerifier);
			const accepted = await app.inject({
				method: "POST",
				url: "/token",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					authorization: basicHeader(secret)
				},
				payload: new URLSearchParams({
					grant_type: "authorization_code",
					code: acceptedCode,
					redirect_uri: redirectUri,
					code_verifier: acceptedVerifier
				}).toString()
			});
			expect(accepted.statusCode).toBe(200);
		} finally {
			await app.close();
		}
	});

	it("uses hash-aware Basic authentication for H1 client authority", async () => {
		const { app } = await buildOidcTestApp();
		try {
			const secret = "synthetic-h1-rollback-secret";
			await setClientSecret(storedHash(secret));
			const authority = {
				clients: inMemoryOIDCClientRepository,
				applications: inMemoryApplicationRepository,
				tenants: inMemoryTenantRepository
			};
			const authorized = await authorizeH1Client(
				{ headers: { authorization: basicHeader(secret) } } as import("fastify").FastifyRequest,
				authority
			);
			expect(authorized.clientId).toBe(clientId);
			await expect(authorizeH1Client(
				{ headers: { authorization: basicHeader((await inMemoryOIDCClientRepository.findByClientId(clientId))!.clientSecret) } } as import("fastify").FastifyRequest,
				authority
			)).rejects.toMatchObject({ statusCode: 401 });
		} finally {
			await app.close();
		}
	});

	it("blocks a configured client in shared H1 authority", async () => {
		process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS = clientId;
		configuration.reload();
		const { app } = await buildOidcTestApp();
		try {
			await expect(authorizeH1Client(
				{ headers: { authorization: basicHeader(legacySecret) } } as import("fastify").FastifyRequest,
				{
					clients: inMemoryOIDCClientRepository,
					applications: inMemoryApplicationRepository,
					tenants: inMemoryTenantRepository
				}
			)).rejects.toMatchObject({ statusCode: 401 });
		} finally {
			await app.close();
		}
	});

	it("blocks a configured client before authorization", async () => {
		const { app } = await buildOidcTestApp();
		try {
			const verifier = "blocked-access-token-verifier-123";
			const code = await authorizeAndGetCode(app, verifier);
			const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
			expect(tokenResponse.statusCode).toBe(200);
			const token = tokenResponse.json() as { access_token: string };

			process.env.HAPI_OIDC_BLOCKED_CLIENT_IDS = clientId;
			configuration.reload();
			const { oidcService } = await import("../src/oidc/oidcServiceInstance.js");
			const dashboard = await oidcService.getDashboardSnapshot();
			expect(dashboard.clients.map(client => client.clientId)).not.toContain(clientId);

			const query = new URLSearchParams({
				response_type: "code",
				client_id: clientId,
				redirect_uri: redirectUri,
				scope: "openid profile email",
				state: "rollback-block-test",
				nonce: "rollback-block-nonce",
				code_challenge_method: "S256",
				code_challenge: pkceChallengeFromVerifier("rollback-block-verifier-123456")
			});
			const response = await app.inject({ method: "GET", url: `/authorize?${query}` });
			expect(response.statusCode).toBe(400);
			expect(response.json()).toMatchObject({ error: "invalid_client" });

			const userInfo = await app.inject({
				method: "GET",
				url: "/userinfo",
				headers: { authorization: `Bearer ${token.access_token}` }
			});
			expect(userInfo.statusCode).toBe(401);
			expect(userInfo.json()).toMatchObject({ error: "invalid_token" });
		} finally {
			await app.close();
		}
	});
});
