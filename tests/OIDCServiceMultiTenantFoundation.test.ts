import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { describe, it, expect } from "vitest";

import { ensureOidcTestEnvironment } from "./oidcTestHarness.js";
import { OIDCService } from "../src/oidc/OIDCService.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { BOOKWRM_APPLICATION_ID } from "../src/identity/WellKnownIdentities.js";
import { ensureBookwrmApplicationSeed } from "../src/adapters/base44/Base44ApplicationSeed.js";
import type {
		AuthenticationProvider,
		AuthenticatedUser,
		AuthenticationStatus,
		PendingAuthorizationContext,
		AsyncAuthenticationSession
} from "../src/authentication/AuthenticationProvider.js";

class MockAuthenticationProvider implements AuthenticationProvider {
		readonly beginAsyncAuthenticationCalls: string[] = [];

		async authenticate(): Promise<AuthenticatedUser> {
				throw new Error("not used by this test");
		}

		async cancel(): Promise<void> {}

		async status(): Promise<AuthenticationStatus> {
				return { state: "idle" };
		}

		async logout(): Promise<void> {}

		setPendingAuthorizationContext(_context: PendingAuthorizationContext): void {}

		async beginAsyncAuthentication(correlationId: string): Promise<AsyncAuthenticationSession> {
				this.beginAsyncAuthenticationCalls.push(correlationId);
				return { launchUrl: "https://mock-provider.example.com/launch", sessionId: "mock-session-1" };
		}
}

async function buildAppWithService(service: OIDCService) {
		const app = Fastify();
		await app.register(formbody);
		await service.registerEndpoints(app);
		await app.ready();
		return app;
}

describe("HAPI ID H1 - OIDCService AuthenticationProvider DI", () => {
		it("uses an injected AuthenticationProvider instead of constructing PrivateIDAuthenticationProvider", async () => {
				ensureOidcTestEnvironment();
				const mockProvider = new MockAuthenticationProvider();
				const oidcClients = new InMemoryOIDCClientRepository();
				await ensureBookwrmApplicationSeed({ oidcClients });
				const service = new OIDCService({ authenticationProvider: mockProvider, oidcClients });
				const app = await buildAppWithService(service);

				const response = await app.inject({
						method: "GET",
						url: "/authorize?client_id=base44-web&redirect_uri=https://example.com/callback&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256"
				});

				expect(response.statusCode).toBe(302);
				expect(response.headers.location).toBe("https://mock-provider.example.com/launch");
				expect(mockProvider.beginAsyncAuthenticationCalls).toHaveLength(1);
		});
});

describe("HAPI ID H1 - OIDCService persisted OIDCClient resolution", () => {
		it("resolves a persisted OIDCClient over the legacy env-driven fallback once seeded", async () => {
				ensureOidcTestEnvironment();
				const mockProvider = new MockAuthenticationProvider();
				const oidcClients = new InMemoryOIDCClientRepository();
				await oidcClients.upsert({
						id: randomUUID(),
						applicationId: BOOKWRM_APPLICATION_ID,
						clientId: "base44-web",
						// Deliberately different from the OIDC_BASE44_* env fallback so a match proves the DB path was used.
						clientSecret: "persisted-secret-not-in-env",
						redirectUris: ["https://persisted.example.com/callback"],
						scopes: ["openid", "profile", "email"],
						grantTypes: ["authorization_code", "refresh_token"],
						responseTypes: ["code"],
						tokenEndpointAuthMethod: "client_secret_post",
						requirePkce: true
				});

				const service = new OIDCService({ authenticationProvider: mockProvider, oidcClients });
				const app = await buildAppWithService(service);

				const response = await app.inject({
						method: "GET",
						url: "/authorize?client_id=base44-web&redirect_uri=https://persisted.example.com/callback&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256"
				});

				// The persisted redirect_uris, rather than the env values, authorize this request.
				expect(response.statusCode).toBe(302);
		});

		it("rejects an authorization request when no persisted client exists", async () => {
				ensureOidcTestEnvironment();
				const mockProvider = new MockAuthenticationProvider();
				const oidcClients = new InMemoryOIDCClientRepository();

				const service = new OIDCService({ authenticationProvider: mockProvider, oidcClients });
				const app = await buildAppWithService(service);

				const response = await app.inject({
						method: "GET",
						url: "/authorize?client_id=base44-web&redirect_uri=https://example.com/callback&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256"
				});

				expect(response.statusCode).toBe(400);
		});
});
