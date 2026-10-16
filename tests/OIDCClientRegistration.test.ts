import { afterEach, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { registerOIDCClients } from "../src/oidc/clients.js";

const originalEnvironment = {
		clientId: process.env.OIDC_BASE44_CLIENT_ID,
		clientSecret: process.env.OIDC_BASE44_CLIENT_SECRET,
		redirectUri: process.env.OIDC_BASE44_REDIRECT_URI,
		redirectUris: process.env.OIDC_BASE44_REDIRECT_URIS,
		tokenEndpointAuthMethod: process.env.OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD,
		pkceRequired: process.env.OIDC_BASE44_PKCE_REQUIRED
};

afterEach(() => {
		for (const [key, value] of Object.entries({
			OIDC_BASE44_CLIENT_ID: originalEnvironment.clientId,
			OIDC_BASE44_CLIENT_SECRET: originalEnvironment.clientSecret,
			OIDC_BASE44_REDIRECT_URI: originalEnvironment.redirectUri,
			OIDC_BASE44_REDIRECT_URIS: originalEnvironment.redirectUris,
			OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD: originalEnvironment.tokenEndpointAuthMethod,
			OIDC_BASE44_PKCE_REQUIRED: originalEnvironment.pkceRequired
		})) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
		configuration.reload();
});

describe("OIDC production client registration", () => {
		it("registers all Base44 production callback URIs without removing the configured URI", () => {
			const existingRedirectUri = "https://existing.example.com/auth/sso/callback";
			process.env.OIDC_BASE44_CLIENT_ID = "bookwrm-base44-production";
			process.env.OIDC_BASE44_CLIENT_SECRET = "test-secret";
			process.env.OIDC_BASE44_REDIRECT_URI = existingRedirectUri;
			delete process.env.OIDC_BASE44_REDIRECT_URIS;
			configuration.reload();

			const [client] = registerOIDCClients();

			expect(client.redirect_uris).toEqual([
				existingRedirectUri,
				"https://app.base44.com/api/apps/6a1120e649a9d350fef35074/auth/sso/callback",
				"https://bookwrm.com/api/apps/6a1120e649a9d350fef35074/auth/sso/callback",
				"https://www.bookwrm.com/api/apps/6a1120e649a9d350fef35074/auth/sso/callback"
			]);
		});

	it("registers explicitly public clients without requiring a secret and requires PKCE", () => {
		process.env.OIDC_BASE44_CLIENT_ID = "public-test-client";
		delete process.env.OIDC_BASE44_CLIENT_SECRET;
		process.env.OIDC_BASE44_REDIRECT_URI = "https://public.example.com/callback";
		delete process.env.OIDC_BASE44_REDIRECT_URIS;
		process.env.OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD = "none";
		process.env.OIDC_BASE44_PKCE_REQUIRED = "true";
		configuration.reload();

		const [client] = registerOIDCClients();

		expect(client.client_secret).toBe("");
		expect(client.token_endpoint_auth_method).toBe("none");
		expect(client.require_pkce).toBe(true);
	});

	it("rejects a confidential client with no configured secret", () => {
		process.env.OIDC_BASE44_CLIENT_ID = "confidential-test-client";
		delete process.env.OIDC_BASE44_CLIENT_SECRET;
		process.env.OIDC_BASE44_REDIRECT_URI = "https://confidential.example.com/callback";
		delete process.env.OIDC_BASE44_REDIRECT_URIS;
		process.env.OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_post";
		configuration.reload();

		expect(() => registerOIDCClients()).toThrow("OIDC confidential client configuration missing");
	});

	it("rejects public-client configuration that disables PKCE", () => {
		process.env.OIDC_BASE44_CLIENT_ID = "public-test-client";
		delete process.env.OIDC_BASE44_CLIENT_SECRET;
		process.env.OIDC_BASE44_REDIRECT_URI = "https://public.example.com/callback";
		delete process.env.OIDC_BASE44_REDIRECT_URIS;
		process.env.OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD = "none";
		process.env.OIDC_BASE44_PKCE_REQUIRED = "false";
		configuration.reload();

		expect(() => registerOIDCClients()).toThrow("OIDC public clients must require PKCE");
	});
});