import { afterEach, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { registerOIDCClients } from "../src/oidc/clients.js";

const originalEnvironment = {
		clientId: process.env.OIDC_BASE44_CLIENT_ID,
		clientSecret: process.env.OIDC_BASE44_CLIENT_SECRET,
		redirectUri: process.env.OIDC_BASE44_REDIRECT_URI,
		redirectUris: process.env.OIDC_BASE44_REDIRECT_URIS
};

afterEach(() => {
		process.env.OIDC_BASE44_CLIENT_ID = originalEnvironment.clientId;
		process.env.OIDC_BASE44_CLIENT_SECRET = originalEnvironment.clientSecret;
		process.env.OIDC_BASE44_REDIRECT_URI = originalEnvironment.redirectUri;
		process.env.OIDC_BASE44_REDIRECT_URIS = originalEnvironment.redirectUris;
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
});