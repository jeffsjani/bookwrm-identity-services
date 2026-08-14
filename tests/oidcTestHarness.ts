import Fastify, { type FastifyInstance } from "fastify";
import formbody from "@fastify/formbody";
import { createHash, generateKeyPairSync } from "node:crypto";
import { configuration } from "../src/config/ConfigurationService.js";
import { getCurrentPrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";

type AuthorizeOptions = {
		clientId?: string;
		redirectUri?: string;
		scope?: string;
		nonce?: string;
		state?: string;
		codeChallengeMethod?: string;
		codeChallenge?: string;
};

export function ensureOidcTestEnvironment(): void {
		const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

		process.env.JWT_PRIVATE_KEY = privateKey
				.export({ type: "pkcs8", format: "pem" })
				.toString()
				.replace(/\n/g, "\\n");
		process.env.JWT_PUBLIC_KEY = publicKey
				.export({ type: "spki", format: "pem" })
				.toString()
				.replace(/\n/g, "\\n");

		process.env.OIDC_TEST_USER_ID = "dev-user-1";
		process.env.OIDC_TEST_USER_EMAIL = "dev.user@bookwrm.local";
		process.env.OIDC_TEST_USER_NAME = "Dev User";

		process.env.OIDC_BASE44_CLIENT_ID = "base44-web";
		process.env.OIDC_BASE44_CLIENT_SECRET = "base44-secret";
		process.env.OIDC_BASE44_REDIRECT_URI = "https://example.com/callback";
		process.env.OIDC_BASE44_SCOPES = "openid,profile,email";
		process.env.OIDC_BASE44_GRANT_TYPES = "authorization_code,refresh_token";
		process.env.OIDC_BASE44_PKCE_REQUIRED = "true";

		process.env.BASE44_BASE_URL = "https://identity.example.com";
		process.env.IDENTITY_API_PATH = "/api/identity";
		process.env.BOOKWRM_IDENTITY_API_KEY = "test-key";

		process.env.PRIVATEID_AUTH_API_KEY = "privateid-auth-key";
		process.env.PRIVATEID_AUTH_BASE_URL = "https://privateid.example.com";
		process.env.PRIVATEID_REDIRECT_URL = "https://example.com/privateid/callback";
		process.env.PRIVATEID_CALLBACK_URL = "https://example.com/privateid/webhook";
		process.env.PRIVATEID_ALLOWED_REDIRECT_ORIGINS = "https://example.com,https://bookwrm.local";
		process.env.PRIVATEID_WEBHOOK_SHARED_SECRET = "privateid-webhook-secret";
		process.env.PRIVATEID_MOCK_MODE = "true";
		process.env.PRIVATEID_FALLBACK_USER_ID = "dev-user-1";
		process.env.PRIVATEID_FALLBACK_EMAIL = "dev.user@bookwrm.local";
		process.env.PRIVATEID_FALLBACK_NAME = "Dev User";

		configuration.reload();
}

export async function buildOidcTestApp(): Promise<{ app: FastifyInstance }> {
		ensureOidcTestEnvironment();
		const { oidcService } = await import("../src/oidc/OIDCService.js");
		const { registerDiagnosticsRoutes } = await import("../src/routes/diagnostics.js");
		const { registerPrivateIdRoutes } = await import("../src/routes/privateid.js");

		const app = Fastify();
		await app.register(formbody);
		await registerDiagnosticsRoutes(app);
		await registerPrivateIdRoutes(app);
		await oidcService.registerEndpoints(app);
		await app.ready();

		return { app };
}

export function pkceChallengeFromVerifier(verifier: string): string {
		return createHash("sha256").update(verifier).digest("base64url");
}

export async function authorizeAndGetCode(
		app: FastifyInstance,
		verifier: string,
		overrides: AuthorizeOptions = {}
): Promise<string> {
		const challenge = overrides.codeChallenge ?? pkceChallengeFromVerifier(verifier);
		const params = new URLSearchParams({
				response_type: "code",
				client_id: overrides.clientId ?? "base44-web",
				redirect_uri: overrides.redirectUri ?? "https://example.com/callback",
				scope: overrides.scope ?? "openid profile email",
				state: overrides.state ?? "test-state",
				nonce: overrides.nonce ?? "test-nonce",
				code_challenge_method: overrides.codeChallengeMethod ?? "S256",
				code_challenge: challenge
		});

		const authorizeResponse = await app.inject({
				method: "GET",
				url: `/authorize?${params.toString()}`
		});

		if (authorizeResponse.statusCode !== 302) {
				throw new Error(`Authorize failed: ${authorizeResponse.statusCode} ${authorizeResponse.body}`);
		}

		if (!authorizeResponse.headers.location) {
				throw new Error("Authorize response missing PrivateID launch redirect");
		}

		// Sprint 8.15: /authorize only launches the PrivateID session now; completion arrives via webhook + callback.
		const sessionRecord = getCurrentPrivateIDSessionRecord();
		if (!sessionRecord) {
				throw new Error("No PrivateID session was created by /authorize");
		}

		const webhookResponse = await app.inject({
				method: "POST",
				url: "/privateid/webhook",
				headers: {
						"x-storythink-webhook-secret": "privateid-webhook-secret"
				},
				payload: {
						status: "SUCCESS",
						sessionId: sessionRecord.session.sessionId,
						transactionId: sessionRecord.session.transactionId,
						privateIdUserId: "dev-user-1"
				}
		});

		if (webhookResponse.statusCode !== 200) {
				throw new Error(`PrivateID webhook failed: ${webhookResponse.statusCode} ${webhookResponse.body}`);
		}

		const callbackResponse = await app.inject({
				method: "GET",
				url: `/privateid/callback?reason=success&sessionId=${encodeURIComponent(sessionRecord.session.sessionId)}&transactionId=${encodeURIComponent(sessionRecord.session.transactionId)}`
		});

		if (callbackResponse.statusCode !== 302) {
				throw new Error(`Callback failed: ${callbackResponse.statusCode} ${callbackResponse.body}`);
		}

		const location = callbackResponse.headers.location;
		if (!location) {
				throw new Error("Callback response missing redirect location");
		}

		const redirectUrl = new URL(location as string);
		const code = redirectUrl.searchParams.get("code");
		if (!code) {
				throw new Error("Callback redirect missing code parameter");
		}

		return code;
}

export async function exchangeAuthorizationCode(
		app: FastifyInstance,
		code: string,
		verifier: string,
		overrides: {
				clientId?: string;
				clientSecret?: string;
				redirectUri?: string;
		} = {}
) {
		const body = new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: overrides.redirectUri ?? "https://example.com/callback",
				client_id: overrides.clientId ?? "base44-web",
				client_secret: overrides.clientSecret ?? "base44-secret",
				code_verifier: verifier
		});

		return app.inject({
				method: "POST",
				url: "/token",
				headers: {
						"content-type": "application/x-www-form-urlencoded"
				},
				payload: body.toString()
		});
}
