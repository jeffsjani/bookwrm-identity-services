import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import {
		createHash,
		createPrivateKey,
		createPublicKey,
		createSign,
		randomBytes,
		randomUUID,
		type KeyObject
} from "node:crypto";
import Provider from "oidc-provider";
import { z } from "zod";
import type { EmailOIDCHandoff } from "../authentication/EmailOIDCHandoff.js";
import { EmailAuthenticationError } from "../authentication/email/EmailAuthenticationTypes.js";
import { VerificationError } from "../email/VerificationChallenge.js";

import type { AuthenticationProvider, AuthenticatedUser, PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityCache } from "../cache/IdentityCache.js";
import { identityRegistry } from "../identity/IdentityRegistry.js";
import { BOOKWRM_APPLICATION_ID } from "../identity/WellKnownIdentities.js";
import type { OIDCClientRepository } from "../identity/OIDCClientRepository.js";
import { inMemoryOIDCClientRepository } from "../identity/InMemoryOIDCClientRepository.js";
import { PostgresOIDCClientRepository } from "../identity/PostgresOIDCClientRepository.js";
import type { OIDCClientRecord } from "../models/OIDCClientRecord.js";
import type { OIDCAuthorizationCode } from "../models/OIDCAuthorizationCode.js";
import { ClaimsService } from "./ClaimsService.js";
import { oidcClaims } from "./claims.js";
import { oidcConfiguration } from "./configuration.js";
import { recordOIDCRequest } from "./infrastructure/OIDCMetrics.js";
import { OIDCKeyRotationService } from "./infrastructure/OIDCKeyRotationService.js";
import { identityCircuitBreaker } from "../infrastructure/CircuitBreaker.js";
import { RedisLockService } from "./infrastructure/RedisLockService.js";
import { RedisOIDCProviderAdapter } from "./infrastructure/RedisOIDCProviderAdapter.js";
import {
		RedisOIDCStore,
		type AccessTokenRecord,
		type RefreshTokenRecord
} from "./infrastructure/RedisOIDCStore.js";
import { OIDCRateLimiter } from "./infrastructure/OIDCRateLimiter.js";
import { getRedisClient } from "./infrastructure/RedisInfrastructure.js";
import { registerOidcRoutes } from "./routes.js";
import type { OIDCLogEntry } from "./types.js";
import { consumePendingAuthorizationRequest, getPrivateIDAuthenticatedUser, storePrivateIDBrowserReturn,
	PRIVATEID_BROWSER_RETURN_COOKIE } from "../privateid/PrivateIDSessionStore.js";
import { storeCorrelation } from "./CorrelationStore.js";
import {
		AUTHORIZATION_INTERACTION_TTL_MS,
		AuthorizationInteractionStore,
		type AuthorizationInteraction,
		type AuthorizationInteractionBinding
} from "./AuthorizationInteractionStore.js";
import { chooserPage, codePage, emailPage, messagePage, type RenderedLoginPage } from "./UniversalLoginPages.js";
import type { InteractiveEmailAuthority, InteractiveEmailMode } from "../authentication/InteractiveEmailAuthentication.js";
import { bucketRemainingTtl, diagnosticCorrelationId, logUniversalLoginDiagnostic } from "./UniversalLoginDiagnostics.js";

// __Host- prefix: Secure, host-only, Path=/ — the interaction handle cannot be scoped to another domain.
const UNIVERSAL_LOGIN_COOKIE = "__Host-hapi_login";
const universalLoginEmailSchema = z.string().trim().min(3).max(320).email();
const isInteractiveEmailMode = (value: unknown): value is InteractiveEmailMode =>
	value === "AUTHENTICATION" || value === "REGISTRATION" || value === "INELIGIBLE";

export type OIDCClient = Record<string, unknown>;
export type OIDCSigningKey = JsonWebKey;
export type OIDCPublicKey = JsonWebKey;

export type OIDCServiceOptions = {
		issuer?: string;
		mountPath?: string;
		clients?: OIDCClient[];
		signingKeys?: OIDCSigningKey[];
		authenticationProvider: AuthenticationProvider;
		oidcClients?: OIDCClientRepository;
};

type AuthorizationQuery = {
		client_id?: string;
		redirect_uri?: string;
		response_type?: string;
		scope?: string;
		state?: string;
		nonce?: string;
		code_challenge?: string;
		code_challenge_method?: string;
};

const emailAuthorizationSchema = z.object({
	client_id: z.string().min(1),
	redirect_uri: z.string().url(),
	response_type: z.literal("code"),
	scope: z.string().refine(value => value.split(" ").includes("openid")),
	state: z.string().optional(),
	nonce: z.string().min(1),
	code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
	code_challenge_method: z.literal("S256"),
	authentication_result: z.string().regex(/^[A-Za-z0-9_-]{43}$/)
}).strict();

type TokenRequestBody = {
		grant_type?: string;
		code?: string;
		redirect_uri?: string;
		client_id?: string;
		client_secret?: string;
		code_verifier?: string;
};

type OIDCMetrics = {
		authorizationRequests: number;
		tokensIssued: number;
		errors: number;
};

type DashboardClientView = {
		clientId: string;
		redirectUris: string[];
		scopes: string[];
		grantTypes: string[];
		pkceRequired: boolean;
		tokenEndpointAuthMethod: string;
};

export type OIDCDashboardSnapshot = {
		clients: DashboardClientView[];
		issuer: string;
		discovery: string;
		jwks: string;
		authorizationRequests: number;
		tokensIssued: number;
		errors: number;
		health: boolean;
		infrastructure: {
			redis: {
				enabled: boolean;
				healthy: boolean;
				configured: boolean;
			};
			cache: ReturnType<typeof identityCache.getSnapshot>;
			circuitBreaker: ReturnType<typeof identityCircuitBreaker.getSnapshot>;
			health: {
				providerReady: boolean;
				signingKeysLoaded: boolean;
			};
			metrics: {
				enabled: boolean;
				requestCount: number;
				errorCount: number;
			};
			keyRotation: {
				enabled: boolean;
				issuer: string;
			};
			featureFlags: {
				oidcEnabled: boolean;
				mockMode: boolean;
				mockAuthEnabled: boolean;
				redisEnabled: boolean;
				cacheEnabled: boolean;
				metricsEnabled: boolean;
			};
		};
};

export class OIDCService {
		private static readonly DEFAULT_ISSUER = "https://identity.bookwrm.com";
		private static readonly AUTHORIZATION_CODE_TTL_MS = 60_000;
		private static readonly AUTHORIZATION_CODE_CLEANUP_INTERVAL_MS = 30_000;
		private static readonly ACCESS_TOKEN_TTL_MS = 300_000;
		private static readonly REFRESH_TOKEN_TTL_MS = 2_592_000_000;

		private provider?: Provider;
		private readonly options: OIDCServiceOptions;
		private readonly authenticationProvider: AuthenticationProvider;
		private emailAuthentication?: EmailOIDCHandoff;
		private readonly oidcClients: OIDCClientRepository;
		private readonly claimsService: ClaimsService;
		private readonly redisStore: RedisOIDCStore;
		private readonly lockService: RedisLockService;
		private readonly rateLimiter: OIDCRateLimiter;
		private readonly interactions: AuthorizationInteractionStore;
		private readonly keyRotationService: OIDCKeyRotationService;
		private readonly providerAdapter = new RedisOIDCProviderAdapter();
		private readonly metrics: OIDCMetrics = {
				authorizationRequests: 0,
				tokensIssued: 0,
				errors: 0
		};

		constructor(options: OIDCServiceOptions) {
				this.options = options;
				this.authenticationProvider = options.authenticationProvider;
				this.oidcClients = options.oidcClients ?? (
						configuration.getIdentityRegistryDriver() === "memory"
								? inMemoryOIDCClientRepository
								: new PostgresOIDCClientRepository()
				);
				this.claimsService = new ClaimsService();
				this.redisStore = new RedisOIDCStore();
				this.lockService = new RedisLockService();
				this.rateLimiter = new OIDCRateLimiter();
				this.keyRotationService = new OIDCKeyRotationService();
				this.interactions = new AuthorizationInteractionStore();
		}

		configureEmailAuthentication(handoff: EmailOIDCHandoff): void {
				this.emailAuthentication = handoff;
		}

		async configureProvider(): Promise<Provider> {
				this.assertSigningKeyConfiguration();

				const issuer = this.resolveIssuer();
				const clients = await this.configureClients();
				const signingKeys = await this.keyRotationService.getSigningKeys();
				const pkce = this.configurePKCE();
				const claims = this.configureClaims();

				const adapterBackend = this.providerAdapter;
				class OIDCProductionAdapter {
						readonly name: string;

						constructor(name: string) {
								this.name = name;
						}

						upsert(id: string, payload: unknown, expiresIn: number): Promise<void> {
								return adapterBackend.upsert(`${this.name}:${id}`, payload, expiresIn);
						}

						find<T>(id: string): Promise<T | undefined> {
								return adapterBackend.find<T>(`${this.name}:${id}`);
						}

						findByUid<T>(uid: string): Promise<T | undefined> {
								return adapterBackend.findByUid<T>(`${this.name}:${uid}`);
						}

						destroy(id: string): Promise<void> {
								return adapterBackend.destroy(`${this.name}:${id}`);
						}

						revokeByGrantId(grantId: string): Promise<void> {
								return adapterBackend.revokeByGrantId(`${this.name}:${grantId}`);
						}

						consume(id: string): Promise<void> {
								return adapterBackend.consume(`${this.name}:${id}`);
						}
				}

				this.provider = new Provider(issuer, {
						...oidcConfiguration,
						clients,
						claims,
						pkce,
						adapter: OIDCProductionAdapter,
						jwks: {
								keys: signingKeys
						}
				});

				return this.provider;
		}

		async registerEndpoints(app: FastifyInstance): Promise<void> {
				const provider = this.provider ?? await this.configureProvider();
				app.get("/.well-known/openid-configuration", async (request, reply) => {
						const startedAt = Date.now();
						let error = "";
						try {
								return this.getDiscoveryConfiguration();
						} catch (err) {
								error = err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId: "",
										flow: "discovery",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply),
										error,
										user: "",
										pkce: "N/A",
										correlationId: this.correlationIdFor(request)
								});
						}
				});
				app.route({ method: ["GET", "POST"], url: "/authorize", bodyLimit: 4096,
					errorHandler: (error, request, reply) => {
						if (request.method !== "POST") throw error;
						reply.header("Cache-Control", "no-store");
						const status = typeof error.statusCode === "number" && error.statusCode >= 400 && error.statusCode < 500
							? error.statusCode : 503;
						if (status === 503) request.log.error({ event: "EMAIL_OIDC_HANDOFF_UNAVAILABLE" }, "Email OIDC handoff failed");
						return reply.code(status).send({ error: status === 503 ? "authentication_unavailable" : "invalid_request" });
					},
					handler: async (request, reply) => {
						let emailResult: string | undefined;
						let query: AuthorizationQuery;
						if (request.method === "POST") {
								reply.header("Cache-Control", "no-store");
								if (!this.emailAuthentication) return reply.code(404).send({ error: "not_found" });
								const parsed = emailAuthorizationSchema.safeParse(request.body);
								if (!parsed.success) return reply.code(400).send({ error: "invalid_request" });
								emailResult = parsed.data.authentication_result;
								query = parsed.data;
						} else {
								query = request.query as AuthorizationQuery;
						}
						const startedAt = Date.now();
						let error = "";
						let userId = "";
						this.metrics.authorizationRequests += 1;
						const clientId = query.client_id?.trim();
						const redirectUri = query.redirect_uri;
						const responseType = query.response_type;
						const codeChallenge = query.code_challenge?.trim();
						const codeChallengeMethod = query.code_challenge_method;
						const requestedScopes = (query.scope ?? "")
								.split(" ")
								.map((scope) => scope.trim())
								.filter((scope) => scope.length > 0);

					try {
								await this.rateLimiter.assertWithinLimits({
										ip: request.ip,
										clientId: clientId ?? "",
										userId: ""
								});

								if (!clientId) {
										reply.code(400);
										error = "client_id is required";
										return { error: "invalid_request", error_description: "client_id is required" };
								}

								if (!redirectUri) {
										reply.code(400);
										error = "redirect_uri is required";
										return { error: "invalid_request", error_description: "redirect_uri is required" };
								}

								const client = await this.resolveClient(clientId, request.method === "POST");
								if (!client) {
										reply.code(400);
										error = "Unknown client";
										return { error: "invalid_client", error_description: "Unknown client" };
								}

								const allowedRedirectUris = this.extractRedirectUris(client);
								// TEMPORARY RELEASE PATCH 6.5 - REMOVE AFTER PRODUCTION CERTIFICATION
								app.log.info(
										{ clientId, requestedRedirectUri: redirectUri, registeredRedirectUris: allowedRedirectUris },
										"OIDC Redirect Validation"
								);
								if (allowedRedirectUris.length > 0 && !allowedRedirectUris.includes(redirectUri)) {
										app.log.warn(
												{ clientId, requestedRedirectUri: redirectUri },
												"OIDC_REDIRECT_URI_MISMATCH"
										);
										reply.code(400);
										error = "redirect_uri is not registered for client";
										return { error: "invalid_request", error_description: "redirect_uri is not registered for client" };
								}

								if (!this.clientAllowsAuthorizationCodeGrant(client)) {
										reply.code(400);
										error = "Client cannot use authorization_code grant";
										return { error: "unauthorized_client", error_description: "Client cannot use authorization_code grant" };
								}

								const allowedScopes = this.extractScopes(client);
								if (allowedScopes.length > 0 && requestedScopes.some((scope) => !allowedScopes.includes(scope))) {
										reply.code(400);
										error = "Requested scope is not allowed for client";
										return { error: "invalid_scope", error_description: "Requested scope is not allowed for client" };
								}

								if (responseType !== "code") {
										reply.code(400);
										error = "Only response_type=code is supported";
										return { error: "unsupported_response_type", error_description: "Only response_type=code is supported" };
								}

								const pkceRequired = this.clientRequiresPkce(client);
								if (pkceRequired && (!codeChallenge || codeChallenge.length === 0)) {
										reply.code(400);
										error = "code_challenge is required";
										return { error: "invalid_request", error_description: "code_challenge is required" };
								}

								if (codeChallengeMethod === "plain") {
										reply.code(400);
										error = "PKCE plain is not supported";
										return {
												error: "invalid_request",
												error_description: "PKCE plain is not supported"
										};
								}

								if (codeChallenge && codeChallengeMethod !== "S256") {
										reply.code(400);
										error = "Only code_challenge_method=S256 is supported";
										return {
												error: "invalid_request",
												error_description: "Only code_challenge_method=S256 is supported"
										};
								}

								const pendingContext: PendingAuthorizationContext = {
										clientId,
										redirectUri,
										scope: query.scope ?? "",
										nonce: query.nonce ?? "",
										codeChallenge: codeChallenge ?? "",
										state: query.state
								};
								if (emailResult && this.emailAuthentication) {
										const principal = await this.emailAuthentication.consume(request, emailResult, clientId);
										userId = principal.id;
										const redirect = await this.issueAuthorizationRedirect(principal, pendingContext);
										return { redirectUri: redirect };
								}
								if (request.method === "GET" && this.isUniversalLoginEnabled()) {
										const handle = await this.createAuthorizationInteraction(app, clientId, pendingContext, query);
										reply.header("Cache-Control", "no-store");
										reply.header("Set-Cookie", this.interactionCookie(handle));
										reply.redirect("/login", 302);
										return;
								}
								await this.beginFaceAuthorization(reply, pendingContext);
						} catch (err) {
								if (request.method === "POST") {
										if (err instanceof EmailAuthenticationError || err instanceof VerificationError) {
												error = "email_authentication_failed";
												return reply.code(err.statusCode).send({ error: "authentication_failed" });
										}
										app.log.error({ event: "EMAIL_OIDC_HANDOFF_UNAVAILABLE" }, "Email OIDC handoff failed");
										error = "email_authentication_unavailable";
										return reply.code(503).send({ error: "authentication_unavailable" });
								}
								error = err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId: clientId ?? "",
										flow: "authorize",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply),
										error,
										user: userId,
										pkce: codeChallengeMethod ?? "missing",
										correlationId: this.correlationIdFor(request)
								});
						}
				}});
				this.registerUniversalLogin(app);
				app.get("/jwks", async (request, reply) => {
						const startedAt = Date.now();
						let error = "";
						try {
								return {
										keys: await this.keyRotationService.getPublicKeys()
								};
						} catch (err) {
								error = err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId: "",
										flow: "jwks",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply),
										error,
										user: "",
										pkce: "N/A",
										correlationId: this.correlationIdFor(request)
								});
						}
				});
				app.get("/userinfo", async (request, reply) => {
						const startedAt = Date.now();
						let error = "";
						let clientId = "";
						let user = "";
						try {
								await this.rateLimiter.assertWithinLimits({
										ip: request.ip,
										clientId: "",
										userId: ""
								});

								const authorization = request.headers.authorization;
								if (!authorization || !authorization.startsWith("Bearer ")) {
										reply.code(401);
										error = "Bearer access token is required";
										return { error: "invalid_token", error_description: "Bearer access token is required" };
								}

								const accessToken = authorization.slice("Bearer ".length).trim();
								const tokenRecord = await this.getAccessTokenRecord(accessToken);

								if (!tokenRecord) {
										reply.code(401);
										error = "Access token is invalid or expired";
										return { error: "invalid_token", error_description: "Access token is invalid or expired" };
								}

								clientId = tokenRecord.clientId;
								user = tokenRecord.sub;
								await this.rateLimiter.assertWithinLimits({
										ip: request.ip,
										clientId,
										userId: user
								});

								// Release Patch 6.1: resolve current claims live from the Identity Registry, not from the access token record.
								const currentClaims = await this.resolveCurrentClaims(tokenRecord.sub);
								const userInfoResponse = {
										sub: tokenRecord.sub,
										...(currentClaims.email !== undefined ? { email: currentClaims.email } : {}),
										...(currentClaims.emailVerified !== undefined ? { email_verified: currentClaims.emailVerified } : {}),
										...(currentClaims.name !== undefined ? { name: currentClaims.name } : {})
								};
								return userInfoResponse;
						} catch (err) {
								error = err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId,
										flow: "userinfo",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply),
										error,
										user,
										pkce: "N/A",
										correlationId: this.correlationIdFor(request)
								});
						}
				});
				app.post("/token", async (request, reply) => {
						const startedAt = Date.now();
						let error = "";
						let user = "";
						let pkce = "not_used";
						const body = request.body as TokenRequestBody;
						const grantType = body.grant_type;
						const code = body.code?.trim();
						const redirectUri = body.redirect_uri?.trim();
						const codeVerifier = body.code_verifier?.trim();

						// RFC 6749 §2.3.1: client_secret_basic credentials arrive via the Authorization header and take precedence over the request body.
						const basicCredentials = this.parseBasicClientCredentials(request.headers.authorization);
						const clientId = basicCredentials?.clientId ?? body.client_id?.trim();
						const clientSecret = basicCredentials?.clientSecret ?? body.client_secret?.trim();

						try {
								await this.rateLimiter.assertWithinLimits({
										ip: request.ip,
										clientId: clientId ?? "",
										userId: ""
								});

								if (grantType !== "authorization_code") {
										reply.code(400);
										error = "Only grant_type=authorization_code is supported";
										return {
												error: "unsupported_grant_type",
												error_description: "Only grant_type=authorization_code is supported"
										};
								}

								if (!code || !redirectUri) {
										reply.code(400);
										error = "code and redirect_uri are required";
										return {
												error: "invalid_request",
												error_description: "code and redirect_uri are required"
										};
								}

								if (!clientId) {
										reply.code(400);
										error = "Client authentication failed: no client_id supplied";
										return { error: "invalid_client", error_description: "Client authentication failed: no client_id supplied" };
								}

								const codeRecord = await this.lockService.withAuthorizationCodeLock(code, async () => {
										return this.consumeAuthorizationCode(code);
								});
								if (!codeRecord) {
										reply.code(400);
										error = "Invalid or expired authorization code";
										return { error: "invalid_grant", error_description: "Invalid or expired authorization code" };
								}

								if (codeRecord.clientId !== clientId) {
										reply.code(400);
										error = "client_id does not match code";
										return { error: "invalid_client", error_description: "client_id does not match code" };
								}

								if (codeRecord.redirectUri !== redirectUri) {
										reply.code(400);
										error = "redirect_uri does not match code";
										return { error: "invalid_grant", error_description: "redirect_uri does not match code" };
								}

								const client = await this.resolveClient(clientId, codeRecord.authenticationMethod === "HAPI_EMAIL");
								if (!client) {
										reply.code(400);
										error = "Unknown client";
										return { error: "invalid_client", error_description: "Unknown client" };
								}

								const configuredClientSecret =
									typeof client.client_secret === "string" ? client.client_secret : undefined;
								const tokenEndpointAuthMethod =
									typeof client.token_endpoint_auth_method === "string"
											? client.token_endpoint_auth_method
											: "client_secret_post";
								if (
										configuredClientSecret &&
										tokenEndpointAuthMethod !== "none" &&
										configuredClientSecret !== clientSecret
								) {
										reply.code(400);
										error = "client_secret is invalid";
										return { error: "invalid_client", error_description: "client_secret is invalid" };
								}

								const allowedRedirectUris = this.extractRedirectUris(client);
								if (allowedRedirectUris.length > 0 && !allowedRedirectUris.includes(redirectUri)) {
										reply.code(400);
										error = "redirect_uri is not registered for client";
										return { error: "invalid_grant", error_description: "redirect_uri is not registered for client" };
								}

								const pkceRequired = this.clientRequiresPkce(client);
								if (pkceRequired && !codeRecord.codeChallenge) {
										reply.code(400);
										error = "PKCE challenge missing on authorization code";
										return { error: "invalid_grant", error_description: "PKCE challenge missing on authorization code" };
								}

								if (pkceRequired && !codeVerifier) {
										reply.code(400);
										error = "code_verifier is required for PKCE-enabled clients";
										return {
												error: "invalid_request",
												error_description: "code_verifier is required for PKCE-enabled clients"
										};
								}

								if (codeVerifier) {
										pkce = "S256";
								}

								if (codeRecord.codeChallenge && codeVerifier) {
										const expectedChallenge = this.toS256CodeChallenge(codeVerifier);
										if (expectedChallenge !== codeRecord.codeChallenge) {
												reply.code(400);
												error = "PKCE validation failed";
												return { error: "invalid_grant", error_description: "PKCE validation failed" };
										}
								}

								if (!codeRecord.nonce) {
										reply.code(400);
										error = "nonce is missing on authorization code";
										return { error: "invalid_grant", error_description: "nonce is missing on authorization code" };
								}

								const now = Math.floor(Date.now() / 1000);
								const issuer = this.resolveIssuer();
								if (codeRecord.authenticationMethod === "HAPI_EMAIL") {
										const subject = await identityRegistry.findByOidcSubject(codeRecord.userSub);
										if (!subject || subject.primaryProvider !== "HAPI_EMAIL" ||
											subject.status !== "ACTIVE" || subject.emailVerified !== true ||
											subject.email !== subject.primaryProviderSubject) {
												error = "email_identity_not_eligible";
												return reply.code(400).send({ error: "invalid_grant" });
										}
								}
								// Release Patch 6.1: the code only carries userId/userSub -- mutable claims are re-resolved live from the
								// Identity Registry here, so an Identity Registry update after code issuance is never missed.
							const currentClaims = await this.resolveCurrentClaims(codeRecord.userSub);
							const authenticatedUser: AuthenticatedUser = {
									id: codeRecord.userId,
									sub: codeRecord.userSub,
									email: currentClaims.email,
									emailVerified: currentClaims.emailVerified,
									name: currentClaims.name
							};
							user = authenticatedUser.id;
							await this.rateLimiter.assertWithinLimits({
									ip: request.ip,
									clientId,
									userId: user
							});

							const claims = await this.claimsService.toOIDCClaims(authenticatedUser);

							const accessToken = this.createOpaqueToken();
							const refreshToken = this.createOpaqueToken();
							await this.storeAccessToken(accessToken, {
									sub: claims.sub,
									clientId,
									nonce: codeRecord.nonce,
									scope: codeRecord.scope,
									...(codeRecord.authenticationMethod ? {
										authenticationMethod: codeRecord.authenticationMethod,
										authenticatedAt: codeRecord.authenticatedAt
									} : {})
							});
							await this.storeRefreshToken(refreshToken, {
									userId: codeRecord.userId,
									clientId,
									scope: codeRecord.scope
							});
							const idToken = await this.createIdToken({
							issuer,
								subject: codeRecord.userSub,
							audience: clientId,
							nonce: codeRecord.nonce,
							scope: codeRecord.scope,
							...(codeRecord.authenticationMethod ? {
								authenticationMethod: codeRecord.authenticationMethod,
								authenticatedAt: codeRecord.authenticatedAt
							} : {}),
							...(claims.email !== undefined ? { email: claims.email } : {}),
							...(claims.emailVerified !== undefined ? { emailVerified: claims.emailVerified } : {}),
								...(claims.name !== undefined ? { name: claims.name } : {}),
							iat: now,
							exp: now + 300
						});

							reply.code(200);
							this.metrics.tokensIssued += 1;
							return {
								token_type: "Bearer",
								expires_in: 300,
								access_token: accessToken,
								refresh_token: refreshToken,
								id_token: idToken
								};
						} catch (err) {
								error = err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId: clientId ?? "",
										flow: "token",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply),
										error,
										user,
										pkce,
										correlationId: this.correlationIdFor(request)
								});
						}
				});
				await registerOidcRoutes(app, provider, { mountPath: this.options.mountPath });
		}

		getDiscoveryConfiguration(): Record<string, unknown> {
				const issuer = this.resolveIssuer();
				const claimsSupported = [...new Set(Object.values(oidcClaims).flat())];

				const discovery = {
						issuer,
						authorization_endpoint: `${issuer}/authorize`,
						token_endpoint: `${issuer}/token`,
						userinfo_endpoint: `${issuer}/userinfo`,
						jwks_uri: `${issuer}/jwks`,
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["RS256"],
						scopes_supported: ["openid", "profile", "email"],
						token_endpoint_auth_methods_supported: [
								"client_secret_basic",
								"client_secret_post",
								"none"
						],
						grant_types_supported: ["authorization_code", "refresh_token"],
						claims_supported: claimsSupported,
						code_challenge_methods_supported: ["S256"]
				};

				this.validateDiscoveryConfiguration(discovery);
				return discovery;
		}

		private resolveIssuer(): string {
				if (this.options.issuer) {
						return this.options.issuer;
				}

				return configuration.getOidcIssuer(OIDCService.DEFAULT_ISSUER);
		}

		private assertSigningKeyConfiguration(): void {
				const hasInjectedKeys = Boolean(this.options.signingKeys && this.options.signingKeys.length > 0);
				const keyConfig = configuration.getOIDCKeyConfiguration();
				const hasPrivateKeyEnv = keyConfig.privateKey.length > 0;
				const hasJwksEnv = Boolean(keyConfig.jwksJson);
				const isLocalDevelopment = configuration.getEnvironment() !== "production";

				if (hasInjectedKeys || hasPrivateKeyEnv || hasJwksEnv || isLocalDevelopment) {
					return;
				}

				throw new Error(
						"OIDC startup guard failed: configure JWT_PRIVATE_KEY or OIDC_JWKS_JSON before boot (Railway env vars)."
				);
		}

		private validateDiscoveryConfiguration(discovery: Record<string, unknown>): void {
				const requiredFields = [
						"issuer",
						"authorization_endpoint",
						"token_endpoint",
						"jwks_uri",
						"response_types_supported",
						"subject_types_supported",
						"id_token_signing_alg_values_supported"
				];

				for (const field of requiredFields) {
						if (!(field in discovery)) {
								throw new Error(`OpenID discovery validation failed: missing ${field}`);
						}
				}

				if (discovery.issuer !== OIDCService.DEFAULT_ISSUER) {
						throw new Error("OpenID discovery validation failed: issuer mismatch");
				}
		}

		private loadSigningKeys(): OIDCSigningKey[] {
				if (this.options.signingKeys && this.options.signingKeys.length > 0) {
						return this.options.signingKeys;
				}

				const privatePemKeys = secretProvider.getJwtPrivateKeys();
				if (privatePemKeys.length > 0) {
						return privatePemKeys.map((pem, index) => {
								const privateKey = createPrivateKey(pem);
								const publicKey = createPublicKey(privateKey);
								const kid = this.createKid(publicKey, index);
								const jwk = privateKey.export({ format: "jwk" });

								return {
										...jwk,
										kid,
										alg: "RS256",
										use: "sig"
								};
						});
				}

				const rawJwks = secretProvider.getOidcJwksJson();

				if (!rawJwks) {
						return [];
				}

				const parsed = JSON.parse(rawJwks) as { keys?: OIDCSigningKey[] };
				return parsed.keys ?? [];
		}

		private loadPublicKeys(): OIDCPublicKey[] {
				const publicPemKeys = secretProvider.getJwtPublicKeys();
				if (publicPemKeys.length > 0) {
						return publicPemKeys.map((pem, index) => {
								const publicKey = createPublicKey(pem);
								const jwk = publicKey.export({ format: "jwk" });
								const kid = this.createKid(publicKey, index);

								return {
										...jwk,
										kid,
										alg: "RS256",
										use: "sig"
								};
						});
				}

				const signingKeys = this.loadSigningKeys();
				return signingKeys.map((key, index) => {
						const existingKid = (key as Record<string, unknown>).kid;
						const { d, p, q, dp, dq, qi, oth, ...publicPart } = key;
						return {
								...publicPart,
								kid: typeof existingKid === "string" ? existingKid : `rotating-key-${index + 1}`,
								alg: "RS256",
								use: "sig"
						};
				});
		}

		private readPemKeysFromEnv(envName: "JWT_PRIVATE_KEY" | "JWT_PUBLIC_KEY"): string[] {
				const raw = configuration.get(envName);

				if (!raw) {
						return [];
				}

				const trimmed = raw.trim();
				if (!trimmed) {
						return [];
				}

				if (trimmed.startsWith("[")) {
						const parsed = JSON.parse(trimmed) as string[];
						return parsed.map((value) => this.normalizePem(value));
				}

				const pemBlocks = this.extractPemBlocks(trimmed);
				if (pemBlocks.length > 0) {
						return pemBlocks.map((value) => this.normalizePem(value));
				}

				return [this.normalizePem(trimmed)];
		}

		private extractPemBlocks(raw: string): string[] {
				const matches = raw.match(/-----BEGIN [^-]+-----[\s\S]+?-----END [^-]+-----/g);
				return matches ?? [];
		}

		private normalizePem(raw: string): string {
				return raw.replace(/\\n/g, "\n").trim();
		}

		private createKid(publicKey: KeyObject, index: number): string {
				const der = publicKey.export({ type: "spki", format: "der" });
				const fingerprint = createHash("sha256").update(der).digest("base64url").slice(0, 16);
				return `rsa-${index + 1}-${fingerprint}`;
		}

		private toOIDCClient(record: OIDCClientRecord): OIDCClient {
				return {
						client_id: record.clientId,
						client_secret: record.clientSecret,
						redirect_uris: record.redirectUris,
						scope: record.scopes.join(" "),
						grant_types: record.grantTypes,
						response_types: record.responseTypes,
						token_endpoint_auth_method: record.tokenEndpointAuthMethod,
						require_pkce: record.requirePkce
				};
		}

		// HAPI ID Core resolves clients only from the persisted application/client registry.
		private async configureClients(): Promise<OIDCClient[]> {
				if (this.options.clients && this.options.clients.length > 0) {
						return this.options.clients;
				}

				const persistedClients = await this.oidcClients.listByApplication(BOOKWRM_APPLICATION_ID);
				if (persistedClients.length > 0) {
						return persistedClients.map((record) => this.toOIDCClient(record));
				}

				const rawClients = configuration.get("OIDC_CLIENTS_JSON");
				if (!rawClients) {
						return [];
				}

				return JSON.parse(rawClients) as OIDCClient[];
		}

		private configurePKCE(): { required: () => boolean; methods: string[] } {
				return {
						required: () => true,
						methods: ["S256"]
				};
		}

		private configureClaims() {
				return oidcClaims;
		}

		private createAuthorizationCode(): string {
				return randomBytes(32).toString("base64url");
		}

		private async issueAuthorizationRedirect(user: AuthenticatedUser, context: PendingAuthorizationContext): Promise<string> {
				const authorizationCode = this.createAuthorizationCode();

				// Release Patch 6.1: the code carries only stable protocol fields (sub/client/nonce/scope/PKCE/expiration);
				// mutable claims are re-resolved from the Identity Registry at /token time, never snapshotted here.
				await this.storeAuthorizationCode({
						code: authorizationCode,
						clientId: context.clientId,
						redirectUri: context.redirectUri,
						scope: context.scope,
						nonce: context.nonce,
						codeChallenge: context.codeChallenge,
						userId: user.id,
						userSub: user.sub,
						...(user.authenticationMethod ? {
							authenticationMethod: user.authenticationMethod,
							authenticatedAt: user.authenticatedAt
						} : {})
				});

				const redirectTarget = new URL(context.redirectUri);
				redirectTarget.searchParams.set("code", authorizationCode);

				if (context.state) {
						redirectTarget.searchParams.set("state", context.state);
				}

				return redirectTarget.toString();
		}

		// Existing interactive PrivateID Face path, shared by flag-off GET /authorize and Universal Login "Continue with Face".
		private async beginFaceAuthorization(reply: FastifyReply, pendingContext: PendingAuthorizationContext): Promise<void> {
				this.authenticationProvider.setPendingAuthorizationContext?.(pendingContext);

				// correlationId ties this authorization request to its PrivateID session without depending on Bookwrm.
				const correlationId = randomUUID();
				storeCorrelation(correlationId, pendingContext);

				const beginAsyncAuthentication = this.authenticationProvider.beginAsyncAuthentication?.bind(this.authenticationProvider);
				if (!beginAsyncAuthentication) {
						throw new Error("Authentication provider does not support asynchronous authorization");
				}

				const asyncSession = await beginAsyncAuthentication(correlationId);
				const browserReturn = storePrivateIDBrowserReturn(asyncSession.sessionId);
				if (browserReturn) reply.header("Set-Cookie",
					`${PRIVATEID_BROWSER_RETURN_COOKIE}=${browserReturn}; Path=/privateid/callback; Max-Age=300; HttpOnly; Secure; SameSite=Lax`);

				reply.redirect(asyncSession.launchUrl, 302);
		}

		private isUniversalLoginEnabled(): boolean {
				return configuration.getFeatureFlag("HAPI_UNIVERSAL_LOGIN_ENABLED", false);
		}

		private interactionCookie(handle: string | null): string {
				return handle
						? `${UNIVERSAL_LOGIN_COOKIE}=${handle}; Path=/; Max-Age=${AUTHORIZATION_INTERACTION_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`
						: `${UNIVERSAL_LOGIN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
		}

		private readInteractionHandle(request: FastifyRequest): string | undefined {
				return request.headers.cookie?.split(";").map(value => value.trim())
						.find(value => value.startsWith(`${UNIVERSAL_LOGIN_COOKIE}=`))?.slice(UNIVERSAL_LOGIN_COOKIE.length + 1);
		}

		private async createAuthorizationInteraction(app: FastifyInstance, clientId: string,
				authorization: PendingAuthorizationContext, query: AuthorizationQuery): Promise<string> {
				let binding: AuthorizationInteractionBinding | undefined;
				const interactive = this.emailAuthentication?.interactive;
				if (interactive) {
						try {
								const authority = await interactive.authority(clientId);
								if (authority.context.applicationId) binding = {
										tenantId: authority.context.tenantId,
										applicationId: authority.context.applicationId,
										tenantName: authority.tenantName
								};
						} catch (error) {
								if (!(error instanceof VerificationError)) throw error;
								app.log.warn({ event: "UNIVERSAL_LOGIN_EMAIL_UNAVAILABLE_FOR_CLIENT", clientId }, "Universal Login email unavailable for client");
						}
				}
				const { handle } = await this.interactions.create({
						clientId,
						binding,
						authorization,
						request: {
								client_id: clientId,
								redirect_uri: authorization.redirectUri,
								response_type: query.response_type ?? "",
								scope: query.scope ?? "",
								...(query.state !== undefined ? { state: query.state } : {}),
								...(query.nonce !== undefined ? { nonce: query.nonce } : {}),
								...(query.code_challenge !== undefined ? { code_challenge: query.code_challenge } : {}),
								...(query.code_challenge_method !== undefined ? { code_challenge_method: query.code_challenge_method } : {})
						}
				});
				app.log.info({ event: "UNIVERSAL_LOGIN_INTERACTION_CREATED", clientId, emailAvailable: Boolean(binding) }, "Universal Login interaction created");
				logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_CREATED", route: "GET /authorize", clientId,
					correlationId: diagnosticCorrelationId(handle), remainingTtlBucket: ">300s" });
				return handle;
		}

		// The client and redirect_uri bound at GET /authorize must still be registered when the interaction completes.
		private async interactionClientStillValid(interaction: AuthorizationInteraction): Promise<boolean> {
				const client = await this.resolveClient(interaction.clientId);
				if (!client || !this.clientAllowsAuthorizationCodeGrant(client)) return false;
				const redirectUris = this.extractRedirectUris(client);
				return redirectUris.length === 0 || redirectUris.includes(interaction.authorization.redirectUri);
		}

		private async interactiveEmailAuthority(interaction: AuthorizationInteraction): Promise<InteractiveEmailAuthority | null> {
				const interactive = this.emailAuthentication?.interactive;
				if (!interactive || !interaction.binding) return null;
				let authority: InteractiveEmailAuthority;
				try {
						authority = await interactive.authority(interaction.clientId);
				} catch (error) {
						if (error instanceof VerificationError) return null;
						throw error;
				}
				return authority.clientId === interaction.clientId &&
						authority.context.tenantId === interaction.binding.tenantId &&
						authority.context.applicationId === interaction.binding.applicationId ? authority : null;
		}

		private registerUniversalLogin(app: FastifyInstance): void {
				const send = (reply: FastifyReply, status: number, page: RenderedLoginPage) => reply.code(status)
						.header("Cache-Control", "no-store").header("Pragma", "no-cache")
						.header("Referrer-Policy", "no-referrer").header("X-Frame-Options", "DENY")
						.header("Content-Security-Policy", page.contentSecurityPolicy)
						.type("text/html; charset=utf-8").send(page.html);
				const expired = (reply: FastifyReply) => {
						reply.header("Set-Cookie", this.interactionCookie(null));
						return send(reply, 400, messagePage({
								title: "This sign-in request has expired",
								message: "Return to the application you were signing in to and start again."
						}));
				};
				const unavailable = (reply: FastifyReply) => send(reply, 503, messagePage({
						title: "Sign-in is temporarily unavailable", message: "Please try again in a few minutes."
				}));
				const tooMany = (reply: FastifyReply, interaction: AuthorizationInteraction, page: "email" | "code") => send(reply, 429,
						(page === "email" ? emailPage : codePage)({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
								error: "Too many attempts. Please wait a few minutes and try again." }));
				const emailFailed = "We couldn't sign you in with that code. Check the code, request a new one, or use a different email.";
				const statusOf = (error: unknown) => typeof (error as { statusCode?: unknown })?.statusCode === "number"
						? (error as { statusCode: number }).statusCode : 500;
				const logLogin = (request: FastifyRequest, flow: string, interaction: AuthorizationInteraction | null,
						startedAt: number, success: boolean, error: string, user = "") => this.logOidcRequest(app, {
						requestId: request.id, clientId: interaction?.clientId ?? "", flow, latency: Date.now() - startedAt,
						success, error, user, pkce: interaction?.authorization.codeChallenge ? "S256" : "missing",
						correlationId: this.correlationIdFor(request)
				});
				// Loads the live interaction for the browser and enforces the flag, CSRF and rate limits.
				const load = async (request: FastifyRequest, reply: FastifyReply, mutation: boolean, routeLabel: string) => {
						if (!this.isUniversalLoginEnabled()) {
								reply.code(404).send({ error: "not_found" });
								return null;
						}
						const handle = this.readInteractionHandle(request);
						const cookiePresent = Boolean(handle);
						const correlationId = diagnosticCorrelationId(handle);
						// Diagnostics-only read, captured before find()'s own expiry cleanup can delete the key.
						const probe = handle ? await this.interactions.inspect(handle) : null;
						const interaction = await this.interactions.find(handle);
						if (!interaction || !handle) {
								logUniversalLoginDiagnostic(app, {
										event: "UNIVERSAL_LOGIN_INTERACTION_LOADED", route: routeLabel, correlationId, cookiePresent,
										interactionFound: false,
										remainingTtlBucket: probe ? bucketRemainingTtl(probe.remainingMs) : "unknown",
										reasonCode: !cookiePresent ? "COOKIE_MISSING"
												: probe?.state === "expired" ? "INTERACTION_EXPIRED"
												: probe?.state === "consumed" ? "INTERACTION_ALREADY_CONSUMED"
												: "INTERACTION_NOT_FOUND"
								});
								expired(reply);
								return null;
						}
						logUniversalLoginDiagnostic(app, {
								event: "UNIVERSAL_LOGIN_INTERACTION_LOADED", route: routeLabel, clientId: interaction.clientId, correlationId,
								cookiePresent, interactionFound: true, remainingTtlBucket: bucketRemainingTtl(interaction.expiresAt - Date.now())
						});
						if (mutation) {
								const body = (request.body ?? {}) as Record<string, unknown>;
								if (!AuthorizationInteractionStore.csrfMatches(interaction, body.csrf)) {
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: routeLabel,
												clientId: interaction.clientId, correlationId, csrfValid: false, reasonCode: "CSRF_MISMATCH" });
										expired(reply);
										return null;
								}
								await this.rateLimiter.assertWithinLimits({ ip: request.ip, clientId: interaction.clientId, userId: "" });
						}
						return { handle, interaction, body: (request.body ?? {}) as Record<string, unknown> };
				};

				app.get("/login", async (request, reply) => {
						const loaded = await load(request, reply, false, "GET /login");
						if (!loaded) return reply;
						const { interaction } = loaded;
						return send(reply, 200, chooserPage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
								emailAvailable: Boolean(interaction.binding && this.emailAuthentication?.interactive) }));
				});

				app.get("/login/email", async (request, reply) => {
						const loaded = await load(request, reply, false, "GET /login/email");
						if (!loaded) return reply;
						const { interaction } = loaded;
						if (!interaction.binding || !this.emailAuthentication?.interactive) return reply.redirect("/login", 303);
						return send(reply, 200, emailPage({ tenantName: interaction.binding.tenantName, csrf: interaction.csrf }));
				});

				app.post("/login/email", { bodyLimit: 4096 }, async (request, reply) => {
						const startedAt = Date.now();
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, "POST /login/email");
								if (!loaded) return reply;
								interaction = loaded.interaction;
								const correlationId = diagnosticCorrelationId(loaded.handle);
								const authority = await this.interactiveEmailAuthority(interaction);
								if (!authority) {
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/email",
												clientId: interaction.clientId, correlationId, authorityValid: false, reasonCode: "AUTHORITY_INVALID" });
										return expired(reply);
								}
								const email = universalLoginEmailSchema.safeParse(loaded.body.email);
								if (!email.success) {
										return send(reply, 400, emailPage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
												error: "Enter a valid email address." }));
								}
								const started = await this.emailAuthentication!.interactive!.start(authority, email.data);
								if (!await this.interactions.save(loaded.handle, { ...interaction,
									email: { challengeId: started.challengeId, mode: started.mode } })) {
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/email",
												clientId: interaction.clientId, correlationId, authorityValid: true, reasonCode: "INTERACTION_SAVE_FAILED" });
										return expired(reply);
								}
								logLogin(request, "universal_login_email_start", interaction, startedAt, true, "");
								logUniversalLoginDiagnostic(app, { event: "EMAIL_FLOW_STARTED", route: "POST /login/email",
										clientId: interaction.clientId, correlationId, authenticationMethod: "email" });
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_EMAIL_STARTED", route: "POST /login/email",
										clientId: interaction.clientId, correlationId, authorityValid: true, authenticationMethod: "email" });
								return reply.header("Cache-Control", "no-store").redirect("/login/email/code", 303);
						} catch (error) {
								logUniversalLoginDiagnostic(app, { event: "EMAIL_FLOW_FAILED", route: "POST /login/email",
										clientId: interaction?.clientId,
										correlationId: diagnosticCorrelationId(this.readInteractionHandle(request)),
										authenticationMethod: "email" });
								logLogin(request, "universal_login_email_start", interaction, startedAt, false, error instanceof VerificationError ? error.code : "unavailable");
								if (interaction && statusOf(error) === 429) return tooMany(reply, interaction, "email");
								if (interaction && error instanceof VerificationError && error.statusCode < 500) {
										return send(reply, 400, emailPage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
												error: "Enter a valid email address." }));
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_EMAIL_UNAVAILABLE" }, "Universal Login email start failed");
								return unavailable(reply);
						}
				});

				app.get("/login/email/code", async (request, reply) => {
						const loaded = await load(request, reply, false, "GET /login/email/code");
						if (!loaded) return reply;
						const { interaction } = loaded;
						if (!interaction.email) return reply.redirect("/login/email", 303);
						return send(reply, 200, codePage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf }));
				});

				app.post("/login/email/resend", { bodyLimit: 4096 }, async (request, reply) => {
						const startedAt = Date.now();
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, "POST /login/email/resend");
								if (!loaded) return reply;
								interaction = loaded.interaction;
								const authority = await this.interactiveEmailAuthority(interaction);
								if (!authority || !interaction.email) return expired(reply);
								await this.emailAuthentication!.interactive!.resend(authority, interaction.email.challengeId, interaction.email.mode);
								logLogin(request, "universal_login_email_resend", interaction, startedAt, true, "");
								return send(reply, 200, codePage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
										notice: "We sent a new code. Earlier codes no longer work." }));
						} catch (error) {
								logUniversalLoginDiagnostic(app, { event: "EMAIL_FLOW_FAILED", route: "POST /login/email/resend",
										clientId: interaction?.clientId,
										correlationId: diagnosticCorrelationId(this.readInteractionHandle(request)),
										authenticationMethod: "email" });
								logLogin(request, "universal_login_email_resend", interaction, startedAt, false, error instanceof VerificationError ? error.code : "unavailable");
								if (interaction && error instanceof VerificationError && error.statusCode < 500) {
										return send(reply, statusOf(error) === 429 ? 429 : 400, codePage({ tenantName: interaction.binding?.tenantName,
												csrf: interaction.csrf, error: statusOf(error) === 429
														? "Please wait before requesting another code."
														: "A new code can't be sent for this request. Use a different email or start again." }));
								}
								if (interaction && statusOf(error) === 429) return tooMany(reply, interaction, "code");
								app.log.error({ event: "UNIVERSAL_LOGIN_EMAIL_UNAVAILABLE" }, "Universal Login email resend failed");
								return unavailable(reply);
						}
				});

				app.post("/login/email/code", { bodyLimit: 4096 }, async (request, reply) => {
						const startedAt = Date.now();
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, "POST /login/email/code");
								if (!loaded) return reply;
								interaction = loaded.interaction;
								const correlationId = diagnosticCorrelationId(loaded.handle);
								const authority = await this.interactiveEmailAuthority(interaction);
								const clientValid = await this.interactionClientStillValid(interaction);
								const mode = interaction.email?.mode;
								if (!authority || !interaction.email || !isInteractiveEmailMode(mode) || !clientValid) {
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/email/code",
												clientId: interaction.clientId, correlationId, authorityValid: Boolean(authority), clientValid,
												reasonCode: !authority ? "AUTHORITY_INVALID" : !clientValid ? "CLIENT_INVALID" : "AUTHORITY_INVALID" });
										return expired(reply);
								}
								const code = typeof loaded.body.code === "string" && loaded.body.code.length <= 128 ? loaded.body.code.trim() : "";
								const interactive = this.emailAuthentication!.interactive!;
								const verification = await interactive.verify(authority, interaction.email.challengeId, code, mode);
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_EMAIL_VERIFIED", route: "POST /login/email/code",
										clientId: interaction.clientId, correlationId, authorityValid: true, clientValid: true, authenticationMethod: "email" });
								// Single-use: only the request that wins the interaction may turn the H4 result into an authorization code.
								const consumed = await this.interactions.consume(loaded.handle);
								if (!consumed) {
										logLogin(request, "universal_login_email", interaction, startedAt, false, "interaction_replayed");
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/email/code",
												clientId: interaction.clientId, correlationId, reasonCode: "INTERACTION_ALREADY_CONSUMED" });
										return expired(reply);
								}
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_CONSUMED", route: "POST /login/email/code",
										clientId: interaction.clientId, correlationId });
								const principal = verification.mode === "REGISTRATION" ? verification.principal
									: await interactive.consumeResult(authority, verification.authenticationResult);
								logUniversalLoginDiagnostic(app, {
									event: verification.mode === "REGISTRATION" ? "EMAIL_REGISTRATION_COMPLETED" : "EMAIL_AUTHENTICATION_COMPLETED",
									route: "POST /login/email/code", clientId: interaction.clientId, correlationId,
									authenticationMethod: "email"
								});
								const redirect = await this.issueAuthorizationRedirect(principal, consumed.authorization);
								logLogin(request, "universal_login_email", consumed, startedAt, true, "", principal.id);
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_OIDC_REDIRECT_ISSUED", route: "POST /login/email/code",
										clientId: interaction.clientId, correlationId, authenticationMethod: "email", httpStatus: 303 });
								reply.header("Set-Cookie", this.interactionCookie(null));
								return reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer").redirect(redirect, 303);
						} catch (error) {
								const failed = error instanceof VerificationError || error instanceof EmailAuthenticationError;
								logUniversalLoginDiagnostic(app, { event: "EMAIL_FLOW_FAILED", route: "POST /login/email/code",
										clientId: interaction?.clientId, correlationId: diagnosticCorrelationId(this.readInteractionHandle(request)),
										authenticationMethod: "email" });
								logLogin(request, "universal_login_email", interaction, startedAt, false,
										failed ? "email_authentication_failed" : statusOf(error) === 429 ? "rate_limited" : "unavailable");
								if (interaction && statusOf(error) === 429 && !failed) return tooMany(reply, interaction, "code");
								if (interaction && failed) {
										return send(reply, 401, codePage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf, error: emailFailed }));
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_EMAIL_UNAVAILABLE" }, "Universal Login email verification failed");
								return unavailable(reply);
						}
				});

				app.post("/login/face", { bodyLimit: 4096 }, async (request, reply) => {
						const startedAt = Date.now();
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, "POST /login/face");
								if (!loaded) return reply;
								interaction = loaded.interaction;
								const correlationId = diagnosticCorrelationId(loaded.handle);
								const clientValid = await this.interactionClientStillValid(interaction);
								if (!clientValid) {
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/face",
												clientId: interaction.clientId, correlationId, clientValid: false, reasonCode: "CLIENT_INVALID" });
										return expired(reply);
								}
								const consumed = await this.interactions.consume(loaded.handle);
								if (!consumed) {
										logLogin(request, "universal_login_face", interaction, startedAt, false, "interaction_replayed");
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/face",
												clientId: interaction.clientId, correlationId, reasonCode: "INTERACTION_ALREADY_CONSUMED" });
										return expired(reply);
								}
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_CONSUMED", route: "POST /login/face",
										clientId: interaction.clientId, correlationId, authenticationMethod: "face" });
								reply.header("Set-Cookie", this.interactionCookie(null));
								reply.header("Cache-Control", "no-store");
								await this.beginFaceAuthorization(reply, consumed.authorization);
								logLogin(request, "universal_login_face", consumed, startedAt, true, "");
								return reply;
						} catch (error) {
								logLogin(request, "universal_login_face", interaction, startedAt, false, statusOf(error) === 429 ? "rate_limited" : "unavailable");
								if (interaction && statusOf(error) === 429) {
										return send(reply, 429, chooserPage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
												emailAvailable: Boolean(interaction.binding && this.emailAuthentication?.interactive),
												error: "Too many attempts. Please wait a few minutes and try again." }));
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_FACE_UNAVAILABLE" }, "Universal Login face start failed");
								return unavailable(reply);
						}
				});
		}

		// Resumes the same authorization-code path /authorize uses once a PrivateID session completes.
		async resumePendingAuthorization(privateIdSessionId: string): Promise<string | null> {
				const pendingContext = consumePendingAuthorizationRequest(privateIdSessionId);
				if (!pendingContext) {
						return null;
				}

				const user = getPrivateIDAuthenticatedUser(privateIdSessionId);
				if (!user) {
						return null;
				}

				return this.issueAuthorizationRedirect(user, pendingContext);
		}

		// Release Patch 6.1: sole point where /token and /userinfo pull mutable claims -- always a live
		// Identity Registry read by oidcSubject, never a cached/snapshotted value.
		private async resolveCurrentClaims(oidcSubject: string): Promise<{ email?: string; emailVerified?: boolean; name?: string }> {
				const subject = await identityRegistry.findByOidcSubject(oidcSubject);
				if (!subject) {
						return {};
				}

				return {
						email: subject.email,
						emailVerified: subject.emailVerified,
						name: subject.displayName
				};
		}

		// Release Patch 6.2: read-only diagnostics snapshot for /diagnostics/claims -- reuses resolveCurrentClaims
		// and claimsService.toOIDCClaims (the exact code paths /token and /userinfo run) rather than duplicating them.
		async getClaimsSnapshot(oidcSubject: string): Promise<{
				identityRegistry: { sub: string; email?: string; emailVerified?: boolean; name?: string };
				idTokenClaims: { sub: string; email?: string; email_verified?: boolean; name?: string };
				userInfoClaims: { sub: string; email?: string; email_verified?: boolean; name?: string };
		}> {
				const currentClaims = await this.resolveCurrentClaims(oidcSubject);
				const claims = await this.claimsService.toOIDCClaims({
						id: oidcSubject,
						sub: oidcSubject,
						email: currentClaims.email,
						emailVerified: currentClaims.emailVerified,
						name: currentClaims.name
				});

				return {
						identityRegistry: { sub: oidcSubject, ...currentClaims },
						idTokenClaims: {
								sub: claims.sub,
								...(claims.email !== undefined ? { email: claims.email } : {}),
								...(claims.emailVerified !== undefined ? { email_verified: claims.emailVerified } : {}),
								...(claims.name !== undefined ? { name: claims.name } : {})
						},
						userInfoClaims: {
								sub: oidcSubject,
								...(currentClaims.email !== undefined ? { email: currentClaims.email } : {}),
								...(currentClaims.emailVerified !== undefined ? { email_verified: currentClaims.emailVerified } : {}),
								...(currentClaims.name !== undefined ? { name: currentClaims.name } : {})
						}
				};
		}

		private createOpaqueToken(): string {
				return randomBytes(32).toString("base64url");
		}

		private toS256CodeChallenge(verifier: string): string {
				return createHash("sha256").update(verifier).digest("base64url");
		}

		private async resolveClient(clientId: string, emailAuthentication = false): Promise<OIDCClient | null> {
				if (emailAuthentication && !this.options.clients) {
						const persisted = await this.oidcClients.findByClientId(clientId);
						if (persisted) return this.toOIDCClient(persisted);
				}
				const clients = await this.configureClients();
				const client = clients.find((candidate) => {
						return typeof candidate.client_id === "string" && candidate.client_id === clientId;
				});

				return client ?? null;
		}

		private extractRedirectUris(client: OIDCClient): string[] {
				const redirectUris = client.redirect_uris;

				if (!Array.isArray(redirectUris)) {
						return [];
				}

				return redirectUris.filter((value): value is string => typeof value === "string");
		}

		private extractScopes(client: OIDCClient): string[] {
				if (typeof client.scope !== "string") {
						return [];
				}

				return client.scope
						.split(" ")
						.map((scope) => scope.trim())
						.filter((scope) => scope.length > 0);
		}

		private clientAllowsAuthorizationCodeGrant(client: OIDCClient): boolean {
				const grants = client.grant_types;

				if (!Array.isArray(grants)) {
						return true;
				}

				return grants.includes("authorization_code");
		}

		private clientRequiresPkce(client: OIDCClient): boolean {
				if (typeof client.require_pkce === "boolean") {
						return client.require_pkce;
				}

				return true;
		}

		private buildIdTokenPayload(input: {
			issuer: string;
			subject: string;
			audience: string;
			nonce: string;
			scope: string;
		email?: string;
			emailVerified?: boolean;
			name?: string;
			iat: number;
			exp: number;
			authenticationMethod?: "HAPI_EMAIL" | "PRIVATEID_FACE";
			authenticatedAt?: string;
		}): Record<string, unknown> {
			return {
				iss: input.issuer,
				sub: input.subject,
				aud: input.audience,
				nonce: input.nonce,
				scope: input.scope,
				...(input.email !== undefined ? { email: input.email } : {}),
				...(input.emailVerified !== undefined ? { email_verified: input.emailVerified } : {}),
				...(input.name !== undefined ? { name: input.name } : {}),
				iat: input.iat,
				exp: input.exp,
				...(input.authenticationMethod && input.authenticatedAt ? {
					amr: input.authenticationMethod === "HAPI_EMAIL" ? ["email"] : ["face", "privateid"],
					auth_time: Math.floor(Date.parse(input.authenticatedAt) / 1000)
				} : {})
			};
		}

		private async createIdToken(input: {
			issuer: string;
			subject: string;
			audience: string;
			nonce: string;
			scope: string;
			email?: string;
			emailVerified?: boolean;
			name?: string;
			iat: number;
			exp: number;
			authenticationMethod?: "HAPI_EMAIL" | "PRIVATEID_FACE";
			authenticatedAt?: string;
		}): Promise<string> {
			const signing = await this.getSigningMaterial();
			const payload = this.buildIdTokenPayload(input);

			const header = {
				alg: "RS256",
				typ: "JWT",
				kid: signing.kid
			};

			const encodedHeader = this.base64UrlJson(header);
			const encodedPayload = this.base64UrlJson(payload);
			const signingInput = `${encodedHeader}.${encodedPayload}`;
			const signer = createSign("RSA-SHA256");
			signer.update(signingInput);
			signer.end();
			const signature = signer.sign(signing.privateKey).toString("base64url");

			return `${signingInput}.${signature}`;
		}


		// RFC 6749 §2.3.1: decodes an HTTP Basic Authorization header into client_secret_basic credentials.
		private parseBasicClientCredentials(authorizationHeader?: string): { clientId: string; clientSecret: string } | undefined {
				if (!authorizationHeader || !authorizationHeader.startsWith("Basic ")) {
						return undefined;
				}

				const encoded = authorizationHeader.slice("Basic ".length).trim();
				if (!encoded) {
						return undefined;
				}

				let decoded: string;
				try {
						decoded = Buffer.from(encoded, "base64").toString("utf8");
				} catch {
						return undefined;
				}

				const separatorIndex = decoded.indexOf(":");
				if (separatorIndex === -1) {
						return undefined;
				}

				const clientId = this.tryDecodeUriComponent(decoded.slice(0, separatorIndex));
				const clientSecret = this.tryDecodeUriComponent(decoded.slice(separatorIndex + 1));
				if (!clientId) {
						return undefined;
				}

				return { clientId, clientSecret };
		}

		private tryDecodeUriComponent(value: string): string {
				try {
						return decodeURIComponent(value);
				} catch {
						return value;
				}
		}

		private async getSigningMaterial(): Promise<{ privateKey: KeyObject; kid: string }> {
				return this.keyRotationService.getSigningKey();
		}

		private base64UrlJson(payload: Record<string, unknown>): string {
				return Buffer.from(JSON.stringify(payload)).toString("base64url");
		}

		private async storeAuthorizationCode(code: Omit<OIDCAuthorizationCode, "expiresAt" | "consumed">): Promise<void> {
				await this.redisStore.storeAuthorizationCode(code, OIDCService.AUTHORIZATION_CODE_TTL_MS);
		}

		private async consumeAuthorizationCode(code: string): Promise<OIDCAuthorizationCode | null> {
				return this.redisStore.consumeAuthorizationCode(code);
		}

		private async storeAccessToken(accessToken: string, tokenRecord: Omit<AccessTokenRecord, "expiresAt">): Promise<void> {
				await this.redisStore.storeAccessToken(accessToken, tokenRecord, OIDCService.ACCESS_TOKEN_TTL_MS);
		}

		private async getAccessTokenRecord(accessToken: string): Promise<AccessTokenRecord | null> {
				return this.redisStore.getAccessTokenRecord(accessToken);
		}

		private async storeRefreshToken(refreshToken: string, tokenRecord: Omit<RefreshTokenRecord, "expiresAt">): Promise<void> {
				await this.redisStore.storeRefreshToken(refreshToken, tokenRecord, OIDCService.REFRESH_TOKEN_TTL_MS);
		}

		private correlationIdFor(request: { headers: Record<string, unknown>; id: string }): string {
				const raw = request.headers["x-correlation-id"] ?? request.headers["x-request-id"];
				return typeof raw === "string" && raw.trim().length > 0 ? raw.trim() : request.id;
		}

		private replySucceeded(reply: { statusCode: number }): boolean {
				if (reply.statusCode === 0) {
						return true;
				}

				return reply.statusCode < 400;
		}

		private logOidcRequest(app: FastifyInstance, entry: OIDCLogEntry): void {
				if (!entry.success) {
						this.metrics.errors += 1;
				}

				recordOIDCRequest(
						{
								flow: entry.flow,
								client_id: entry.clientId || "unknown",
								status: entry.success ? "success" : "error"
						},
						entry.latency
				);

				void this.redisStore.pushAuditLog(entry);

				app.log.info({
						RequestId: entry.requestId,
						ClientId: entry.clientId,
						Flow: entry.flow,
						Latency: entry.latency,
						Success: entry.success,
						Error: entry.error,
						User: entry.user,
						PKCE: entry.pkce,
						CorrelationId: entry.correlationId
				}, "OIDC request");
		}

		async getDashboardSnapshot(): Promise<OIDCDashboardSnapshot> {
				const issuer = this.resolveIssuer();
				const configuredClients = await this.configureClients();
				const clients = configuredClients.map((client) => {
						const clientId = typeof client.client_id === "string" ? client.client_id : "";
						const redirectUris = this.extractRedirectUris(client);
						const scopes = this.extractScopes(client);
						const grantTypes = Array.isArray(client.grant_types)
								? client.grant_types.filter((value): value is string => typeof value === "string")
								: [];
						const tokenEndpointAuthMethod =
								typeof client.token_endpoint_auth_method === "string"
										? client.token_endpoint_auth_method
										: "client_secret_post";

						return {
								clientId,
								redirectUris,
								scopes,
								grantTypes,
								pkceRequired: this.clientRequiresPkce(client),
								tokenEndpointAuthMethod
						};
				});

				const discovery = `${issuer}/.well-known/openid-configuration`;
				const jwks = `${issuer}/jwks`;
				const hasSigningConfig = this.hasSigningKeyConfiguration();
				const health = Boolean(this.provider) && hasSigningConfig;
				const redisConfigured = featureFlags.isRedisEnabled();
				const redisHealthy = redisConfigured ? await this.checkRedisHealth() : true;
				const cacheSnapshot = identityCache.getSnapshot();
				const breakerSnapshot = identityCircuitBreaker.getSnapshot();

				return {
						clients,
						issuer,
						discovery,
						jwks,
						authorizationRequests: this.metrics.authorizationRequests,
						tokensIssued: this.metrics.tokensIssued,
						errors: this.metrics.errors,
						health,
						infrastructure: {
							redis: {
								enabled: redisConfigured,
								healthy: redisHealthy,
								configured: Boolean(configuration.getRedisConfiguration().url || configuration.getRedisConfiguration().host)
							},
							cache: cacheSnapshot,
							circuitBreaker: breakerSnapshot,
							health: {
								providerReady: Boolean(this.provider),
								signingKeysLoaded: hasSigningConfig
							},
							metrics: {
								enabled: featureFlags.isMetricsEnabled(),
								requestCount: this.metrics.authorizationRequests + this.metrics.tokensIssued,
								errorCount: this.metrics.errors
							},
							keyRotation: {
								enabled: hasSigningConfig,
								issuer
							},
							featureFlags: {
								oidcEnabled: featureFlags.isOidcEnabled(),
								mockMode: featureFlags.isPrivateIdMockMode(),
								mockAuthEnabled: featureFlags.isMockAuthEnabled(),
								redisEnabled: featureFlags.isRedisEnabled(),
								cacheEnabled: featureFlags.isCacheEnabled(),
								metricsEnabled: featureFlags.isMetricsEnabled()
							}
						}
				};
		}

		private hasSigningKeyConfiguration(): boolean {
				const hasInjectedKeys = Boolean(this.options.signingKeys && this.options.signingKeys.length > 0);
				const keyConfig = configuration.getOIDCKeyConfiguration();
				const hasPrivateKeyEnv = keyConfig.privateKey.length > 0;
				const hasJwksEnv = Boolean(keyConfig.jwksJson);

				return hasInjectedKeys || hasPrivateKeyEnv || hasJwksEnv;
		}

		private async checkRedisHealth(): Promise<boolean> {
				try {
						await getRedisClient().ping();
						return true;
				} catch {
						return false;
				}
		}

		hasSigningKeysAvailable(): boolean {
				return this.hasSigningKeyConfiguration();
		}

		isProviderReady(): boolean {
				return Boolean(this.provider);
		}
}
