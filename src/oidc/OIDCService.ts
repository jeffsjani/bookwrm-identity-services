import type { FastifyInstance } from "fastify";
import {
		createHash,
		createPrivateKey,
		createPublicKey,
		createSign,
		randomBytes,
		type KeyObject
} from "node:crypto";
import Provider from "oidc-provider";

import type { AuthenticationProvider, AuthenticatedUser, PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityCache } from "../cache/IdentityCache.js";
import type { OIDCAuthorizationCode } from "../models/OIDCAuthorizationCode.js";
import { ClaimsService } from "./ClaimsService.js";
import { oidcClaims } from "./claims.js";
import { registerOIDCClients } from "./clients.js";
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
import { PrivateIDAuthenticationProvider } from "../privateid/PrivateIDAuthenticationProvider.js";
import { consumePendingAuthorizationRequest, getPrivateIDAuthenticatedUser } from "../privateid/PrivateIDSessionStore.js";

export type OIDCClient = Record<string, unknown>;
export type OIDCSigningKey = JsonWebKey;
export type OIDCPublicKey = JsonWebKey;

export type OIDCServiceOptions = {
		issuer?: string;
		mountPath?: string;
		clients?: OIDCClient[];
		signingKeys?: OIDCSigningKey[];
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

export type OIDCBase44IntegrationStatus = {
		issuer: string;
		clientConfigured: boolean;
		base44ToOidc: boolean;
		oidcToBookwrmIdentityServices: boolean;
		authenticatedSession: boolean;
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
		private readonly claimsService: ClaimsService;
		private readonly redisStore: RedisOIDCStore;
		private readonly lockService: RedisLockService;
		private readonly rateLimiter: OIDCRateLimiter;
		private readonly keyRotationService: OIDCKeyRotationService;
		private readonly providerAdapter = new RedisOIDCProviderAdapter();
		private readonly metrics: OIDCMetrics = {
				authorizationRequests: 0,
				tokensIssued: 0,
				errors: 0
		};

		constructor(options: OIDCServiceOptions = {}) {
				this.options = options;
				this.authenticationProvider = new PrivateIDAuthenticationProvider();
				this.claimsService = new ClaimsService();
				this.redisStore = new RedisOIDCStore();
				this.lockService = new RedisLockService();
				this.rateLimiter = new OIDCRateLimiter();
				this.keyRotationService = new OIDCKeyRotationService();
		}

		async configureProvider(): Promise<Provider> {
				this.assertSigningKeyConfiguration();

				const issuer = this.resolveIssuer();
				const clients = this.configureClients();
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
				app.get("/authorize", async (request, reply) => {
						const startedAt = Date.now();
						let error = "";
						let userId = "";
						this.metrics.authorizationRequests += 1;
						const query = request.query as AuthorizationQuery;
						const clientId = query.client_id?.trim();
						const redirectUri = query.redirect_uri;
						const responseType = query.response_type;
						const codeChallenge = query.code_challenge?.trim();
						const codeChallengeMethod = query.code_challenge_method;
						const requestedScopes = (query.scope ?? "")
								.split(" ")
								.map((scope) => scope.trim())
								.filter((scope) => scope.length > 0);

						// TEMP-AUDIT-LOG: /authorize 500 investigation - remove once root cause is fixed.
						const auditSnapshot = () => ({
								client_id: clientId ?? "(missing)",
								redirect_uri: redirectUri ?? "(missing)",
								scope: query.scope ?? "",
								statePresent: Boolean(query.state),
								pkceChallengePresent: Boolean(codeChallenge),
								correlationId: this.correlationIdFor(request)
						});

						try {
								app.log.warn({ ...auditSnapshot(), stage: "before_initial_rate_limit_check" }, "authorize audit checkpoint");
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

								app.log.warn({ ...auditSnapshot(), stage: "before_resolve_client" }, "authorize audit checkpoint");
								const client = this.resolveClient(clientId);
								if (!client) {
										reply.code(400);
										error = "Unknown client";
										return { error: "invalid_client", error_description: "Unknown client" };
								}

								const allowedRedirectUris = this.extractRedirectUris(client);
								if (allowedRedirectUris.length > 0 && !allowedRedirectUris.includes(redirectUri)) {
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

								this.authenticationProvider.setPendingAuthorizationContext?.({
										clientId,
										redirectUri,
										scope: query.scope ?? "",
										nonce: query.nonce ?? "",
										codeChallenge: codeChallenge ?? "",
										state: query.state
								});

								// TEMP-AUDIT-LOG: Sprint 8.15 - non-polling OIDC authorize flow.
								app.log.info({ ...auditSnapshot(), stage: "oidc_authorize_started" }, "OIDC Authorize Started");

								const beginAsyncAuthentication = this.authenticationProvider.beginAsyncAuthentication?.bind(this.authenticationProvider);
								if (!beginAsyncAuthentication) {
										throw new Error("Authentication provider does not support asynchronous authorization");
								}

								// TEMP-AUDIT-LOG: Sprint 8.15.1 - runtime proof of which authentication method is invoked.
								app.log.info("AUTH FLOW: beginAsyncAuthentication");
								const asyncSession = await beginAsyncAuthentication();
								app.log.info({ ...auditSnapshot(), stage: "privateid_session_created", sessionId: asyncSession.sessionId }, "PrivateID Session Created");
								app.log.info({ ...auditSnapshot(), stage: "pending_authorization_stored", sessionId: asyncSession.sessionId }, "Pending Authorization Stored");
								app.log.info({ ...auditSnapshot(), stage: "returning_launch_url", sessionId: asyncSession.sessionId }, "Returning Launch URL");

								reply.redirect(asyncSession.launchUrl, 302);
						} catch (err) {
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
				});
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

								const userInfoResponse = {
										sub: tokenRecord.sub,
										email: tokenRecord.email,
										email_verified: tokenRecord.emailVerified,
										name: tokenRecord.name
								};
								app.log.info(userInfoResponse, "TEMP-OIDC-USERINFO");
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
						const tokenAuthMethodUsed = basicCredentials ? "client_secret_basic" : "client_secret_post";

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

								// TEMP-AUDIT-LOG: Sprint 8.16 - runtime proof of token endpoint client authentication method.
								if (clientId) {
										app.log.info(`TOKEN AUTH METHOD: ${tokenAuthMethodUsed}`);
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

								const client = this.resolveClient(clientId);
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
								// Sprint 8.15: the code record already reflects the PrivateID-authenticated user; no re-authentication needed.
							const authenticatedUser: AuthenticatedUser = {
									id: codeRecord.userId,
									sub: codeRecord.userSub,
									email: codeRecord.userEmail,
									emailVerified: codeRecord.userEmailVerified,
									name: codeRecord.userName
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
									email: claims.email,
									emailVerified: claims.emailVerified,
									name: claims.name,
									clientId,
									nonce: codeRecord.nonce,
									scope: codeRecord.scope
							});
							await this.storeRefreshToken(refreshToken, {
									userId: codeRecord.userId,
									clientId,
									scope: codeRecord.scope
							});
						app.log.info({
							sub: codeRecord.userId,
							email: claims.email,
							email_verified: claims.emailVerified,
							name: claims.name,
							preferred_username: claims.email,
							iss: issuer,
							aud: clientId,
							scope: codeRecord.scope,
							nonce: codeRecord.nonce
						}, "TEMP-OIDC-IDTOKEN");
							const idToken = await this.createIdToken({
							issuer,
							subject: codeRecord.userId,
							audience: clientId,
							nonce: codeRecord.nonce,
							scope: codeRecord.scope,
							email: claims.email,
							emailVerified: claims.emailVerified,
							iat: now,
							exp: now + 300
						});

							reply.code(200);
							this.metrics.tokensIssued += 1;
						app.log.info({
							userId: codeRecord.userId,
							email: claims.email,
							emailVerified: claims.emailVerified
						}, "TEMP-OIDC-TOKEN-ISSUED");
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

		private configureClients(): OIDCClient[] {
				if (this.options.clients && this.options.clients.length > 0) {
						return this.options.clients;
				}

				const configuredClients = registerOIDCClients();
				if (configuredClients.length > 0) {
						return configuredClients;
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

				await this.storeAuthorizationCode({
						code: authorizationCode,
						clientId: context.clientId,
						redirectUri: context.redirectUri,
						scope: context.scope,
						nonce: context.nonce,
						codeChallenge: context.codeChallenge,
						userId: user.id,
						userSub: user.sub,
						userEmail: user.email,
						userEmailVerified: user.emailVerified,
						userName: user.name
				});

				const redirectTarget = new URL(context.redirectUri);
				redirectTarget.searchParams.set("code", authorizationCode);

				if (context.state) {
						redirectTarget.searchParams.set("state", context.state);
				}

				return redirectTarget.toString();
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

		private createOpaqueToken(): string {
				return randomBytes(32).toString("base64url");
		}

		private toS256CodeChallenge(verifier: string): string {
				return createHash("sha256").update(verifier).digest("base64url");
		}

		private resolveClient(clientId: string): OIDCClient | null {
				const clients = this.configureClients();
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
			email: string;
			emailVerified: boolean;
			iat: number;
			exp: number;
		}): Record<string, unknown> {
			// TEMP-EMAIL-TRACE: Sprint 8.19.2
			console.info("TEMP-EMAIL-TRACE buildIdTokenPayload(input)", {
				emailState: input.email === undefined ? "undefined" : input.email.length > 0 ? "present" : "empty"
			});
			return {
				iss: input.issuer,
				sub: input.subject,
				aud: input.audience,
				nonce: input.nonce,
				scope: input.scope,
				email: input.email,
				email_verified: input.emailVerified,
				iat: input.iat,
				exp: input.exp
			};
		}

		private async createIdToken(input: {
			issuer: string;
			subject: string;
			audience: string;
			nonce: string;
			scope: string;
			email: string;
			emailVerified: boolean;
			iat: number;
			exp: number;
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

		// TEMP-DIAGNOSTIC: Sprint 8.19 - returns the unsigned ID Token claims /token would embed for this access token.
		async getDiagnosticIdTokenClaims(accessToken: string): Promise<Record<string, unknown> | null> {
				const tokenRecord = await this.getAccessTokenRecord(accessToken);
				if (!tokenRecord) {
						return null;
				}

				const now = Math.floor(Date.now() / 1000);
				return {
						...this.buildIdTokenPayload({
								issuer: this.resolveIssuer(),
								subject: tokenRecord.sub,
								audience: tokenRecord.clientId,
								nonce: tokenRecord.nonce,
								scope: tokenRecord.scope,
								email: tokenRecord.email,
								emailVerified: tokenRecord.emailVerified,
								iat: now,
								exp: now + 300
						}),
						preferred_username: tokenRecord.email
				};
		}

		// TEMP-DIAGNOSTIC: Sprint 8.19 - returns exactly what /userinfo returns for this access token.
		async getDiagnosticUserInfoClaims(accessToken: string): Promise<{ sub: string; email: string; email_verified: boolean; name: string } | null> {
				const tokenRecord = await this.getAccessTokenRecord(accessToken);
				if (!tokenRecord) {
						return null;
				}

				return {
						sub: tokenRecord.sub,
						email: tokenRecord.email,
						email_verified: tokenRecord.emailVerified,
						name: tokenRecord.name
				};
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
				const clients = this.configureClients().map((client) => {
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

		getBase44IntegrationStatus(): OIDCBase44IntegrationStatus {
				const issuer = this.resolveIssuer();
				const clients = this.configureClients();
				const clientConfigured = clients.length > 0;
				const base44ToOidc = issuer === OIDCService.DEFAULT_ISSUER && clientConfigured;
				const oidcToBookwrmIdentityServices = Boolean(this.provider) && this.hasSigningKeyConfiguration();
				const authenticatedSession = this.metrics.tokensIssued > 0;

				return {
						issuer,
						clientConfigured,
						base44ToOidc,
						oidcToBookwrmIdentityServices,
						authenticatedSession
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

export const oidcService = new OIDCService();
