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
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import type { EmailOIDCHandoff } from "../authentication/EmailOIDCHandoff.js";
import { EmailAuthenticationError } from "../authentication/email/EmailAuthenticationTypes.js";
import { VerificationError } from "../email/VerificationChallenge.js";

import type { AuthenticationProvider, AuthenticatedUser, PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import { isStagingConsoleInternalRequest } from "./StagingConsoleInternal.js";
import { configuration } from "../config/ConfigurationService.js";
import { DEFAULT_OIDC_ISSUER, recordIssuerAccepted, resolveConfiguredIssuer } from "../config/IssuerPolicy.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityCache } from "../cache/IdentityCache.js";
import { identityRegistry } from "../identity/IdentityRegistry.js";
import { PasskeyAuthenticationRejected, PostgresPasskeyCredentialRepository } from "../identity/PostgresPasskeyCredentialRepository.js";
import { resolveRegisteredClient, requireApplicationMethod, type H1ClientAuthority } from "../identity/H1ClientAuthority.js";
import { inMemoryApplicationRepository } from "../identity/InMemoryApplicationRepository.js";
import { inMemoryTenantRepository } from "../identity/InMemoryTenantRepository.js";
import { PostgresApplicationRepository } from "../identity/PostgresApplicationRepository.js";
import { PostgresTenantRepository } from "../identity/PostgresTenantRepository.js";
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
import {
		RefreshRotationError,
		RefreshTokenRotationService,
		type RefreshClientProfile
} from "./refresh/RefreshTokenRotationService.js";
import type { OIDCLogEntry } from "./types.js";
import { constantTimeStringEqual } from "../security/ServiceAuthentication.js";
import { consumePendingAuthorizationRequest, getPrivateIDAuthenticatedUser, storePrivateIDBrowserReturn,
	PRIVATEID_BROWSER_RETURN_COOKIE } from "../privateid/PrivateIDSessionStore.js";
import { storeCorrelation } from "./CorrelationStore.js";
import {
		AUTHORIZATION_INTERACTION_TTL_MS,
		AuthorizationInteractionStore,
		type AuthorizationInteraction,
		type AuthorizationInteractionBinding
} from "./AuthorizationInteractionStore.js";
import { chooserPage, codePage, emailPage, federatedAccountChoicePage, messagePage, passkeyManagePage, passkeyOfferPage, type RenderedLoginPage } from "./UniversalLoginPages.js";
import type { InteractiveEmailAuthority, InteractiveEmailMode } from "../authentication/InteractiveEmailAuthentication.js";
import { bucketRemainingTtl, diagnosticCorrelationId, logUniversalLoginDiagnostic } from "./UniversalLoginDiagnostics.js";
import {
		APPLE_AUTHORIZATION_ENDPOINT,
		APPLE_TOKEN_ENDPOINT,
		FederatedAuthorizationError,
		FederatedAuthorizationService,
		GOOGLE_AUTHORIZATION_ENDPOINT,
		GOOGLE_TOKEN_ENDPOINT,
		type AppleExchangeDiagnostic
} from "../identity/federation/FederatedAuthorizationService.js";
import { FederationTransactionStore } from "../identity/federation/FederationTransactionStore.js";
import {
		federatedIdentityResolutionService,
		type FederatedIdentityResolutionService
} from "../identity/federation/FederatedIdentityResolutionService.js";
import { AppleClientSecretService } from "../identity/federation/AppleClientSecretService.js";
import { AppleIdentityTokenVerifier } from "../identity/federation/AppleIdentityTokenVerifier.js";
import { GoogleIdentityTokenVerifier } from "../identity/federation/GoogleIdentityTokenVerifier.js";
import type { VerifiedFederatedIdentity } from "../identity/federation/FederatedIdentityTypes.js";
import { HAPI_SESSION_COOKIE, HapiSessionService } from "../identity/sessions/HapiSessionService.js";
import type { HapiSession, HapiSessionAuthenticationMethod } from "../models/HapiSession.js";
import type { IdentitySubject } from "../models/IdentitySubject.js";
import type { AuthenticationMethod } from "../models/Application.js";

// __Host- prefix: Secure, host-only, Path=/ — the interaction handle cannot be scoped to another domain.
const UNIVERSAL_LOGIN_COOKIE = "__Host-hapi_login";
const PASSKEY_ENROLLMENT_COOKIE = "__Host-hapi_passkey";
const universalLoginEmailSchema = z.string().trim().min(3).max(320).email();
const isInteractiveEmailMode = (value: unknown): value is InteractiveEmailMode =>
	value === "AUTHENTICATION" || value === "REGISTRATION" || value === "INELIGIBLE";
const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/).max(100_000);
const registrationResponseSchema = z.object({
		id: base64url, rawId: base64url, type: z.literal("public-key"),
		authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
		clientExtensionResults: z.object({}).passthrough(),
		response: z.object({
				clientDataJSON: base64url, attestationObject: base64url,
				transports: z.array(z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"])).max(7).optional()
		}).passthrough()
});
const authenticationResponseSchema = z.object({
		id: base64url, rawId: base64url, type: z.literal("public-key"),
		authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
		clientExtensionResults: z.object({}).passthrough(),
		response: z.object({ clientDataJSON: base64url, authenticatorData: base64url,
				signature: base64url, userHandle: base64url }).passthrough()
});

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
		clientAuthority?: H1ClientAuthority;
		interactionStore?: AuthorizationInteractionStore;
		passkeyCredentials?: PostgresPasskeyCredentialRepository;
		refreshTokenRotation?: RefreshTokenRotationService;
		// HAPI ID V2-D: injectable federation collaborators (tests supply synthetic providers).
		// Defaults are constructed lazily from configuration, and ONLY consulted when the
		// corresponding default-off federation flags are enabled.
		federation?: {
				apple?: FederatedAuthorizationService;
				google?: FederatedAuthorizationService;
				transactions?: FederationTransactionStore;
				resolution?: FederatedIdentityResolutionService;
				sessions?: HapiSessionService;
		};
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
		login_hint?: string;
		idp_hint?: string;
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
		refresh_token?: string;
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
		private static readonly DEFAULT_ISSUER = DEFAULT_OIDC_ISSUER;
		private static readonly AUTHORIZATION_CODE_TTL_MS = 60_000;
		private static readonly AUTHORIZATION_CODE_CLEANUP_INTERVAL_MS = 30_000;
		private static readonly ACCESS_TOKEN_TTL_MS = 300_000;
		private static readonly REFRESH_TOKEN_TTL_MS = 2_592_000_000;

		private provider?: Provider;
		private readonly options: OIDCServiceOptions;
		private readonly authenticationProvider: AuthenticationProvider;
		private emailAuthentication?: EmailOIDCHandoff;
		private readonly oidcClients: OIDCClientRepository;
		private readonly clientAuthority: H1ClientAuthority;
		private readonly claimsService: ClaimsService;
		private readonly redisStore: RedisOIDCStore;
		private readonly lockService: RedisLockService;
		private readonly rateLimiter: OIDCRateLimiter;
		private readonly interactions: AuthorizationInteractionStore;
		private readonly passkeyCredentials: PostgresPasskeyCredentialRepository;
		private readonly keyRotationService: OIDCKeyRotationService;
		private readonly providerAdapter = new RedisOIDCProviderAdapter();
		// HAPI ID V2-C: constructed lazily and consulted only when HAPI_REFRESH_GRANT_ENABLED is on.
		private refreshRotation?: RefreshTokenRotationService;
		// HAPI ID V2-D: federation collaborators, consulted only behind their default-off flags.
		private federationTransactions?: FederationTransactionStore;
		private federationResolution?: FederatedIdentityResolutionService;
		private sessionService?: HapiSessionService;
		private appleFederation?: FederatedAuthorizationService;
		private googleFederation?: FederatedAuthorizationService;
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
				this.clientAuthority = options.clientAuthority ?? {
						clients: this.oidcClients,
						applications: configuration.getIdentityRegistryDriver() === "memory" ? inMemoryApplicationRepository : new PostgresApplicationRepository(),
						tenants: configuration.getIdentityRegistryDriver() === "memory" ? inMemoryTenantRepository : new PostgresTenantRepository()
				};
				this.redisStore = new RedisOIDCStore();
				this.lockService = new RedisLockService();
				this.rateLimiter = new OIDCRateLimiter();
				this.keyRotationService = new OIDCKeyRotationService();
				this.interactions = options.interactionStore ?? new AuthorizationInteractionStore();
				this.passkeyCredentials = options.passkeyCredentials ?? new PostgresPasskeyCredentialRepository();
				this.refreshRotation = options.refreshTokenRotation;
				this.federationTransactions = options.federation?.transactions;
				this.federationResolution = options.federation?.resolution;
				this.sessionService = options.federation?.sessions;
				this.appleFederation = options.federation?.apple;
				this.googleFederation = options.federation?.google;
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

								if (!this.hasValidClientAuthenticationConfiguration(client)) {
										reply.code(400);
										error = "Client authentication metadata is invalid";
										return { error: "invalid_client", error_description: "Client authentication metadata is invalid" };
								}

								const registration = await resolveRegisteredClient(clientId, this.clientAuthority);
								if (query.idp_hint !== undefined) {
										// Provider routing is not implemented; even an allowlisted provider cannot select a route yet.
										return reply.code(400).send({ error: "invalid_request", error_description: "Provider selection is not enabled" });
								}
								app.log.info({ event: "APPLICATION_AUTHORIZATION", applicationId: registration.application.id,
										clientId, requestId: request.id, result: "validated" }, "Application authority validated");

								const allowedRedirectUris = this.extractRedirectUris(client);
								// TEMPORARY RELEASE PATCH 6.5 - REMOVE AFTER PRODUCTION CERTIFICATION
								app.log.info(
										{ clientId, requestedRedirectUri: redirectUri, registeredRedirectUris: allowedRedirectUris },
										"OIDC Redirect Validation"
								);
								if (allowedRedirectUris.length === 0 || !allowedRedirectUris.includes(redirectUri)) {
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

								// V2-B nonce policy: every HAPI ID transaction binds the ID Token to the client's
								// nonce, and the token endpoint has always rejected codes without one. Enforcing the
								// existing requirement here fails fast at /authorize instead of issuing a code that
								// can never be exchanged. No functional client is affected: all successfully
								// integrated clients already send nonce.
								if (!query.nonce || query.nonce.trim().length === 0) {
										reply.code(400);
										error = "nonce is required";
										return { error: "invalid_request", error_description: "nonce is required" };
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
										await requireApplicationMethod(clientId, this.clientAuthority, "HAPI_EMAIL");
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
								if (err instanceof VerificationError) return reply.code(err.statusCode).send({ error: "unauthorized_client" });
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
								error = isStagingConsoleInternalRequest(request) ? "staging_console_verification_failed" : err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId: "",
										flow: "jwks",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply) && (!isStagingConsoleInternalRequest(request) || !error),
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

								if (!tokenRecord || !recordIssuerAccepted(tokenRecord.issuer, this.resolveIssuer())) {
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
								error = isStagingConsoleInternalRequest(request) ? "staging_console_verification_failed" : err instanceof Error ? err.message : "unknown_error";
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId,
										flow: "userinfo",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply) && (!isStagingConsoleInternalRequest(request) || !error),
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

								// HAPI ID V2-C: grant_type=refresh_token exists ONLY behind the default-off
								// feature gate. With the gate off, the rejection below is byte-identical to V2-B.
								const refreshGrantEnabled = featureFlags.isRefreshGrantEnabled();
								if (grantType === "refresh_token" && refreshGrantEnabled) {
										const result = await this.handleRefreshTokenGrant({
												refreshToken: body.refresh_token?.trim(),
												clientId,
												clientSecret,
												reply
										});
										error = result.error ?? "";
										user = result.user ?? "";
										return result.body;
								}

								if (grantType !== "authorization_code") {
										const supported = refreshGrantEnabled
												? "Only grant_type=authorization_code or refresh_token is supported"
												: "Only grant_type=authorization_code is supported";
										reply.code(400);
										error = supported;
										return {
												error: "unsupported_grant_type",
												error_description: supported
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

								// HAPI ID V2-E Stage 0: authorization codes are issuer-bound. A code minted
								// under a different issuer environment is never redeemable here, even when the
								// environments share a backing store.
								if (!recordIssuerAccepted(codeRecord.issuer, this.resolveIssuer())) {
										reply.code(400);
										error = "authorization code issuer mismatch";
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

								const tokenEndpointAuthMethod = this.clientTokenEndpointAuthMethod(client);
								await requireApplicationMethod(clientId, this.clientAuthority,
										this.applicationMethodFor(codeRecord.authenticationMethod));
								if (!this.hasValidClientAuthenticationConfiguration(client)) {
										reply.code(400);
										error = "Client authentication metadata is invalid";
										return { error: "invalid_client", error_description: "Client authentication metadata is invalid" };
								}
								const configuredClientSecret =
									typeof client.client_secret === "string" ? client.client_secret : "";
								if (
										tokenEndpointAuthMethod !== "none" &&
										(!clientSecret || !configuredClientSecret.trim() ||
											!constantTimeStringEqual(configuredClientSecret, clientSecret))
								) {
										reply.code(400);
										error = "client_secret is invalid";
										return { error: "invalid_client", error_description: "client_secret is invalid" };
								}

								const allowedRedirectUris = this.extractRedirectUris(client);
								if (allowedRedirectUris.length === 0 || !allowedRedirectUris.includes(redirectUri)) {
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
								// V2-D provider revocation handling: a federated code is redeemable only while the
								// subject is ACTIVE and the provider identity is STILL actively linked -- an unlink
								// or provider-side revocation between code issuance and redemption fails closed.
								if (codeRecord.authenticationMethod === "APPLE" || codeRecord.authenticationMethod === "GOOGLE") {
										const subject = await identityRegistry.findByOidcSubject(codeRecord.userSub);
										if (!subject || subject.status !== "ACTIVE" ||
											!(await this.getFederationResolution().isSubjectLinkActive(subject.id, codeRecord.authenticationMethod))) {
												error = "federated_identity_not_eligible";
												return reply.code(400).send({ error: "invalid_grant" });
										}
								}
								if (codeRecord.authenticationMethod === "PASSKEY") {
										if (!featureFlags.isPasskeyAuthenticationEnabled() || !codeRecord.passkeyCredentialId ||
											!await this.passkeyCredentials.isActive(codeRecord.passkeyCredentialId, codeRecord.userId, codeRecord.userSub)) {
												error = "passkey_identity_not_eligible";
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

							// V2-B interim refresh-token policy: a refresh token is only issued when the
							// client's registration explicitly includes the refresh_token grant (preserving
							// legacy Bookwrm behavior). V2-C: when the default-off refresh grant gate is ON,
							// issuance moves to rotating refresh-token families (PostgreSQL, hashed, one-time
							// use); with the gate OFF the legacy Redis-stored token behavior is unchanged.
							const issueRefreshToken = codeRecord.authenticationMethod !== "PASSKEY" && this.clientAllowsRefreshTokenGrant(client);
							const accessToken = this.createOpaqueToken();
							let refreshToken: string | undefined;
							let legacyRefreshToken: string | undefined;
							if (issueRefreshToken) {
									if (featureFlags.isRefreshGrantEnabled()) {
											const subjectRecord = await identityRegistry.findByOidcSubject(codeRecord.userSub);
											if (subjectRecord) {
													const issued = await this.getRefreshRotation().issueFamily({
															identitySubjectId: subjectRecord.id,
															clientId,
															scope: codeRecord.scope,
															clientProfile: this.refreshClientProfile(client),
															...(codeRecord.authenticationMethod ? {
																	authenticationMethod: codeRecord.authenticationMethod,
																	...(codeRecord.authenticatedAt
																			? { authenticatedAt: codeRecord.authenticatedAt } : {})
															} : {})
													});
													refreshToken = issued.refreshToken;
											} else {
													// No registry subject to anchor a family to: keep the legacy contract
													// rather than silently dropping the client's refresh token.
													legacyRefreshToken = this.createOpaqueToken();
													refreshToken = legacyRefreshToken;
											}
									} else {
											legacyRefreshToken = this.createOpaqueToken();
											refreshToken = legacyRefreshToken;
									}
							}
							await this.storeAccessToken(accessToken, {
									sub: claims.sub,
									clientId,
									nonce: codeRecord.nonce,
									scope: codeRecord.scope,
									issuer,
									...(codeRecord.authenticationMethod ? {
										authenticationMethod: codeRecord.authenticationMethod,
										authenticatedAt: codeRecord.authenticatedAt
									} : {})
							});
							if (legacyRefreshToken) {
									await this.storeRefreshToken(legacyRefreshToken, {
											userId: codeRecord.userId,
											clientId,
											scope: codeRecord.scope,
											issuer
									});
							}
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
								...(refreshToken !== undefined ? { refresh_token: refreshToken } : {}),
								id_token: idToken
								};
						} catch (err) {
								error = isStagingConsoleInternalRequest(request) ? "staging_console_verification_failed" : err instanceof Error ? err.message : "unknown_error";
								if (err instanceof VerificationError) return reply.code(400).send({ error: "unauthorized_client" });
								throw err;
						} finally {
								this.logOidcRequest(app, {
										requestId: request.id,
										clientId: clientId ?? "",
										flow: "token",
										latency: Date.now() - startedAt,
										success: this.replySucceeded(reply) && (!isStagingConsoleInternalRequest(request) || !error),
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
						// HAPI ID V2-C: refresh_token is advertised only while the default-off gate is on.
						grant_types_supported: featureFlags.isRefreshGrantEnabled()
								? ["authorization_code", "refresh_token"]
								: ["authorization_code"],
						claims_supported: claimsSupported,
						code_challenge_methods_supported: ["S256"]
				};

				this.validateDiscoveryConfiguration(discovery);
				return discovery;
		}

		// HAPI ID V2-E Stage 0: the resolved issuer is always validated (exact https origin, no
		// wildcard/suffix matching) and checked against OIDC_ALLOWED_ISSUERS when configured --
		// malformed or conflicting issuer configuration fails closed here.
		private resolveIssuer(): string {
				return resolveConfiguredIssuer(this.options.issuer);
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

				// HAPI ID V2-E Stage 0: the configured issuer is the authoritative expected value --
				// discovery must assert exactly the resolved issuer, and every advertised endpoint
				// must be anchored to that issuer. No wildcard or suffix matching.
				const expectedIssuer = this.resolveIssuer();
				if (discovery.issuer !== expectedIssuer) {
						throw new Error("OpenID discovery validation failed: issuer mismatch");
				}

				for (const endpointField of ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]) {
						const value = discovery[endpointField];
						if (typeof value !== "string" || !value.startsWith(`${expectedIssuer}/`)) {
								throw new Error(`OpenID discovery validation failed: ${endpointField} is not anchored to the issuer`);
						}
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

				const persistedClients = await this.oidcClients.list();
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
				await requireApplicationMethod(context.clientId, this.clientAuthority,
						this.applicationMethodFor(user.authenticationMethod));
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
						issuer: this.resolveIssuer(),
						...(user.authenticationMethod ? {
							authenticationMethod: user.authenticationMethod,
							authenticatedAt: user.authenticatedAt
						} : {}),
						...(user.passkeyCredentialId ? { passkeyCredentialId: user.passkeyCredentialId } : {})
				});

				const redirectTarget = new URL(context.redirectUri);
				redirectTarget.searchParams.set("code", authorizationCode);

				if (context.state) {
						redirectTarget.searchParams.set("state", context.state);
				}

				return redirectTarget.toString();
		}

		// Maps a user authentication method onto the Application capability that must be enabled for
		// it: HAPI email OTP, PrivateID face, or an external upstream provider (Apple/Google).
		private applicationMethodFor(method?: AuthenticatedUser["authenticationMethod"]): AuthenticationMethod {
				if (method === "HAPI_EMAIL") return "HAPI_EMAIL";
				if (method === "APPLE" || method === "GOOGLE") return "EXTERNAL_OIDC";
				if (method === "PASSKEY") return "PASSKEY";
				return "PRIVATEID_FACE";
		}

		// Existing interactive PrivateID Face path, shared by flag-off GET /authorize and Universal Login "Continue with Face".
		private async beginFaceAuthorization(reply: FastifyReply, pendingContext: PendingAuthorizationContext): Promise<void> {
				await requireApplicationMethod(pendingContext.clientId, this.clientAuthority, "PRIVATEID_FACE");
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
				const registered = await resolveRegisteredClient(clientId, this.clientAuthority);
				let binding: AuthorizationInteractionBinding | undefined = {
						tenantId: registered.tenant.id, applicationId: registered.application.id, tenantName: registered.application.name
				};
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
				const registered = await resolveRegisteredClient(interaction.clientId, this.clientAuthority);
				if (!interaction.binding || registered.application.id !== interaction.binding.applicationId ||
						registered.tenant.id !== interaction.binding.tenantId) return false;
				const redirectUris = this.extractRedirectUris(client);
				return redirectUris.length > 0 && redirectUris.includes(interaction.authorization.redirectUri);
		}

		private async interactiveEmailAuthority(interaction: AuthorizationInteraction): Promise<InteractiveEmailAuthority | null> {
				const interactive = this.emailAuthentication?.interactive;
				if (!interactive || !interaction.binding) return null;
				let authority: InteractiveEmailAuthority;
				try {
						await requireApplicationMethod(interaction.clientId, this.clientAuthority, "HAPI_EMAIL");
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
				const connectingApple = (interaction: AuthorizationInteraction) =>
						interaction.federation?.provider === "APPLE" && interaction.federation.linkExisting === true;
				const tooMany = (reply: FastifyReply, interaction: AuthorizationInteraction, page: "email" | "code") => send(reply, 429,
						(page === "email" ? emailPage : codePage)({ tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
								csrf: interaction.csrf, ...(page === "code" ? { connectApple: connectingApple(interaction) } : {}),
								error: "Too many attempts. Please wait a few minutes and try again." }));
				const emailFailed = "We couldn't sign you in with that code. Check the code, request a new one, or use a different email.";
				const statusOf = (error: unknown) => typeof (error as { statusCode?: unknown })?.statusCode === "number"
						? (error as { statusCode: number }).statusCode : 500;
				const logLogin = (request: FastifyRequest, flow: string, interaction: AuthorizationInteraction | null,
						startedAt: number, success: boolean, error: string, user = "", appleExchange?: AppleExchangeDiagnostic) => {
						const method = flow === "universal_login_face" ? "PRIVATEID_FACE"
								: flow.includes("federated_apple") ? "APPLE"
								: flow.includes("federated_google") ? "GOOGLE"
								: "HAPI_EMAIL";
						app.log.info({ event: "APPLICATION_AUTHENTICATION", applicationId: interaction?.binding?.applicationId,
								clientId: interaction?.clientId, identitySubjectId: user || undefined, requestId: request.id,
								authenticationMethod: method,
								result: success ? "success" : "rejected", reasonCode: error || undefined,
								...(appleExchange ? { appleExchangeCategory: appleExchange.category } : {}),
								...(appleExchange?.category === "provider_rejection"
										? { appleExchangeStatus: appleExchange.status,
												...(appleExchange.oauthError ? { appleOAuthError: appleExchange.oauthError } : {}) } : {})
						}, "Application authentication result");
						this.logOidcRequest(app, {
						requestId: request.id, clientId: interaction?.clientId ?? "", flow, latency: Date.now() - startedAt,
						success, error, user, pkce: interaction?.authorization.codeChallenge ? "S256" : "missing",
						correlationId: this.correlationIdFor(request)
				});
				};
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

				// Chooser rendering shared by GET /login and federated-callback error recovery.
				const renderChooser = async (request: FastifyRequest, reply: FastifyReply, interaction: AuthorizationInteraction,
						status = 200, errorMessage?: string) => {
						const registration = await resolveRegisteredClient(interaction.clientId, this.clientAuthority);
						const externalAllowed = registration.application.allowedAuthenticationMethods.includes("EXTERNAL_OIDC");
						const continuation = await this.detectSessionContinuation(request);
						return send(reply, status, chooserPage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
								clientId: interaction.clientId,
								faceAvailable: registration.application.allowedAuthenticationMethods.includes("PRIVATEID_FACE") ? undefined : false,
								emailAvailable: Boolean(interaction.binding && this.emailAuthentication?.interactive &&
										registration.application.allowedAuthenticationMethods.includes("HAPI_EMAIL")),
								appleAvailable: externalAllowed && Boolean(this.federatedService("APPLE")),
								googleAvailable: externalAllowed && Boolean(this.federatedService("GOOGLE")),
								passkeyAvailable: featureFlags.isPasskeyAuthenticationEnabled() &&
										registration.application.allowedAuthenticationMethods.includes("PASSKEY"),
								...(continuation ? { continueAs: continuation.subject.email ?? continuation.subject.displayName ?? "your account" } : {}),
								...(errorMessage !== undefined ? { error: errorMessage } : {}) }));
				};

				const passkeyOffered = async (interaction: AuthorizationInteraction) => {
						if (!featureFlags.isPasskeyAuthenticationEnabled()) return false;
						const registration = await resolveRegisteredClient(interaction.clientId, this.clientAuthority);
						return registration.application.allowedAuthenticationMethods.includes("PASSKEY");
				};
				const showPasskeyOffer = (reply: FastifyReply, browserProof: string) => reply
						.header("Set-Cookie", `${PASSKEY_ENROLLMENT_COOKIE}=${browserProof}; Path=/; Max-Age=${AUTHORIZATION_INTERACTION_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`)
						.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer")
						.redirect("/login/passkey", 303);
				const browserProof = (request: FastifyRequest) => request.headers.cookie?.split(";").map(value => value.trim())
						.find(value => value.startsWith(`${PASSKEY_ENROLLMENT_COOKIE}=`))?.slice(PASSKEY_ENROLLMENT_COOKIE.length + 1);
				const freshManagementDeadline = (principal: AuthenticatedUser): number => {
						if (principal.authenticationMethod !== "HAPI_EMAIL" && principal.authenticationMethod !== "PASSKEY") return 0;
						const authenticatedAt = Date.parse(principal.authenticatedAt ?? "");
						if (!Number.isFinite(authenticatedAt) || authenticatedAt > Date.now()) return 0;
						return authenticatedAt + 300_000;
				};
				const activeManagementCredential = async (principal: AuthenticatedUser): Promise<boolean> =>
						principal.authenticationMethod !== "PASSKEY" || Boolean(principal.passkeyCredentialId &&
								await this.passkeyCredentials.isActive(principal.passkeyCredentialId, principal.id, principal.sub));
				app.post("/login/passkey/auth/options", { bodyLimit: 4096 }, async (request, reply) => {
						try {
								const loaded = await load(request, reply, true, "POST /login/passkey/auth/options");
								if (!loaded) return reply;
								if (request.headers.origin !== this.resolveIssuer()) return reply.code(403).send({ error: "invalid_origin" });
								if (!await passkeyOffered(loaded.interaction) || !await this.interactionClientStillValid(loaded.interaction)) {
										return reply.code(403).send({ error: "passkey_not_allowed" });
								}
								if (loaded.body.purpose !== undefined && loaded.body.purpose !== "manage") {
										return reply.code(400).send({ error: "invalid_request" });
								}
								const options = await generateAuthenticationOptions({
										rpID: new URL(this.resolveIssuer()).hostname, userVerification: "required"
								});
								if (!await this.interactions.beginPasskeyAuthentication(loaded.handle, loaded.interaction, options.challenge,
										loaded.body.purpose === "manage" ? "manage" : "login")) {
										return expired(reply);
								}
								return reply.header("Cache-Control", "no-store").send(options);
						} catch {
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_AUTH_OPTIONS_UNAVAILABLE" }, "Passkey authentication options failed");
								return reply.code(503).send({ error: "passkey_unavailable" });
						}
				});
				app.post("/login/passkey/auth/verify", { bodyLimit: 131072 }, async (request, reply) => {
						try {
								const loaded = await load(request, reply, true, "POST /login/passkey/auth/verify");
								if (!loaded) return reply;
								if (request.headers.origin !== this.resolveIssuer()) return reply.code(403).send({ error: "invalid_origin" });
								if (!await passkeyOffered(loaded.interaction) || !await this.interactionClientStillValid(loaded.interaction)) {
										return reply.code(403).send({ error: "passkey_not_allowed" });
								}
								const parsed = authenticationResponseSchema.safeParse(loaded.body.credential);
								if (!parsed.success || parsed.data.id !== parsed.data.rawId) return reply.code(400).send({ error: "invalid_credential" });
								const claimed = await this.interactions.claimPasskeyAuthentication(loaded.handle, loaded.interaction);
								if (!claimed) return reply.code(400).send({ error: "invalid_challenge" });
								const credential = parsed.data;
								const resolved = await this.passkeyCredentials.authenticate(credential.id, credential.response.userHandle,
										claimed.expiresAt, async stored => {
												let verified;
												try {
														verified = await verifyAuthenticationResponse({
																response: credential, expectedChallenge: claimed.challenge,
																expectedOrigin: this.resolveIssuer(), expectedRPID: new URL(this.resolveIssuer()).hostname,
																requireUserVerification: true,
																// Synchronized credentials may report zero or non-monotonic counters.
																credential: { id: stored.id, publicKey: stored.publicKey,
																		counter: stored.backupEligible ? 0 : stored.counter }
														});
												} catch {
														throw new PasskeyAuthenticationRejected();
												}
												if (!verified.verified) throw new PasskeyAuthenticationRejected();
												return { counter: verified.authenticationInfo.newCounter,
														backupEligible: verified.authenticationInfo.credentialDeviceType === "multiDevice",
														backupState: verified.authenticationInfo.credentialBackedUp };
										});
								const subject = await identityRegistry.findById(resolved.subjectId);
								if (!subject || subject.status !== "ACTIVE" || subject.oidcSubject !== resolved.oidcSubject ||
										claimed.expiresAt <= Date.now()) return reply.code(401).send({ error: "invalid_credential" });
								const principal: AuthenticatedUser = {
										id: subject.id, sub: subject.oidcSubject, authenticationMethod: "PASSKEY",
										authenticatedAt: new Date().toISOString(), passkeyCredentialId: credential.id
								};
								if (claimed.purpose === "manage") {
										const offered = await this.interactions.offerPasskeyEnrollment(loaded.handle, loaded.interaction, principal);
										if (!offered) return reply.code(400).send({ error: "invalid_challenge" });
										return reply.header("Set-Cookie", `${PASSKEY_ENROLLMENT_COOKIE}=${offered.browserProof}; Path=/; Max-Age=${AUTHORIZATION_INTERACTION_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`)
												.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer")
												.send({ redirect: "/login/passkey/manage" });
								}
								if (!await this.interactions.consumeExpected(loaded.handle, loaded.interaction)) {
										return reply.code(400).send({ error: "invalid_challenge" });
								}
								const redirect = await this.issueAuthorizationRedirect(principal, loaded.interaction.authorization);
								const cookies = [this.interactionCookie(null)];
								return reply.header("Set-Cookie", cookies).header("Cache-Control", "no-store")
										.header("Referrer-Policy", "no-referrer").send({ redirect });
						} catch (error) {
								if (error instanceof PasskeyAuthenticationRejected) {
										app.log.warn({ event: "UNIVERSAL_LOGIN_PASSKEY_AUTH_REJECTED" }, "Passkey assertion rejected");
										return reply.code(401).send({ error: "invalid_credential" });
								}
								if (error instanceof VerificationError) return reply.code(403).send({ error: "authentication_method_not_allowed" });
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_AUTH_UNAVAILABLE" }, "Passkey authentication failed");
								return reply.code(503).send({ error: "passkey_unavailable" });
						}
				});
				app.get("/login/passkey", async (request, reply) => {
						const loaded = await load(request, reply, false, "GET /login/passkey");
						if (!loaded) return reply;
						const proof = browserProof(request);
						const enrollment = proof && await this.interactions.inspectPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf);
						if (!enrollment || enrollment.state !== "OFFERED") return expired(reply);
						return send(reply, 200, passkeyOfferPage({ tenantName: loaded.interaction.binding?.tenantName,
								clientId: loaded.interaction.clientId, csrf: loaded.interaction.csrf,
								managementAvailable: freshManagementDeadline(enrollment.principal) > Date.now(),
								available: !enrollment.expired && await passkeyOffered(loaded.interaction) }));
				});
				app.get("/login/passkey/manage", async (request, reply) => {
						try {
								const loaded = await load(request, reply, false, "GET /login/passkey/manage");
								if (!loaded) return reply;
								const proof = browserProof(request);
								const enrollment = proof && await this.interactions.inspectPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf);
								if (!proof || !enrollment || enrollment.expired || enrollment.state !== "OFFERED" ||
										!await passkeyOffered(loaded.interaction) || !await this.interactionClientStillValid(loaded.interaction)) return expired(reply);
								if (freshManagementDeadline(enrollment.principal) <= Date.now()) return reply.code(403).send({ error: "fresh_authentication_required" });
								if (!await activeManagementCredential(enrollment.principal)) return reply.code(403).send({ error: "fresh_authentication_required" });
								const subject = await identityRegistry.findById(enrollment.principal.id);
								if (!subject || subject.status !== "ACTIVE" || subject.oidcSubject !== enrollment.principal.sub) return expired(reply);
								await requireApplicationMethod(loaded.interaction.clientId, this.clientAuthority,
										this.applicationMethodFor(enrollment.principal.authenticationMethod));
								const credentials = await this.passkeyCredentials.list(subject.id, subject.oidcSubject,
										Math.min(enrollment.expiresAt, freshManagementDeadline(enrollment.principal)), enrollment.principal.passkeyCredentialId);
								return send(reply, 200, passkeyManagePage({ tenantName: loaded.interaction.binding?.tenantName,
										clientId: loaded.interaction.clientId, csrf: loaded.interaction.csrf, credentials }));
						} catch (error) {
								if (error instanceof PasskeyAuthenticationRejected) return reply.code(403).send({ error: "fresh_authentication_required" });
								if (error instanceof VerificationError) return reply.code(403).send({ error: "authentication_method_not_allowed" });
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_MANAGE_UNAVAILABLE" }, "Passkey management unavailable");
								return unavailable(reply);
						}
				});
				app.post("/login/passkey/revoke", { bodyLimit: 4096 }, async (request, reply) => {
						try {
								const loaded = await load(request, reply, true, "POST /login/passkey/revoke");
								if (!loaded) return reply;
								if (request.headers.origin !== this.resolveIssuer()) return reply.code(403).send({ error: "invalid_origin" });
								const credentialId = base64url.safeParse(loaded.body.credential_id);
								if (!credentialId.success) return reply.code(400).send({ error: "invalid_credential" });
								const proof = browserProof(request);
								const enrollment = proof && await this.interactions.inspectPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf);
								if (!proof || !enrollment || enrollment.expired || enrollment.state !== "OFFERED" ||
										!await passkeyOffered(loaded.interaction) || !await this.interactionClientStillValid(loaded.interaction)) return expired(reply);
								const freshUntil = freshManagementDeadline(enrollment.principal);
								if (freshUntil <= Date.now()) return reply.code(403).send({ error: "fresh_authentication_required" });
								if (!await activeManagementCredential(enrollment.principal)) return reply.code(403).send({ error: "fresh_authentication_required" });
								const subject = await identityRegistry.findById(enrollment.principal.id);
								if (!subject || subject.status !== "ACTIVE" || subject.oidcSubject !== enrollment.principal.sub) return expired(reply);
								await requireApplicationMethod(loaded.interaction.clientId, this.clientAuthority,
										this.applicationMethodFor(enrollment.principal.authenticationMethod));
								if (!await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
										subject.id, "OFFERED", "MANAGING")) return expired(reply);
								const revoked = await this.passkeyCredentials.revoke(subject.id, subject.oidcSubject, credentialId.data,
										Math.min(enrollment.expiresAt, freshUntil), enrollment.principal.passkeyCredentialId);
								if (!await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
										subject.id, "MANAGING", "OFFERED")) return unavailable(reply);
								if (!revoked) return reply.code(404).send({ error: "credential_not_found" });
								if (credentialId.data === enrollment.principal.passkeyCredentialId) {
										return send(reply, 200, messagePage({ title: "Passkey revoked",
												message: "Your passkey was revoked. Start sign-in again using another method." }));
								}
								return reply.header("Cache-Control", "no-store").redirect("/login/passkey/manage", 303);
						} catch (error) {
								if (error instanceof PasskeyAuthenticationRejected) return reply.code(403).send({ error: "fresh_authentication_required" });
								if (error instanceof VerificationError) return reply.code(403).send({ error: "authentication_method_not_allowed" });
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_REVOKE_UNAVAILABLE" }, "Passkey revocation failed");
								return unavailable(reply);
						}
				});
				app.post("/login/passkey/options", { bodyLimit: 4096 }, async (request, reply) => {
						try {
								const loaded = await load(request, reply, true, "POST /login/passkey/options");
								if (!loaded) return reply;
								if (request.headers.origin !== this.resolveIssuer()) return reply.code(403).send({ error: "invalid_origin" });
								if (!await passkeyOffered(loaded.interaction) || !await this.interactionClientStillValid(loaded.interaction)) {
										return reply.code(403).send({ error: "passkey_not_allowed" });
								}
								const proof = browserProof(request);
								const enrollment = proof && await this.interactions.inspectPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf);
								if (!proof || !enrollment || enrollment.expired || enrollment.state !== "OFFERED") return expired(reply);
								const subject = await identityRegistry.findById(enrollment.principal.id);
								if (!subject || subject.status !== "ACTIVE" || subject.oidcSubject !== enrollment.principal.sub) return expired(reply);
								await requireApplicationMethod(loaded.interaction.clientId, this.clientAuthority,
										this.applicationMethodFor(enrollment.principal.authenticationMethod));
								const userHandle = await this.passkeyCredentials.userHandle(subject.id);
								const excludeCredentials = await this.passkeyCredentials.activeCredentials(subject.id);
								if (excludeCredentials.length && freshManagementDeadline(enrollment.principal) <= Date.now()) {
										return reply.code(403).send({ error: "fresh_authentication_required" });
								}
								if (!await activeManagementCredential(enrollment.principal)) return reply.code(403).send({ error: "fresh_authentication_required" });
								const issuer = this.resolveIssuer();
								const options = await generateRegistrationOptions({
										rpName: issuer === "https://id-staging.hapiinc.com" ? "HAPI ID Staging" : "HAPI ID",
										rpID: new URL(issuer).hostname,
										userName: "HAPI ID account", userDisplayName: "HAPI ID account",
										userID: Uint8Array.from(userHandle), excludeCredentials, attestationType: "none",
										authenticatorSelection: { residentKey: "required", userVerification: "required" }
								});
								if (!await this.interactions.beginPasskeyRegistration(loaded.handle, proof, loaded.interaction.csrf,
										subject.id, options.challenge, userHandle.toString("base64url"))) return expired(reply);
								return reply.header("Cache-Control", "no-store").send(options);
						} catch (error) {
								if (error instanceof VerificationError) return reply.code(403).send({ error: "authentication_method_not_allowed" });
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_OPTIONS_UNAVAILABLE" }, "Passkey options failed");
								return reply.code(503).send({ error: "passkey_unavailable" });
						}
				});
				app.post("/login/passkey/verify", { bodyLimit: 131072 }, async (request, reply) => {
						try {
								const loaded = await load(request, reply, true, "POST /login/passkey/verify");
								if (!loaded) return reply;
								if (request.headers.origin !== this.resolveIssuer()) return reply.code(403).send({ error: "invalid_origin" });
								if (!await passkeyOffered(loaded.interaction) || !await this.interactionClientStillValid(loaded.interaction)) {
										return reply.code(403).send({ error: "passkey_not_allowed" });
								}
								const parsed = registrationResponseSchema.safeParse(loaded.body.credential);
								if (!parsed.success || parsed.data.id !== parsed.data.rawId) return reply.code(400).send({ error: "invalid_credential" });
								const proof = browserProof(request);
								const enrollment = proof && await this.interactions.inspectPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf);
								if (!proof || !enrollment || enrollment.expired || enrollment.state !== "ENROLLING") return expired(reply);
								const subject = await identityRegistry.findById(enrollment.principal.id);
								if (!subject || subject.status !== "ACTIVE" || subject.oidcSubject !== enrollment.principal.sub) return expired(reply);
								await requireApplicationMethod(loaded.interaction.clientId, this.clientAuthority,
										this.applicationMethodFor(enrollment.principal.authenticationMethod));
								const claimed = await this.interactions.claimPasskeyRegistration(loaded.handle, proof, loaded.interaction.csrf, subject.id);
								if (!claimed) return expired(reply);
								let verified;
								try {
										verified = await verifyRegistrationResponse({
												response: parsed.data, expectedChallenge: claimed.challenge,
												expectedOrigin: this.resolveIssuer(), expectedRPID: new URL(this.resolveIssuer()).hostname,
												requireUserPresence: true, requireUserVerification: true
										});
								} catch {
										await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
												subject.id, "VERIFYING", "FAILED");
										app.log.warn({ event: "UNIVERSAL_LOGIN_PASSKEY_INVALID_CREDENTIAL" }, "Passkey verification rejected");
										return reply.code(400).send({ error: "invalid_credential" });
								}
								if (!verified.verified) {
										await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
												subject.id, "VERIFYING", "FAILED");
										return reply.code(400).send({ error: "invalid_credential" });
								}
								try {
										await this.passkeyCredentials.insert({
												subjectId: subject.id, oidcSubject: subject.oidcSubject,
												userHandle: Buffer.from(claimed.userHandle, "base64url"), authorityRef: claimed.authorityRef,
												expiresAt: claimed.expiresAt, additionalEnrollmentExpiresAt: freshManagementDeadline(claimed.principal),
												authorizingCredentialId: claimed.principal.passkeyCredentialId,
												credential: verified.registrationInfo.credential,
												backupEligible: verified.registrationInfo.credentialDeviceType === "multiDevice",
												backupState: verified.registrationInfo.credentialBackedUp
										});
								} catch (error) {
										try {
												await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
														subject.id, "VERIFYING", "FAILED");
										} catch {
												app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_FAILURE_TRANSITION_UNAVAILABLE" }, "Passkey failure transition failed");
										}
										throw error;
								}
								if (!await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
										subject.id, "VERIFYING", "ENROLLED")) return reply.code(503).send({ error: "passkey_unavailable" });
								const completed = await this.interactions.finishPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf, subject.id);
								if (!completed) return reply.code(503).send({ error: "passkey_unavailable" });
								const redirect = await this.issueAuthorizationRedirect(completed.principal, completed.interaction.authorization);
								const cookies = [this.interactionCookie(null),
										`${PASSKEY_ENROLLMENT_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`];
								const sessionCookie = await this.maybeEstablishSession(request, completed.principal, completed.interaction.clientId);
								if (sessionCookie) cookies.push(sessionCookie);
								return reply.header("Set-Cookie", cookies).header("Cache-Control", "no-store")
										.header("Referrer-Policy", "no-referrer").send({ redirect });
						} catch (error) {
								if (error instanceof VerificationError) return reply.code(403).send({ error: "authentication_method_not_allowed" });
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_VERIFY_UNAVAILABLE" }, "Passkey enrollment failed");
								return reply.code(503).send({ error: "passkey_unavailable" });
						}
				});
				app.post("/login/passkey/skip", { bodyLimit: 4096 }, async (request, reply) => {
						try {
								const loaded = await load(request, reply, true, "POST /login/passkey/skip");
								if (!loaded) return reply;
								if (request.headers.origin !== this.resolveIssuer()) return reply.code(403).send({ error: "invalid_origin" });
								const proof = browserProof(request);
								const enrollment = proof && await this.interactions.inspectPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf);
								if (!proof || !enrollment || !["OFFERED", "ENROLLING", "FAILED"].includes(enrollment.state) ||
										!await this.interactionClientStillValid(loaded.interaction)) return expired(reply);
								const subject = await identityRegistry.findById(enrollment.principal.id);
								if (!subject || subject.status !== "ACTIVE" || subject.oidcSubject !== enrollment.principal.sub) return expired(reply);
								await requireApplicationMethod(loaded.interaction.clientId, this.clientAuthority,
										this.applicationMethodFor(enrollment.principal.authenticationMethod));
								const claimed = enrollment.state === "FAILED" ? true
										: enrollment.state === "ENROLLING"
												? await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
														subject.id, "ENROLLING", "FAILED")
												: enrollment.expired
														? await this.interactions.expirePasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf, subject.id)
														: await this.interactions.transitionPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf,
																subject.id, "OFFERED", "SKIPPED");
								if (!claimed) return expired(reply);
								const completed = await this.interactions.finishPasskeyEnrollment(loaded.handle, proof, loaded.interaction.csrf, subject.id);
								if (!completed) return expired(reply);
								const redirect = await this.issueAuthorizationRedirect(completed.principal, completed.interaction.authorization);
								const cookies = [this.interactionCookie(null),
										`${PASSKEY_ENROLLMENT_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`];
								const sessionCookie = await this.maybeEstablishSession(request, completed.principal, completed.interaction.clientId);
								if (sessionCookie) cookies.push(sessionCookie);
								return reply.header("Set-Cookie", cookies).header("Cache-Control", "no-store")
										.header("Referrer-Policy", "no-referrer").redirect(redirect, 303);
						} catch (error) {
								if (error instanceof VerificationError) return reply.code(403).send({ error: "authentication_method_not_allowed" });
								app.log.error({ event: "UNIVERSAL_LOGIN_PASSKEY_SKIP_UNAVAILABLE" }, "Passkey offer completion failed");
								return unavailable(reply);
						}
				});

				app.get("/login", async (request, reply) => {
						const loaded = await load(request, reply, false, "GET /login");
						if (!loaded) return reply;
						const { interaction } = loaded;
						if (!await this.interactionClientStillValid(interaction)) return expired(reply);
						return renderChooser(request, reply, interaction);
				});

				app.get("/login/email", async (request, reply) => {
						const loaded = await load(request, reply, false, "GET /login/email");
						if (!loaded) return reply;
						const { interaction } = loaded;
						if (!interaction.binding || !this.emailAuthentication?.interactive) return reply.redirect("/login", 303);
						return send(reply, 200, emailPage({ tenantName: interaction.binding.tenantName, clientId: interaction.clientId,
								csrf: interaction.csrf }));
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
										return send(reply, 400, emailPage({ tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
												csrf: interaction.csrf,
												error: "Enter a valid email address." }));
								}
								const started = await this.emailAuthentication!.interactive!.start(authority, email.data,
										connectingApple(interaction) ? { authenticationOnly: true } : undefined);
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
										return send(reply, 400, emailPage({ tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
												csrf: interaction.csrf,
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
						return send(reply, 200, codePage({ tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
								csrf: interaction.csrf, connectApple: connectingApple(interaction) }));
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
								return send(reply, 200, codePage({ tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
										csrf: interaction.csrf, connectApple: connectingApple(interaction),
										notice: "We sent a new code. Earlier codes no longer work." }));
						} catch (error) {
								logUniversalLoginDiagnostic(app, { event: "EMAIL_FLOW_FAILED", route: "POST /login/email/resend",
										clientId: interaction?.clientId,
										correlationId: diagnosticCorrelationId(this.readInteractionHandle(request)),
										authenticationMethod: "email" });
								logLogin(request, "universal_login_email_resend", interaction, startedAt, false, error instanceof VerificationError ? error.code : "unavailable");
								if (interaction && error instanceof VerificationError && error.statusCode < 500) {
										return send(reply, statusOf(error) === 429 ? 429 : 400, codePage({ tenantName: interaction.binding?.tenantName,
												clientId: interaction.clientId,
												csrf: interaction.csrf, connectApple: connectingApple(interaction), error: statusOf(error) === 429
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
								if (connectingApple(interaction) && loaded.body.connect_apple !== "yes") {
										return send(reply, 400, codePage({ tenantName: interaction.binding?.tenantName,
												clientId: interaction.clientId, csrf: interaction.csrf, connectApple: true,
												error: "Confirm that you want to connect Apple to continue." }));
								}
								if (connectingApple(interaction) && mode === "REGISTRATION") throw new EmailAuthenticationError();
								const code = typeof loaded.body.code === "string" && loaded.body.code.length <= 128 ? loaded.body.code.trim() : "";
								const interactive = this.emailAuthentication!.interactive!;
								const verification = await interactive.verify(authority, interaction.email.challengeId, code, mode);
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_EMAIL_VERIFIED", route: "POST /login/email/code",
										clientId: interaction.clientId, correlationId, authorityValid: true, clientValid: true, authenticationMethod: "email" });
								const connectVerifiedApple = async (principal: AuthenticatedUser, verifiedInteraction: AuthorizationInteraction) => {
										if (!connectingApple(verifiedInteraction)) return true;
										const federation = verifiedInteraction.federation!;
										if (verification.mode !== "AUTHENTICATION") throw new EmailAuthenticationError();
										await requireApplicationMethod(verifiedInteraction.clientId, this.clientAuthority, "EXTERNAL_OIDC");
										const linked = await this.getFederationResolution().linkExisting(principal.id, {
												provider: federation.provider, providerIssuer: federation.providerIssuer,
												providerSubject: federation.providerSubject, audience: federation.audience,
												isPrivateRelayEmail: federation.isPrivateRelayEmail,
												evidenceReference: federation.evidenceReference, expiresAt: 0
										});
										if (linked.status === "linked" || linked.status === "already_linked") return true;
										logLogin(request, "universal_login_federated_apple_link", verifiedInteraction, startedAt, false, linked.status);
										return false;
								};
								const linkConflict = () => send(reply, 409, messagePage({ title: "Apple sign-in could not be connected",
										message: "This sign-in could not be connected to your account. Start again or contact support." }));
								if (await passkeyOffered(interaction)) {
										const principal = verification.mode === "REGISTRATION" ? verification.principal
												: await interactive.consumeResult(authority, verification.authenticationResult);
										const offered = await this.interactions.offerPasskeyEnrollment(loaded.handle, interaction, principal);
										if (!offered) return expired(reply);
										if (!await connectVerifiedApple(principal, interaction)) return linkConflict();
										return showPasskeyOffer(reply, offered.browserProof);
								}
								// Single-use: only the request that wins the interaction may turn the H4 result into an authorization code.
								const consumed = await this.interactions.consume(loaded.handle);
								if (!consumed) {
										logLogin(request, "universal_login_email", interaction, startedAt, false, "interaction_replayed");
										logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_FAILED", route: "POST /login/email/code",
												clientId: interaction.clientId, correlationId, reasonCode: "INTERACTION_ALREADY_CONSUMED" });
										return expired(reply);
								}
								if (consumed.email?.challengeId !== interaction.email.challengeId ||
										consumed.email.mode !== mode || connectingApple(consumed) !== connectingApple(interaction) ||
										(connectingApple(consumed) && (consumed.federation?.providerIssuer !== interaction.federation?.providerIssuer ||
												consumed.federation?.providerSubject !== interaction.federation?.providerSubject))) return expired(reply);
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_INTERACTION_CONSUMED", route: "POST /login/email/code",
										clientId: interaction.clientId, correlationId });
								const principal = verification.mode === "REGISTRATION" ? verification.principal
									: await interactive.consumeResult(authority, verification.authenticationResult);
								if (!await connectVerifiedApple(principal, consumed)) return linkConflict();
								logUniversalLoginDiagnostic(app, {
									event: verification.mode === "REGISTRATION" ? "EMAIL_REGISTRATION_COMPLETED" : "EMAIL_AUTHENTICATION_COMPLETED",
									route: "POST /login/email/code", clientId: interaction.clientId, correlationId,
									authenticationMethod: "email"
								});
								const redirect = await this.issueAuthorizationRedirect(principal, consumed.authorization);
								logLogin(request, "universal_login_email", consumed, startedAt, true, "", principal.id);
								logUniversalLoginDiagnostic(app, { event: "UNIVERSAL_LOGIN_OIDC_REDIRECT_ISSUED", route: "POST /login/email/code",
										clientId: interaction.clientId, correlationId, authenticationMethod: "email", httpStatus: 303 });
								const cookies = [this.interactionCookie(null)];
								const sessionCookie = await this.maybeEstablishSession(request, principal, interaction.clientId);
								if (sessionCookie) cookies.push(sessionCookie);
								reply.header("Set-Cookie", cookies);
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
										return send(reply, 401, codePage({ tenantName: interaction.binding?.tenantName,
												clientId: interaction.clientId, csrf: interaction.csrf,
												connectApple: connectingApple(interaction), error: emailFailed }));
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
								await requireApplicationMethod(interaction.clientId, this.clientAuthority, "PRIVATEID_FACE");
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
								if (error instanceof VerificationError) {
										logLogin(request, "universal_login_face", interaction, startedAt, false, "authentication_method_not_allowed");
										return reply.code(403).send({ error: "authentication_method_not_allowed" });
								}
								logLogin(request, "universal_login_face", interaction, startedAt, false, statusOf(error) === 429 ? "rate_limited" : "unavailable");
								if (interaction && statusOf(error) === 429) {
										return send(reply, 429, chooserPage({ tenantName: interaction.binding?.tenantName, csrf: interaction.csrf,
												clientId: interaction.clientId,
												emailAvailable: Boolean(interaction.binding && this.emailAuthentication?.interactive),
												error: "Too many attempts. Please wait a few minutes and try again." }));
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_FACE_UNAVAILABLE" }, "Universal Login face start failed");
								return unavailable(reply);
						}
				});

				// ---- HAPI ID V2-D: HAPI-hosted Apple/Google federation (default-off flags) ----

				// Launches the provider authorization request for a live interaction. state and nonce
				// are server-generated inside the federation transaction; the browser only ever sees
				// the final provider URL.
				const startFederated = async (request: FastifyRequest, reply: FastifyReply,
						provider: "APPLE" | "GOOGLE", routeLabel: string) => {
						const startedAt = Date.now();
						const flow = `universal_login_federated_${provider.toLowerCase()}_start`;
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, routeLabel);
								if (!loaded) return reply;
								interaction = loaded.interaction;
								const service = this.federatedService(provider);
								if (!service) {
										logLogin(request, flow, interaction, startedAt, false, "federation_disabled");
										return reply.code(404).send({ error: "not_found" });
								}
								if (!await this.interactionClientStillValid(interaction)) return expired(reply);
								await requireApplicationMethod(interaction.clientId, this.clientAuthority, "EXTERNAL_OIDC");
								const transaction = await this.getFederationTransactions().create({
										purpose: "login", provider, interactionHandle: loaded.handle });
								logLogin(request, flow, interaction, startedAt, true, "");
								return reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer")
										.redirect(service.buildAuthorizationUrl(transaction), 303);
						} catch (error) {
								if (error instanceof VerificationError) {
										logLogin(request, flow, interaction, startedAt, false, "authentication_method_not_allowed");
										return reply.code(403).send({ error: "authentication_method_not_allowed" });
								}
								logLogin(request, flow, interaction, startedAt, false, statusOf(error) === 429 ? "rate_limited" : "unavailable");
								if (interaction && statusOf(error) === 429) {
										return renderChooser(request, reply, interaction, 429, "Too many attempts. Please wait a few minutes and try again.");
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_FEDERATED_UNAVAILABLE", provider }, "Federated login start failed");
								return unavailable(reply);
						}
				};
				app.post("/login/federated/apple", { bodyLimit: 4096 },
						(request, reply) => startFederated(request, reply, "APPLE", "POST /login/federated/apple"));
				app.post("/login/federated/google", { bodyLimit: 4096 },
						(request, reply) => startFederated(request, reply, "GOOGLE", "POST /login/federated/google"));

				// Provider callbacks. Identification happens EXCLUSIVELY by the single-use server-side
				// state: the Apple callback is a cross-site form_post that carries no cookies, so no
				// cookie or browser-supplied value ever participates in transaction resolution.
				const handleFederatedCallback = async (request: FastifyRequest, reply: FastifyReply,
						provider: "APPLE" | "GOOGLE",
						params: { state?: string; code?: string; error?: string }) => {
						const startedAt = Date.now();
						const flow = `universal_login_federated_${provider.toLowerCase()}`;
						if (!this.isUniversalLoginEnabled()) return reply.code(404).send({ error: "not_found" });
						const service = this.federatedService(provider);
						if (!service) return reply.code(404).send({ error: "not_found" });
						try {
								await this.rateLimiter.assertWithinLimits({ ip: request.ip, clientId: "", userId: "" });
						} catch (error) {
								if (statusOf(error) === 429) return send(reply, 429, messagePage({
										title: "Too many attempts", message: "Please wait a few minutes and try again." }));
								throw error;
						}
						let outcome;
						try {
								outcome = await service.handleCallback(params);
						} catch (error) {
								if (!(error instanceof FederatedAuthorizationError)) throw error;
								logLogin(request, flow, null, startedAt, false, error.code, "", error.appleExchangeDiagnostic);
								// Recovery UX: when the failed transaction still maps to a live interaction, the
								// user returns to their chooser with a friendly message instead of a dead end.
								const handle = error.transaction?.interactionHandle;
								const interaction = handle ? await this.interactions.find(handle) : null;
								if (interaction && await this.interactionClientStillValid(interaction)) {
										return renderChooser(request, reply, interaction, 400,
												error.code === "provider_denied"
														? "Sign-in was cancelled. Choose how you want to continue."
														: "We couldn't complete that sign-in. Choose another way to continue.");
								}
								return expired(reply);
						}
						const { transaction, verified } = outcome;
						if (transaction.purpose !== "login" || !transaction.interactionHandle) return expired(reply);
						const interaction = await this.interactions.find(transaction.interactionHandle);
						if (!interaction || !await this.interactionClientStillValid(interaction)) return expired(reply);
						const resolution = await this.getFederationResolution().resolveForLogin(verified);
						if (resolution.status === "subject_inactive") {
								logLogin(request, flow, interaction, startedAt, false, "subject_inactive");
								return send(reply, 403, messagePage({ title: "This account is unavailable",
										message: "This sign-in is connected to an account that can't be used right now." }));
						}
						if (resolution.status === "unlinked") {
								// Returning-user resolution found nothing: persist the SERVER-verified identity on
								// the interaction and ask the user to choose explicitly. No account is created or
								// linked yet, and matching emails never resolve this automatically.
								const saved = await this.interactions.save(transaction.interactionHandle, { ...interaction, federation: {
										provider,
										providerIssuer: verified.providerIssuer,
										providerSubject: verified.providerSubject,
										audience: verified.audience,
										...(verified.email !== undefined ? { email: verified.email } : {}),
										...(verified.emailVerified !== undefined ? { emailVerified: verified.emailVerified } : {}),
										isPrivateRelayEmail: verified.isPrivateRelayEmail,
										evidenceReference: verified.evidenceReference,
										verifiedAt: Date.now()
								} });
								if (!saved) return expired(reply);
								logLogin(request, flow, interaction, startedAt, true, "account_choice_required");
								return send(reply, 200, federatedAccountChoicePage({
										tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
										csrf: interaction.csrf, provider,
										...(verified.email !== undefined && !verified.isPrivateRelayEmail ? { email: verified.email } : {}) }));
						}
						try {
								await requireApplicationMethod(interaction.clientId, this.clientAuthority, "EXTERNAL_OIDC");
						} catch (error) {
								if (error instanceof VerificationError) {
										logLogin(request, flow, interaction, startedAt, false, "authentication_method_not_allowed");
										return reply.code(403).send({ error: "authentication_method_not_allowed" });
								}
								throw error;
						}
						const principal = this.federatedPrincipal(resolution.subject, provider);
						if (await passkeyOffered(interaction)) {
								const offered = await this.interactions.offerPasskeyEnrollment(transaction.interactionHandle, interaction, principal);
								if (!offered) return expired(reply);
								return showPasskeyOffer(reply, offered.browserProof);
						}
						const consumed = await this.interactions.consume(transaction.interactionHandle);
						if (!consumed) {
								logLogin(request, flow, interaction, startedAt, false, "interaction_replayed");
								return expired(reply);
						}
						const redirect = await this.issueAuthorizationRedirect(principal, consumed.authorization);
						const cookies = [this.interactionCookie(null)];
						const sessionCookie = await this.maybeEstablishSession(request, principal, interaction.clientId);
						if (sessionCookie) cookies.push(sessionCookie);
						logLogin(request, flow, consumed, startedAt, true, "", principal.id);
						reply.header("Set-Cookie", cookies);
						return reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer").redirect(redirect, 303);
				};
				// Apple posts the result cross-site (response_mode=form_post, required with scopes).
				app.post("/federation/apple/callback", { bodyLimit: 65536 }, async (request, reply) => {
						const body = (request.body ?? {}) as Record<string, unknown>;
						return handleFederatedCallback(request, reply, "APPLE", {
								...(typeof body.state === "string" ? { state: body.state } : {}),
								...(typeof body.code === "string" ? { code: body.code } : {}),
								...(typeof body.error === "string" ? { error: body.error } : {})
						});
				});
				app.get("/federation/google/callback", async (request, reply) => {
						const query = (request.query ?? {}) as Record<string, unknown>;
						return handleFederatedCallback(request, reply, "GOOGLE", {
								...(typeof query.state === "string" ? { state: query.state } : {}),
								...(typeof query.code === "string" ? { code: query.code } : {}),
								...(typeof query.error === "string" ? { error: query.error } : {})
						});
				});

				// Explicit account resolution for a verified-but-unlinked federated identity.
				app.post("/login/federated/complete", { bodyLimit: 4096 }, async (request, reply) => {
						const startedAt = Date.now();
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, "POST /login/federated/complete");
								if (!loaded) return reply;
								interaction = loaded.interaction;
								const federation = interaction.federation;
								if (!federation || !await this.interactionClientStillValid(interaction)) return expired(reply);
								const flow = `universal_login_federated_${federation.provider.toLowerCase()}_register`;
								const choice = loaded.body.choice;
								if (choice === "email") {
										if (federation.provider === "APPLE") {
												if (!await this.interactiveEmailAuthority(interaction)) return expired(reply);
												const { email: _email, ...rest } = interaction;
												if (!await this.interactions.save(loaded.handle, {
														...rest, federation: { ...federation, linkExisting: true }
												})) return expired(reply);
												return reply.header("Cache-Control", "no-store").redirect("/login/email", 303);
										}
										const { federation: _federation, ...rest } = interaction;
										if (!await this.interactions.save(loaded.handle, rest)) return expired(reply);
										return reply.header("Cache-Control", "no-store").redirect("/login/email", 303);
								}
								if (connectingApple(interaction)) return expired(reply);
								if (choice !== "create") {
										return send(reply, 400, federatedAccountChoicePage({
												tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
												csrf: interaction.csrf, provider: federation.provider,
												error: "Choose whether to create a new account or sign in with email." }));
								}
								await requireApplicationMethod(interaction.clientId, this.clientAuthority, "EXTERNAL_OIDC");
								const verified: VerifiedFederatedIdentity = {
										provider: federation.provider,
										providerIssuer: federation.providerIssuer,
										providerSubject: federation.providerSubject,
										audience: federation.audience,
										...(federation.email !== undefined ? { email: federation.email } : {}),
										...(federation.emailVerified !== undefined ? { emailVerified: federation.emailVerified } : {}),
										isPrivateRelayEmail: federation.isPrivateRelayEmail,
										expiresAt: 0,
										evidenceReference: federation.evidenceReference
								};
								const registered = await this.getFederationResolution().registerFirstTime(verified);
								if (registered.status === "conflict") {
										logLogin(request, flow, interaction, startedAt, false, "registration_conflict");
										return send(reply, 409, federatedAccountChoicePage({
												tenantName: interaction.binding?.tenantName, clientId: interaction.clientId,
												csrf: interaction.csrf, provider: federation.provider,
												error: "That sign-in just became connected to another account. Sign in with email instead." }));
								}
								const principal = this.federatedPrincipal(registered.subject, federation.provider);
								if (await passkeyOffered(interaction)) {
										const offered = await this.interactions.offerPasskeyEnrollment(loaded.handle, interaction, principal);
										if (!offered) return expired(reply);
										return showPasskeyOffer(reply, offered.browserProof);
								}
								const consumed = await this.interactions.consume(loaded.handle);
								if (!consumed) {
										logLogin(request, flow, interaction, startedAt, false, "interaction_replayed");
										return expired(reply);
								}
								const redirect = await this.issueAuthorizationRedirect(principal, consumed.authorization);
								const cookies = [this.interactionCookie(null)];
								const sessionCookie = await this.maybeEstablishSession(request, principal, interaction.clientId);
								if (sessionCookie) cookies.push(sessionCookie);
								logLogin(request, flow, consumed, startedAt, true, "", principal.id);
								reply.header("Set-Cookie", cookies);
								return reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer").redirect(redirect, 303);
						} catch (error) {
								if (error instanceof VerificationError) {
										return reply.code(403).send({ error: "authentication_method_not_allowed" });
								}
								if (interaction && statusOf(error) === 429) {
										return renderChooser(request, reply, interaction, 429, "Too many attempts. Please wait a few minutes and try again.");
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_FEDERATED_UNAVAILABLE" }, "Federated registration failed");
								return unavailable(reply);
						}
				});

				// Returning-user continuation from an existing valid HAPI session (V2-D account selection).
				app.post("/login/continue", { bodyLimit: 4096 }, async (request, reply) => {
						const startedAt = Date.now();
						let interaction: AuthorizationInteraction | null = null;
						try {
								const loaded = await load(request, reply, true, "POST /login/continue");
								if (!loaded) return reply;
								interaction = loaded.interaction;
								if (!await this.interactionClientStillValid(interaction)) return expired(reply);
								const continuation = await this.detectSessionContinuation(request);
								if (!continuation || continuation.session.authenticationMethod === "PASSKEY") {
										return renderChooser(request, reply, interaction, 401,
												"Your saved session is no longer valid. Choose how you want to sign in.");
								}
								await requireApplicationMethod(interaction.clientId, this.clientAuthority,
										this.applicationMethodFor(continuation.session.authenticationMethod));
								const consumed = await this.interactions.consume(loaded.handle);
								if (!consumed) return expired(reply);
								const subject = continuation.subject;
								const principal: AuthenticatedUser = {
										id: subject.id,
										sub: subject.oidcSubject,
										...(subject.email !== undefined ? { email: subject.email } : {}),
										...(subject.emailVerified !== undefined ? { emailVerified: subject.emailVerified } : {}),
										...(subject.displayName !== undefined ? { name: subject.displayName } : {}),
										authenticationMethod: continuation.session.authenticationMethod,
										// Honest auth_time: the ORIGINAL authentication instant, not the continuation.
										authenticatedAt: continuation.session.authenticatedAt
								};
								const redirect = await this.issueAuthorizationRedirect(principal, consumed.authorization);
								logLogin(request, "universal_login_continue", consumed, startedAt, true, "", principal.id);
								reply.header("Set-Cookie", this.interactionCookie(null));
								return reply.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer").redirect(redirect, 303);
						} catch (error) {
								if (error instanceof VerificationError) {
										return reply.code(403).send({ error: "authentication_method_not_allowed" });
								}
								if (interaction && statusOf(error) === 429) {
										return renderChooser(request, reply, interaction, 429, "Too many attempts. Please wait a few minutes and try again.");
								}
								app.log.error({ event: "UNIVERSAL_LOGIN_CONTINUE_UNAVAILABLE" }, "Session continuation failed");
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
				try {
						await resolveRegisteredClient(clientId, this.clientAuthority);
				} catch (error) {
						if (error instanceof VerificationError) return null;
						throw error;
				}
				if (!this.options.clients) {
						const persisted = await this.oidcClients.findByClientId(clientId);
						return persisted ? this.toOIDCClient(persisted) : null;
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

		private clientTokenEndpointAuthMethod(
				client: OIDCClient
		): "client_secret_basic" | "client_secret_post" | "none" | undefined {
				const method = client.token_endpoint_auth_method;
				return method === "client_secret_basic" || method === "client_secret_post" || method === "none"
						? method
						: undefined;
		}

		private hasValidClientAuthenticationConfiguration(client: OIDCClient): boolean {
				const method = this.clientTokenEndpointAuthMethod(client);
				if (!method) {
						return false;
				}

				if (method === "none") {
						return true;
				}

				return typeof client.client_secret === "string" && client.client_secret.trim().length > 0;
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

		// V2-B interim refresh-token policy: issuance strictly follows the client registration.
		// Legacy metadata without a grant list keeps its existing behavior (token issued).
		private clientAllowsRefreshTokenGrant(client: OIDCClient): boolean {
				const grants = client.grant_types;

				if (!Array.isArray(grants)) {
						return true;
				}

				return grants.includes("refresh_token");
		}

		// HAPI ID V2-C: lifetime profile per the approved family design -- public (secretless)
		// clients get native lifetimes, confidential clients the shorter web lifetimes.
		private refreshClientProfile(client: OIDCClient): RefreshClientProfile {
				return this.clientTokenEndpointAuthMethod(client) === "none"
						? "native_public"
						: "confidential_web";
		}

		private getRefreshRotation(): RefreshTokenRotationService {
				if (!this.refreshRotation) {
						this.refreshRotation = new RefreshTokenRotationService();
				}
				return this.refreshRotation;
		}

		// ---- HAPI ID V2-D federation collaborators (all behind default-off flags) ----

		private getFederationTransactions(): FederationTransactionStore {
				if (!this.federationTransactions) {
						this.federationTransactions = new FederationTransactionStore();
				}
				return this.federationTransactions;
		}

		private getFederationResolution(): FederatedIdentityResolutionService {
				if (!this.federationResolution) {
						this.federationResolution = federatedIdentityResolutionService;
				}
				return this.federationResolution;
		}

		private getSessionService(): HapiSessionService {
				if (!this.sessionService) {
						this.sessionService = new HapiSessionService();
				}
				return this.sessionService;
		}

		// Resolves the provider integration, or null unless BOTH the provider's default-off flag is
		// enabled AND an integration exists (injected, or fully configured credentials). A partially
		// configured provider can never appear on the login surface.
		private federatedService(provider: "APPLE" | "GOOGLE"): FederatedAuthorizationService | null {
				if (provider === "APPLE") {
						if (!featureFlags.isAppleFederationEnabled()) return null;
						if (this.appleFederation) return this.appleFederation;
						const config = configuration.getAppleFederationConfiguration();
						if (!config) return null;
						const secrets = new AppleClientSecretService({
								teamId: config.teamId,
								clientId: config.servicesId,
								keyId: config.keyId,
								privateKeyPem: config.privateKeyPem
						});
						this.appleFederation = new FederatedAuthorizationService(
								{
										provider: "APPLE",
										clientId: config.servicesId,
										redirectUri: config.redirectUri,
										scope: "name email",
										authorizationEndpoint: APPLE_AUTHORIZATION_ENDPOINT,
										tokenEndpoint: APPLE_TOKEN_ENDPOINT,
										// Apple requires form_post when scopes are requested.
										responseMode: "form_post",
										clientSecret: () => secrets.generate()
								},
								new AppleIdentityTokenVerifier({ expectedAudiences: [config.servicesId] }),
								this.getFederationTransactions()
						);
						return this.appleFederation;
				}
				if (!featureFlags.isGoogleFederationEnabled()) return null;
				if (this.googleFederation) return this.googleFederation;
				const config = configuration.getGoogleFederationConfiguration();
				if (!config) return null;
				this.googleFederation = new FederatedAuthorizationService(
						{
								provider: "GOOGLE",
								clientId: config.clientId,
								redirectUri: config.redirectUri,
								scope: "openid email profile",
								authorizationEndpoint: GOOGLE_AUTHORIZATION_ENDPOINT,
								tokenEndpoint: GOOGLE_TOKEN_ENDPOINT,
								clientSecret: async () => config.clientSecret
						},
						new GoogleIdentityTokenVerifier({ expectedAudiences: [config.clientId] }),
						this.getFederationTransactions()
				);
				return this.googleFederation;
		}

		// The ONLY construction path for a federated login principal: subject comes from the
		// authoritative Identity Registry via an active external-identity link.
		private federatedPrincipal(subject: IdentitySubject, provider: "APPLE" | "GOOGLE"): AuthenticatedUser {
				return {
						id: subject.id,
						sub: subject.oidcSubject,
						...(subject.email !== undefined ? { email: subject.email } : {}),
						...(subject.emailVerified !== undefined ? { emailVerified: subject.emailVerified } : {}),
						...(subject.displayName !== undefined ? { name: subject.displayName } : {}),
						authenticationMethod: provider,
						authenticatedAt: new Date().toISOString(),
						assurance: "federated"
				};
		}

		private readSessionCookie(request: FastifyRequest): string | undefined {
				return request.headers.cookie?.split(";").map(value => value.trim())
						.find(value => value.startsWith(`${HAPI_SESSION_COOKIE}=`))?.slice(HAPI_SESSION_COOKIE.length + 1) || undefined;
		}

		// V2-D session establishment at Universal Login completion. Gated on
		// HAPI_PERSISTENT_SESSIONS_ENABLED (default OFF -- byte-identical behavior otherwise), and
		// never allowed to break the login itself. Fixation-safe: any session token the browser
		// already held is revoked by establishSession before the new one exists.
		private async maybeEstablishSession(request: FastifyRequest, principal: AuthenticatedUser,
				clientId: string): Promise<string | undefined> {
				if (!featureFlags.isPersistentSessionsEnabled() || !principal.authenticationMethod || principal.authenticationMethod === "PASSKEY") {
						return undefined;
				}
				try {
						const supersedes = this.readSessionCookie(request);
						const userAgent = request.headers["user-agent"];
						const established = await this.getSessionService().establishSession({
								identitySubjectId: principal.id,
								authenticationMethod: principal.authenticationMethod as HapiSessionAuthenticationMethod,
								clientId,
								...(typeof userAgent === "string" ? { userAgent } : {}),
								...(principal.authenticatedAt !== undefined ? { authenticatedAt: principal.authenticatedAt } : {}),
								...(supersedes !== undefined ? { supersedesSessionToken: supersedes } : {})
						});
						return established.setCookie;
				} catch (error) {
						request.log.error({ event: "HAPI_SESSION_ESTABLISH_FAILED" }, "Failed to establish HAPI session");
						return undefined;
				}
		}

		// Existing-session detection for the Universal Login chooser ("Continue as ..."). Read-only:
		// never touches the session, never throws.
		private async detectSessionContinuation(request: FastifyRequest): Promise<{ session: HapiSession; subject: IdentitySubject } | null> {
				if (!featureFlags.isPersistentSessionsEnabled()) return null;
				const token = this.readSessionCookie(request);
				if (!token) return null;
				try {
						const session = await this.getSessionService().resolveSession(token, { touch: false });
						const subject = await identityRegistry.findById(session.identitySubjectId);
						if (!subject || subject.status !== "ACTIVE") return null;
						return { session, subject };
				} catch {
						return null;
				}
		}

		// HAPI ID V2-C grant_type=refresh_token handler. Reached ONLY when the default-off
		// HAPI_REFRESH_GRANT_ENABLED gate is on. Client authentication mirrors the
		// authorization_code path exactly: confidential clients present their secret, public
		// clients are bound by exact client_id match against the family.
		private async handleRefreshTokenGrant(input: {
				refreshToken?: string;
				clientId?: string;
				clientSecret?: string;
				reply: FastifyReply;
		}): Promise<{ body: Record<string, unknown>; error?: string; user?: string }> {
				const { reply } = input;

				if (!input.refreshToken) {
						reply.code(400);
						return {
								body: { error: "invalid_request", error_description: "refresh_token is required" },
								error: "refresh_token is required"
						};
				}
				if (!input.clientId) {
						reply.code(400);
						return {
								body: { error: "invalid_client", error_description: "Client authentication failed: no client_id supplied" },
								error: "Client authentication failed: no client_id supplied"
						};
				}

				const client = await this.resolveClient(input.clientId);
				if (!client) {
						reply.code(400);
						return { body: { error: "invalid_client", error_description: "Unknown client" }, error: "Unknown client" };
				}
				// Client-specific refresh eligibility: the persisted registration must include the grant.
				if (!this.clientAllowsRefreshTokenGrant(client)) {
						reply.code(400);
						return {
								body: { error: "unauthorized_client", error_description: "Client is not authorized for grant_type=refresh_token" },
								error: "Client is not authorized for grant_type=refresh_token"
						};
				}
				if (!this.hasValidClientAuthenticationConfiguration(client)) {
						reply.code(400);
						return {
								body: { error: "invalid_client", error_description: "Client authentication metadata is invalid" },
								error: "Client authentication metadata is invalid"
						};
				}
				const tokenEndpointAuthMethod = this.clientTokenEndpointAuthMethod(client);
				const configuredClientSecret =
						typeof client.client_secret === "string" ? client.client_secret : "";
				if (
						tokenEndpointAuthMethod !== "none" &&
						(!input.clientSecret || !configuredClientSecret.trim() ||
								!constantTimeStringEqual(configuredClientSecret, input.clientSecret))
				) {
						reply.code(400);
						return {
								body: { error: "invalid_client", error_description: "client_secret is invalid" },
								error: "client_secret is invalid"
						};
				}

				let rotated;
				try {
						rotated = await this.getRefreshRotation().rotate({
								refreshToken: input.refreshToken,
								clientId: input.clientId,
								clientProfile: this.refreshClientProfile(client)
						});
				} catch (err) {
						if (err instanceof RefreshRotationError) {
								// Every rotation failure maps to invalid_grant (RFC 6749 §5.2); the typed code is
								// logged, never echoed with token material. Replay has already revoked the family.
								reply.code(400);
								return {
										body: { error: "invalid_grant", error_description: "Refresh token is invalid, expired, or revoked" },
										error: err.code
								};
						}
						throw err;
				}

				// Subject lifecycle binding: a locked/disabled/retired subject terminates the family.
				const subjectRecord = await identityRegistry.findById(rotated.family.identitySubjectId);
				if (!subjectRecord || subjectRecord.status !== "ACTIVE") {
						await this.getRefreshRotation().revokeFamily(rotated.family.id, "subject_locked");
						reply.code(400);
						return {
								body: { error: "invalid_grant", error_description: "Refresh token is invalid, expired, or revoked" },
								error: "subject_not_active"
						};
				}

				const accessToken = this.createOpaqueToken();
				await this.storeAccessToken(accessToken, {
						sub: subjectRecord.oidcSubject,
						clientId: input.clientId,
						// Refresh exchanges carry no authentication-request nonce (OIDC Core §12).
						nonce: "",
						scope: rotated.family.scope,
						issuer: this.resolveIssuer(),
						...(rotated.family.authenticationMethod ? {
								authenticationMethod: rotated.family.authenticationMethod as "HAPI_EMAIL" | "PRIVATEID_FACE" | "APPLE" | "GOOGLE" | "PASSKEY",
								...(rotated.family.authenticatedAt
										? { authenticatedAt: rotated.family.authenticatedAt } : {})
						} : {})
				});

				reply.code(200);
				this.metrics.tokensIssued += 1;
				return {
						body: {
								token_type: "Bearer",
								expires_in: 300,
								access_token: accessToken,
								refresh_token: rotated.refreshToken,
								scope: rotated.family.scope
						},
						user: subjectRecord.id
				};
		}

		private clientRequiresPkce(client: OIDCClient): boolean {
				if (this.clientTokenEndpointAuthMethod(client) === "none") {
						return true;
				}

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
			authenticationMethod?: AuthenticatedUser["authenticationMethod"];
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
					amr: this.amrFor(input.authenticationMethod),
					auth_time: Math.floor(Date.parse(input.authenticatedAt) / 1000)
				} : {})
			};
		}

		// Honest amr values: the actual authentication the HAPI subject performed, including the
		// upstream provider for federated sign-ins.
		private amrFor(method: NonNullable<AuthenticatedUser["authenticationMethod"]>): string[] {
			switch (method) {
				case "HAPI_EMAIL": return ["email"];
				case "APPLE": return ["apple", "fed"];
				case "GOOGLE": return ["google", "fed"];
				case "PASSKEY": return ["passkey"];
				default: return ["face", "privateid"];
			}
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
			authenticationMethod?: AuthenticatedUser["authenticationMethod"];
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
						const tokenEndpointAuthMethod = this.clientTokenEndpointAuthMethod(client) ?? "invalid";

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
