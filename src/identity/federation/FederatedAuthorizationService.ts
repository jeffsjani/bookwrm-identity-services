import type { ExternalIdentityProvider } from "../../models/ExternalIdentity.js";
import type { FederatedIdentityTokenVerifier, VerifiedFederatedIdentity } from "./FederatedIdentityTypes.js";
import type { FederationTransaction, FederationTransactionStore } from "./FederationTransactionStore.js";

export const APPLE_AUTHORIZATION_ENDPOINT = "https://appleid.apple.com/auth/authorize";
export const APPLE_TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token";
export const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

export type FederatedAuthorizationErrorCode =
		// Unknown, expired, replayed, or forged state: the transaction cannot be identified.
		| "invalid_state"
		// The user declined at the provider (e.g. Apple user_cancelled_authorize, Google access_denied).
		| "provider_denied"
		// Any other provider-reported authorization error.
		| "provider_error"
		// The server-side authorization-code exchange failed (invalid/replayed code, provider outage,
		// misconfigured credentials). Never carries provider response bodies.
		| "code_exchange_failed"
		// The exchanged id_token failed signature/issuer/audience/nonce/expiry verification.
		| "verification_failed";

const APPLE_OAUTH_ERRORS = [
		"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope"
] as const;

export type AppleExchangeDiagnostic =
		| { category: "signing" }
		| { category: "network" | "malformed_response" }
		| { category: "provider_rejection"; status: number; oauthError?: typeof APPLE_OAUTH_ERRORS[number] };

export class FederatedAuthorizationError extends Error {
		constructor(
				readonly code: FederatedAuthorizationErrorCode,
				message: string,
				// Present when the failing transaction could still be identified and consumed, so the
				// caller can route the user back to their live login interaction.
				readonly transaction?: FederationTransaction,
				readonly appleExchangeDiagnostic?: AppleExchangeDiagnostic
		) {
				super(message);
				this.name = "FederatedAuthorizationError";
		}
}

// Server-side authorization-code exchange against the provider token endpoint. Implementations
// receive fully-formed form parameters (including the client secret) and return the raw id_token.
// Tests inject a synthetic exchanger; the HTTP implementation below is used only when live
// provider federation is explicitly configured and enabled.
export interface AuthorizationCodeExchanger {
		exchange(tokenEndpoint: string, params: URLSearchParams): Promise<{ idToken: string }>;
}

export class AuthorizationCodeExchangeError extends Error {
		constructor(message: string, readonly diagnostic: Exclude<AppleExchangeDiagnostic, { category: "signing" }>) {
				super(message);
				this.name = "AuthorizationCodeExchangeError";
		}
}

// Production exchanger: a direct server-to-provider POST. Provider error bodies are never
// included in thrown errors (they can echo the authorization code).
export class HttpAuthorizationCodeExchanger implements AuthorizationCodeExchanger {
		constructor(private readonly fetchImpl: typeof fetch = fetch) {}

		async exchange(tokenEndpoint: string, params: URLSearchParams): Promise<{ idToken: string }> {
				let response: Response;
				try {
						response = await this.fetchImpl(tokenEndpoint, {
								method: "POST",
								headers: { "content-type": "application/x-www-form-urlencoded" },
								body: params.toString()
						});
				} catch {
						throw new AuthorizationCodeExchangeError("Provider token endpoint is unreachable", { category: "network" });
				}
				if (!response.ok) {
						let oauthError: typeof APPLE_OAUTH_ERRORS[number] | undefined;
						if (tokenEndpoint === APPLE_TOKEN_ENDPOINT) {
								try {
										const body: unknown = await response.json();
										const error = typeof body === "object" && body !== null && "error" in body ? body.error : undefined;
										oauthError = APPLE_OAUTH_ERRORS.find((allowed) => allowed === error);
								} catch {
										// A non-JSON rejection still has a safe HTTP status.
								}
						}
						throw new AuthorizationCodeExchangeError(`Provider token endpoint rejected the exchange (${response.status})`,
								{ category: "provider_rejection", status: response.status, ...(oauthError ? { oauthError } : {}) });
				}
				let body: unknown;
				try {
						body = await response.json();
				} catch {
						throw new AuthorizationCodeExchangeError("Provider token endpoint returned a malformed response",
								{ category: "malformed_response" });
				}
				const idToken = (body as { id_token?: unknown })?.id_token;
				if (typeof idToken !== "string" || idToken.length === 0) {
						throw new AuthorizationCodeExchangeError("Provider token endpoint response is missing id_token",
								{ category: "malformed_response" });
				}
				return { idToken };
		}
}

export type FederatedProviderConfiguration = {
		provider: ExternalIdentityProvider;
		// The registered provider client (Apple Services ID / Google OAuth client id).
		clientId: string;
		// The EXACT redirect URI registered with the provider. Always server configuration --
		// callback requests never influence where the provider redirects.
		redirectUri: string;
		scope: string;
		authorizationEndpoint: string;
		tokenEndpoint: string;
		// Apple requires response_mode=form_post whenever scopes are requested.
		responseMode?: "form_post";
		// Returns the client secret for the token exchange: Apple mints a fresh ES256 JWT per
		// exchange (AppleClientSecretService); Google uses its registered static secret.
		clientSecret: () => Promise<string>;
};

export type FederatedCallbackInput = {
		state?: string;
		code?: string;
		error?: string;
};

export type FederatedCallbackResult = {
		transaction: FederationTransaction;
		verified: VerifiedFederatedIdentity;
};

// Provider-cancellation codes mapped to the typed provider_denied outcome.
const PROVIDER_DENIAL_CODES = new Set(["user_cancelled_authorize", "access_denied", "consent_required"]);

// HAPI ID V2-D: one upstream authorization integration per provider. Owns the three
// security-critical steps of the round-trip: (1) launching the provider request with a
// server-generated single-use state and nonce, (2) exchanging the returned code server-side with
// securely held credentials, and (3) verifying the resulting id_token (JWKS signature, exact
// issuer, registered audience, transaction nonce, expiry) before any identity material exists.
export class FederatedAuthorizationService {
		constructor(
				private readonly config: FederatedProviderConfiguration,
				private readonly verifier: FederatedIdentityTokenVerifier,
				private readonly transactions: FederationTransactionStore,
				private readonly exchanger: AuthorizationCodeExchanger = new HttpAuthorizationCodeExchanger()
		) {}

		get provider(): ExternalIdentityProvider {
				return this.config.provider;
		}

		get clientId(): string {
				return this.config.clientId;
		}

		get redirectUri(): string {
				return this.config.redirectUri;
		}

		get scope(): string {
				return this.config.scope;
		}

		// Builds the provider authorization URL for an already-created transaction. The redirect_uri
		// is the registered server configuration value -- never derived from the request.
		buildAuthorizationUrl(transaction: FederationTransaction): string {
				const url = new URL(this.config.authorizationEndpoint);
				url.searchParams.set("response_type", "code");
				url.searchParams.set("client_id", this.config.clientId);
				url.searchParams.set("redirect_uri", this.config.redirectUri);
				url.searchParams.set("scope", this.config.scope);
				url.searchParams.set("state", transaction.state);
				url.searchParams.set("nonce", transaction.nonce);
				if (this.config.responseMode) {
						url.searchParams.set("response_mode", this.config.responseMode);
				}
				return url.toString();
		}

		// Handles the provider callback: state validation (single-use), provider error mapping,
		// server-side code exchange, and full id_token verification bound to the transaction nonce.
		async handleCallback(input: FederatedCallbackInput): Promise<FederatedCallbackResult> {
				// The state is consumed FIRST: even a denied or failed round-trip burns its transaction,
				// so a captured callback URL can never be replayed into a different outcome.
				const transaction = await this.transactions.consumeByState(input.state);
				if (!transaction || transaction.provider !== this.config.provider) {
						throw new FederatedAuthorizationError("invalid_state",
								"Unknown, expired, or already-used federation state");
				}

				if (input.error) {
						const code = PROVIDER_DENIAL_CODES.has(input.error) ? "provider_denied" : "provider_error";
						throw new FederatedAuthorizationError(code,
								`Provider authorization did not complete (${input.error})`, transaction);
				}
				if (typeof input.code !== "string" || input.code.trim().length === 0) {
						throw new FederatedAuthorizationError("provider_error",
								"Provider callback is missing an authorization code", transaction);
				}

				let idToken: string;
				let generatingSecret = true;
				try {
						const clientSecret = await this.config.clientSecret();
						generatingSecret = false;
						const params = new URLSearchParams({
								grant_type: "authorization_code",
								code: input.code,
								redirect_uri: this.config.redirectUri,
								client_id: this.config.clientId,
								client_secret: clientSecret
						});
						({ idToken } = await this.exchanger.exchange(this.config.tokenEndpoint, params));
				} catch (error) {
						// Deliberately detail-free: exchange failures never echo codes, secrets, or bodies.
						const diagnostic = this.config.provider !== "APPLE" ? undefined
								: generatingSecret ? { category: "signing" as const }
								: error instanceof AuthorizationCodeExchangeError ? error.diagnostic : undefined;
						throw new FederatedAuthorizationError("code_exchange_failed",
								"Provider authorization-code exchange failed", transaction, diagnostic);
				}

				try {
						const verified = await this.verifier.verify(idToken, { nonce: transaction.nonce });
						return { transaction, verified };
				} catch {
						throw new FederatedAuthorizationError("verification_failed",
								"Provider identity token failed verification", transaction);
				}
		}
}
