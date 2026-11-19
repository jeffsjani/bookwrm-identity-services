import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";

import { featureFlags } from "../config/FeatureFlagService.js";
import {
		identityFederationService,
		type IdentityFederationService
} from "../identity/IdentityFederationService.js";
import type { FederatedAuthorizationService } from "../identity/federation/FederatedAuthorizationService.js";
import type { FederatedIdentityTokenVerifier } from "../identity/federation/FederatedIdentityTypes.js";
import { FederationTransactionStore } from "../identity/federation/FederationTransactionStore.js";
import {
		HAPI_SESSION_COOKIE,
		HapiSessionError,
		HapiSessionService
} from "../identity/sessions/HapiSessionService.js";
import type { HapiSession } from "../models/HapiSession.js";
import type { ExternalIdentityProvider, IdentityAuthenticationMethod } from "../models/ExternalIdentity.js";
import { OIDCRateLimiter } from "../oidc/infrastructure/OIDCRateLimiter.js";
import { RefreshTokenRotationService } from "../oidc/refresh/RefreshTokenRotationService.js";

// V2-C design §2.6: sensitive account-linking changes require authentication within this window.
export const RECENT_AUTHENTICATION_MAX_AGE_MS = 600_000;
export const HAPI_CSRF_HEADER = "x-hapi-csrf";

export type AccountAuthenticationMethodsDependencies = {
		sessions?: HapiSessionService;
		federation?: IdentityFederationService;
		transactions?: FederationTransactionStore;
		// Server-side provider verifiers; a provider without a verifier cannot be linked.
		verifiers?: Partial<Record<ExternalIdentityProvider, FederatedIdentityTokenVerifier>>;
		// Optional provider authorization integrations used to describe the authorization request a
		// client must launch (client id, redirect URI, scope). Verification never depends on these.
		authorization?: Partial<Record<ExternalIdentityProvider, FederatedAuthorizationService>>;
		rateLimiter?: OIDCRateLimiter;
		refreshRotation?: RefreshTokenRotationService;
};

type ResolvedDependencies = Required<Pick<AccountAuthenticationMethodsDependencies,
		"sessions" | "federation" | "transactions" | "rateLimiter" | "refreshRotation">> & {
		verifiers: Partial<Record<ExternalIdentityProvider, FederatedIdentityTokenVerifier>>;
		authorization: Partial<Record<ExternalIdentityProvider, FederatedAuthorizationService>>;
};

function readSessionCookie(request: FastifyRequest): string | undefined {
		return request.headers.cookie?.split(";").map(value => value.trim())
				.find(value => value.startsWith(`${HAPI_SESSION_COOKIE}=`))?.slice(HAPI_SESSION_COOKIE.length + 1) || undefined;
}

function methodsView(methods: IdentityAuthenticationMethod[]) {
		const active = methods.filter((method) => method.status !== "revoked");
		const canUnlink: Record<string, boolean> = {};
		for (const method of active) {
				// Advisory only -- the repository re-enforces last-method protection transactionally.
				canUnlink[method.id] = !method.derived && active.length > 1;
		}
		return {
				methods: active.map((method) => ({
						id: method.id,
						type: method.methodType,
						status: method.status,
						...(method.derived ? { derived: true } : {}),
						...(method.externalIdentityId !== undefined ? { externalIdentityId: method.externalIdentityId } : {}),
						...(method.createdAt !== undefined ? { linkedAt: method.createdAt } : {}),
						...(method.lastUsedAt !== undefined ? { lastAuthenticatedAt: method.lastUsedAt } : {})
				})),
				canUnlink
		};
}

// HAPI ID V2-D: the authenticated account-linking API specified and certified in the V2-C Phase 4
// design document. Same-origin browser/native API -- NOT an OAuth surface. Non-negotiable
// invariants enforced here:
//   1. every endpoint requires a valid, non-stale HAPI session (__Host-hapi_sid);
//   2. every state-changing request requires the double-submit CSRF header;
//   3. start/complete/unlink require RECENT authentication (step-up window);
//   4. the browser NEVER supplies a trusted issuer or subject -- only raw provider id_tokens that
//      are fully verified server-side against the transaction's server-generated nonce;
//   5. linking/unlinking and audit are atomic in the V2-B repository; matching emails never link.
// The whole surface ships behind the default-off HAPI_ACCOUNT_LINKING_API_ENABLED flag.
export async function registerAccountAuthenticationMethodRoutes(
		app: FastifyInstance,
		dependencies: AccountAuthenticationMethodsDependencies = {}
): Promise<void> {
		let resolved: ResolvedDependencies | undefined;
		const deps = (): ResolvedDependencies => {
				if (!resolved) {
						resolved = {
								sessions: dependencies.sessions ?? new HapiSessionService(),
								federation: dependencies.federation ?? identityFederationService,
								transactions: dependencies.transactions ?? new FederationTransactionStore(),
								verifiers: dependencies.verifiers ?? {},
								authorization: dependencies.authorization ?? {},
								rateLimiter: dependencies.rateLimiter ?? new OIDCRateLimiter(),
								refreshRotation: dependencies.refreshRotation ?? new RefreshTokenRotationService()
						};
				}
				return resolved;
		};

		const enabled = () => featureFlags.isAccountLinkingApiEnabled();

		type AuthenticatedContext = { session: HapiSession };

		// Shared guard: flag, session, rate limits, CSRF (mutations), recent authentication.
		const authenticate = async (request: FastifyRequest, reply: FastifyReply,
				options: { mutation: boolean; stepUp: boolean }): Promise<AuthenticatedContext | null> => {
				if (!enabled()) {
						reply.code(404).send({ error: "not_found" });
						return null;
				}
				const token = readSessionCookie(request);
				if (!token) {
						reply.code(401).send({ error: "authentication_required" });
						return null;
				}
				let session: HapiSession;
				try {
						session = await deps().sessions.resolveSession(token);
				} catch (error) {
						if (error instanceof HapiSessionError) {
								// Stale or foreign sessions fail closed before any state can change.
								reply.code(401).send({ error: error.code === "session_not_found"
										? "authentication_required" : "stale_session" });
								return null;
						}
						throw error;
				}
				try {
						await deps().rateLimiter.assertWithinLimits({
								ip: request.ip, clientId: "hapi-account-linking", userId: session.identitySubjectId });
				} catch (error) {
						if (typeof (error as { statusCode?: unknown })?.statusCode === "number"
								&& (error as { statusCode: number }).statusCode === 429) {
								reply.code(429).send({ error: "rate_limited" });
								return null;
						}
						throw error;
				}
				if (options.mutation) {
						const presented = request.headers[HAPI_CSRF_HEADER];
						try {
								deps().sessions.verifyCsrfToken(session, typeof presented === "string" ? presented : "");
						} catch {
								reply.code(403).send({ error: "csrf_invalid" });
								return null;
						}
				}
				if (options.stepUp && !deps().sessions.isRecentlyAuthenticated(session, RECENT_AUTHENTICATION_MAX_AGE_MS)) {
						reply.code(428).send({ error: "step_up_required", maxAgeSeconds: RECENT_AUTHENTICATION_MAX_AGE_MS / 1000 });
						return null;
				}
				return { session };
		};

		const listResponse = async (session: HapiSession) => {
				const methods = await deps().federation.listAuthenticationMethods(session.identitySubjectId);
				return {
						...methodsView(methods),
						recentAuthentication: {
								satisfied: deps().sessions.isRecentlyAuthenticated(session, RECENT_AUTHENTICATION_MAX_AGE_MS),
								authTime: session.authenticatedAt,
								maxAgeSeconds: RECENT_AUTHENTICATION_MAX_AGE_MS / 1000
						}
				};
		};

		app.get("/account/authentication-methods", async (request, reply) => {
				const context = await authenticate(request, reply, { mutation: false, stepUp: false });
				if (!context) return reply;
				return listResponse(context.session);
		});

		app.post("/account/authentication-methods/link", { bodyLimit: 4096 }, async (request, reply) => {
				const context = await authenticate(request, reply, { mutation: true, stepUp: true });
				if (!context) return reply;
				const body = (request.body ?? {}) as Record<string, unknown>;
				const provider = body.provider;
				if (provider !== "APPLE" && provider !== "GOOGLE") {
						return reply.code(400).send({ error: "invalid_provider" });
				}
				// Linking a provider requires its server-side verifier to exist; a provider that is not
				// configured for verification is indistinguishable from a disabled surface.
				if (!deps().verifiers[provider]) {
						return reply.code(404).send({ error: "linking_disabled" });
				}
				const methods = await deps().federation.listAuthenticationMethods(context.session.identitySubjectId);
				if (methods.some((method) => method.methodType === provider && method.status !== "revoked")) {
						return reply.code(409).send({ error: "provider_already_linked" });
				}
				// Single-use, short-TTL linking transaction bound to this exact subject AND session;
				// state and nonce are server-generated and never influenced by the client.
				const transaction = await deps().transactions.create({
						purpose: "link",
						provider,
						identitySubjectId: context.session.identitySubjectId,
						sessionId: context.session.id
				});
				const authorization = deps().authorization[provider];
				return {
						transactionId: transaction.id,
						nonce: transaction.nonce,
						expiresAt: new Date(transaction.expiresAt).toISOString(),
						authorizationParameters: {
								provider,
								...(authorization ? {
										clientId: authorization.clientId,
										redirectUri: authorization.redirectUri,
										scope: authorization.scope
								} : {})
						}
				};
		});

		app.post("/account/authentication-methods/link/complete", { bodyLimit: 65536 }, async (request, reply) => {
				const context = await authenticate(request, reply, { mutation: true, stepUp: true });
				if (!context) return reply;
				const body = (request.body ?? {}) as Record<string, unknown>;
				const transactionId = typeof body.transactionId === "string" ? body.transactionId : "";
				const identityToken = typeof body.identityToken === "string" ? body.identityToken : "";
				if (!transactionId || !identityToken) {
						return reply.code(400).send({ error: "invalid_request" });
				}
				// One-time consumption; the transaction must belong to THIS subject and THIS session.
				// A transaction minted under a different (possibly hijacked or stale) session is
				// unusable here even with a valid provider token.
				const transaction = await deps().transactions.consumeById(transactionId);
				if (!transaction || transaction.purpose !== "link"
						|| transaction.identitySubjectId !== context.session.identitySubjectId
						|| transaction.sessionId !== context.session.id) {
						return reply.code(400).send({ error: "invalid_transaction" });
				}
				const verifier = deps().verifiers[transaction.provider];
				if (!verifier) {
						return reply.code(404).send({ error: "linking_disabled" });
				}
				let verified;
				try {
						// Full server-side verification: JWKS signature, exact issuer, registered audience,
						// expiry, and the TRANSACTION's nonce. The response never echoes claim details.
						verified = await verifier.verify(identityToken, { nonce: transaction.nonce });
				} catch {
						return reply.code(400).send({ error: "provider_verification_failed" });
				}
				if (verified.provider !== transaction.provider) {
						return reply.code(400).send({ error: "provider_verification_failed" });
				}
				const result = await deps().federation.linkExternalIdentity({
						identitySubjectId: context.session.identitySubjectId,
						provider: verified.provider,
						providerIssuer: verified.providerIssuer,
						providerSubject: verified.providerSubject,
						providerClientContext: verified.audience,
						evidenceReference: verified.evidenceReference,
						correlationId: randomUUID()
				});
				switch (result.status) {
						case "linked":
						case "already_linked":
								return listResponse(context.session);
						case "conflict":
								// The owning subject is NEVER revealed.
								return reply.code(409).send({ error: result.reason === "subject_provider_already_linked"
										? "provider_already_linked" : "provider_identity_in_use" });
						default:
								return reply.code(403).send({ error: "subject_not_eligible" });
				}
		});

		app.delete("/account/authentication-methods/:externalIdentityId", async (request, reply) => {
				const context = await authenticate(request, reply, { mutation: true, stepUp: true });
				if (!context) return reply;
				const externalIdentityId = (request.params as { externalIdentityId?: string }).externalIdentityId ?? "";
				const identities = await deps().federation.listExternalIdentities(context.session.identitySubjectId);
				const target = identities.find((identity) => identity.id === externalIdentityId && identity.status === "linked");
				const result = await deps().federation.unlinkExternalIdentity({
						identitySubjectId: context.session.identitySubjectId,
						externalIdentityId,
						correlationId: randomUUID()
				});
				if (result.status === "rejected") {
						// not_found also covers another subject's identity id: no existence oracle.
						return result.reason === "last_method"
								? reply.code(409).send({ error: "last_method" })
								: reply.code(404).send({ error: "not_found" });
				}
				// Revoke the sessions (and their cascading refresh-token families) that were
				// established through the just-unlinked provider, except the current session's method
				// cannot be the unlinked provider anyway if it remains usable.
				if (target) {
						const sessions = await deps().sessions.listSessions(context.session.identitySubjectId);
						for (const session of sessions) {
								if (session.status === "active" && session.authenticationMethod === target.provider
										&& session.id !== context.session.id) {
										await deps().sessions.revokeSession(context.session.identitySubjectId, session.id, "method_unlinked");
										await deps().refreshRotation.revokeBySession(session.id, "session_revoked");
								}
						}
				}
				return listResponse(context.session);
		});
}
