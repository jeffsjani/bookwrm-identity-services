import { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityService } from "../identity/IdentityService.js";
import { identityRegistry } from "../identity/IdentityRegistry.js";
import type { IdentityProvider } from "../models/IdentitySubject.js";
import { PrivateIDClient } from "../privateid/PrivateIDClient.js";
import { oidcService } from "../oidc/OIDCService.js";
import { findPrivateIDSession } from "../privateid/PrivateIDSessionStore.js";
import {
		privateIdWebhookDiagnosticsRepository,
		PrivateIdWebhookDiagnosticsConnectionError
} from "../identity/infrastructure/PrivateIdWebhookDiagnosticsRepository.js";

type ResolveBody = {
		privateIdUserId?: string;
};

type ClaimsDiagnosticsBody = {
		subject?: string;
		provider?: IdentityProvider;
		providerSubject?: string;
};

type IdentityRecordBody = {
		oidcSubject?: string;
		provider?: IdentityProvider;
		providerSubject?: string;
		sessionId?: string;
};

type IdentityRecordResponse = {
		identitySubject: {
			oidcSubject: string;
			primaryProvider: IdentityProvider;
			primaryProviderSubject: string;
			email?: string;
			emailVerified?: boolean;
			displayName?: string;
			createdAt: string;
			updatedAt: string;
		};
};

type IdentityRecordErrorResponse = {
		error: string;
		error_description?: string;
		message?: string;
};

type PrivateIdDiagnosticsResponse = {
		configuration: {
				configured: boolean;
				authApiConfigured: boolean;
				baseUrlConfigured: boolean;
				redirectUrlConfigured: boolean;
				callbackUrlConfigured: boolean;
				redirectOriginsConfigured: boolean;
				mockMode: boolean;
		};
		sessionType: "VERIFY";
		requirements: string[];
		privateIdReachable: boolean;
		authenticationSessionCreated: boolean;
		launchUrlReturned: boolean;
		session?: {
				sessionId: string;
				transactionId: string;
				status: string;
				launchUrl: string;
				expires: number;
				created: number;
				completed?: number;
		};
		launchUrl?: string;
		error?: string;
};

async function buildPrivateIdDiagnostics(): Promise<PrivateIdDiagnosticsResponse> {
		const authConfiguration = secretProvider.getPrivateIdAuthConfiguration();
		const authApiConfigured = Boolean(authConfiguration.authApiKey);
		const baseUrlConfigured = Boolean(configuration.get("PRIVATEID_AUTH_BASE_URL")?.trim());
		const redirectUrlConfigured = Boolean(configuration.get("PRIVATEID_REDIRECT_URL")?.trim());
		const callbackUrlConfigured = Boolean(configuration.get("PRIVATEID_CALLBACK_URL")?.trim());
		const redirectOriginsConfigured = Boolean(configuration.get("PRIVATEID_ALLOWED_REDIRECT_ORIGINS")?.trim());
		const mockModeConfigured = Boolean(configuration.get("PRIVATEID_MOCK_MODE")?.trim());
		const mockMode = featureFlags.isPrivateIdMockMode();
		const webhookSharedSecretConfigured = Boolean(authConfiguration.webhookSharedSecret);
		const configured = authApiConfigured
				&& baseUrlConfigured
				&& redirectUrlConfigured
				&& callbackUrlConfigured
				&& redirectOriginsConfigured
				&& webhookSharedSecretConfigured
				&& mockModeConfigured;

		if (!configured) {
				return {
						configuration: {
								configured,
								authApiConfigured,
								baseUrlConfigured,
								redirectUrlConfigured,
								callbackUrlConfigured,
								redirectOriginsConfigured,
								mockMode
						},
						sessionType: "VERIFY",
						requirements: ["face"],
						privateIdReachable: false,
						authenticationSessionCreated: false,
						launchUrlReturned: false,
						error: "PrivateID configuration is incomplete"
				};
		}

		const client = new PrivateIDClient();

		try {
				const session = await client.createAuthenticationSession();
				return {
						configuration: {
								configured,
								authApiConfigured,
								baseUrlConfigured,
								redirectUrlConfigured,
								callbackUrlConfigured,
								redirectOriginsConfigured,
								mockMode
						},
						sessionType: "VERIFY",
						requirements: ["face"],
						privateIdReachable: true,
						authenticationSessionCreated: true,
						launchUrlReturned: Boolean(session.launchUrl),
						session,
						launchUrl: session.launchUrl
				};
		} catch (error) {
				return {
						configuration: {
								configured,
								authApiConfigured,
								baseUrlConfigured,
								redirectUrlConfigured,
								callbackUrlConfigured,
								redirectOriginsConfigured,
								mockMode
						},
						sessionType: "VERIFY",
						requirements: ["face"],
						privateIdReachable: false,
						authenticationSessionCreated: false,
						launchUrlReturned: false,
						error: error instanceof Error ? error.message : "PrivateID diagnostics failed"
				};
		}
}

export async function registerDiagnosticsRoutes(
		app: FastifyInstance
){

		app.get(

				"/diagnostics/identityapi",

				async (_request, reply)=>{
						try {
							const response = await identityService.health();

							return {
								configured: true,
								authenticated: true,
								identityApiReachable: true,
								response
							};
						} catch (error) {
							const statusCode = typeof error === "object"
								&& error !== null
								&& "statusCode" in error
								&& typeof error.statusCode === "number"
								? error.statusCode
								: 503;

							return reply.code(statusCode).send({
								configured: true,
								authenticated: false,
								identityApiReachable: false,
								response: {
									error: error instanceof Error ? error.message : "Base44 identity API unreachable",
									details: typeof error === "object" && error !== null && "details" in error
									? error.details
									: undefined
								}
							});
						}

				}

		);

		// TEMPORARY RELEASE PATCH 8.4 - REMOVE AFTER PRODUCTION CERTIFICATION.
		app.get(
				"/diagnostics/privateid-webhook/:sessionId",
				async (request, reply) => {
						const authorization = request.headers.authorization;
						const providedKey = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
						if (!providedKey || providedKey !== configuration.getIdentityApiKey()) {
								reply.code(401);
								return { error: "unauthorized", error_description: "Valid admin/service API key required" };
						}

						const { sessionId } = request.params as { sessionId?: string };
						const diagnostic = sessionId?.trim() ? await privateIdWebhookDiagnosticsRepository.findActiveBySessionId(sessionId.trim()) : undefined;
						if (!diagnostic) {
							reply.code(404);
							return { error: "not_found", error_description: "No active SUCCESS webhook found for this sessionId" };
						}

						return { rawWebhook: diagnostic.raw_webhook_json };
				}
		);

		// TEMPORARY RELEASE PATCH 8.5 - REMOVE AFTER PRODUCTION CERTIFICATION.
		app.get(
				"/diagnostics/privateid-webhook-recent",
				async (_request, reply) => {
						const authorization = _request.headers.authorization;
						const providedKey = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
						if (!providedKey || providedKey !== configuration.getIdentityApiKey()) {
							reply.code(401);
							return { error: "unauthorized", error_description: "Valid admin/service API key required" };
						}

						try {
							const rows = await privateIdWebhookDiagnosticsRepository.findRecent();
							return { status: "ok", count: rows.length, rows };
						} catch (error) {
							if (error instanceof PrivateIdWebhookDiagnosticsConnectionError) {
								return { status: "connection_error", message: "Unable to query diagnostics database" };
							}

							return { status: "database_error", message: "Query failed" };
						}
				}
		);

		app.get(

				"/diagnostics/base44",

				async ()=>{
						return identityService.health();

				}

		);

		app.get(

				"/diagnostics/context",

				async ()=>{

						return identityService.getIdentityContext();

				}

		);

		app.get(

				"/diagnostics/policies",

				async ()=>{

						return identityService.getPolicies();

				}

		);

		app.get(

				"/diagnostics/security",

				async ()=>{

						return identityService.getSecurityContext();

				}

		);

		app.get(

				"/diagnostics/devices",

				async ()=>{

						return identityService.getTrustedDevices();

				}

		);

		app.get(

				"/diagnostics/notifications",

				async ()=>{

						return identityService.getNotifications();

				}

		);

		app.get(

				"/diagnostics/timeline",

				async ()=>{

						return identityService.getTimeline();

				}

		);

		app.post(

				"/diagnostics/reverify",

				async ()=>{

						return identityService.reverify();

				}

		);

		app.post(

				"/diagnostics/resolve",

				async (request)=>{
						const body = request.body as ResolveBody;
						const privateIdUserId = body?.privateIdUserId;

						return identityService.resolveIdentity(privateIdUserId);

				}

		);

		app.get(

				"/diagnostics/privateid",

				async (_request, reply)=>{
						const diagnostics = await buildPrivateIdDiagnostics();
						if (!diagnostics.configuration.configured || !diagnostics.privateIdReachable || !diagnostics.authenticationSessionCreated || !diagnostics.launchUrlReturned) {
								reply.code(503);
						}

						return diagnostics;

				}

		);

		app.get(

				"/diagnostics/oidc/dashboard",

				async ()=>{
						return oidcService.getDashboardSnapshot();

				}

		);

		// Release Patch 6.2: temporary read-only endpoint to verify what /token and /userinfo would issue
		// for a given oidcSubject, ahead of the production PAT-1 rollout. Remove after verification.
		app.post(

				"/diagnostics/claims",

				async (request, reply) => {
						const authorization = request.headers.authorization;
						const providedKey = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
						if (!providedKey || providedKey !== configuration.getIdentityApiKey()) {
								reply.code(401);
								return { error: "unauthorized", error_description: "Valid admin/service API key required" };
						}

						const body = request.body as ClaimsDiagnosticsBody;
						const subject = body?.subject?.trim();
						let oidcSubject = subject;
						let identitySubject;
						if (!oidcSubject && body?.provider && body?.providerSubject?.trim()) {
							identitySubject = await identityRegistry.findByProvider(body.provider, body.providerSubject.trim());
							if (!identitySubject) {
								reply.code(404);
								return { error: "not_found", error_description: "Identity subject not found" };
							}

							oidcSubject = identitySubject.oidcSubject;
						}

						if (!oidcSubject) {
								reply.code(400);
							return { error: "invalid_request", error_description: "subject or provider and providerSubject are required" };
						}

						identitySubject ??= await identityRegistry.findByOidcSubject(oidcSubject);
						const snapshot = await oidcService.getClaimsSnapshot(oidcSubject);
						return {
							...snapshot,
							identityRegistry: {
								...snapshot.identityRegistry,
								...(identitySubject ? { primaryProviderSubject: identitySubject.primaryProviderSubject } : {})
							}
						};
				}

		);

// Release Patch 6.4.2: temporary endpoint to retrieve the actual IdentitySubject row stored
		// in the Identity Registry for production verification. Supports three lookup methods:
		// 1. By oidcSubject
		// 2. By provider + providerSubject
		// 3. By sessionId (resolves to providerSubject via PrivateIDSessionStore)
		// TEMPORARY RELEASE PATCH 6.4.2 - REMOVE AFTER PRODUCTION CERTIFICATION
		app.post(

				"/diagnostics/identity-record",

			async (request, reply): Promise<IdentityRecordResponse | IdentityRecordErrorResponse> => {
					const authorization = request.headers.authorization;
					const providedKey = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
					if (!providedKey || providedKey !== configuration.getIdentityApiKey()) {
							reply.code(401);
							return { error: "unauthorized", error_description: "Valid admin/service API key required" };
					}

					const body = request.body as IdentityRecordBody;
					let identitySubject = undefined;

					// Method 1: By oidcSubject
					if (body?.oidcSubject?.trim()) {
							identitySubject = await identityRegistry.findByOidcSubject(body.oidcSubject.trim());
							if (!identitySubject) {
									reply.code(404);
									return { error: "not_found", error_description: "Identity subject not found" };
							}
					}
					// Method 2: By provider + providerSubject
					else if (body?.provider && body?.providerSubject?.trim()) {
							identitySubject = await identityRegistry.findByProvider(body.provider, body.providerSubject.trim());
							if (!identitySubject) {
									reply.code(404);
									return { error: "not_found", error_description: "Identity subject not found" };
							}
					}
					// Method 3: By sessionId → providerSubject via PrivateIDSessionStore
					else if (body?.sessionId?.trim()) {
						const sessionId = body.sessionId.trim();
						const sessionRecord = findPrivateIDSession(sessionId);
						if (!sessionRecord) {
								reply.code(404);
								return {
									error: "session_expired",
									message: "The requested PrivateID session is no longer available in memory. Run the diagnostics immediately after a new authentication."
								};
						}
						const result = sessionRecord.result;
						if (!result || !result.privateIdUserId) {
								reply.code(404);
								return { error: "not_found", error_description: "PrivateID session has no authenticated result" };
						}
						identitySubject = await identityRegistry.findByProvider("PrivateID", result.privateIdUserId);
						if (!identitySubject) {
								reply.code(404);
								return { error: "not_found", error_description: "Identity subject not found" };
						}
					}
					else {
							reply.code(400);
							return { error: "invalid_request", error_description: "oidcSubject, provider+providerSubject, or sessionId is required" };
					}

					return {
							identitySubject: {
								oidcSubject: identitySubject.oidcSubject,
								primaryProvider: identitySubject.primaryProvider,
								primaryProviderSubject: identitySubject.primaryProviderSubject,
								email: identitySubject.email,
								emailVerified: identitySubject.emailVerified,
								displayName: identitySubject.displayName,
								createdAt: identitySubject.createdAt,
								updatedAt: identitySubject.updatedAt
							}
						};
				}

		);

		app.get(

				"/diagnostics/routes",

				async ()=>{
						return {
								diagnostics: [
										"/diagnostics/identityapi",
										"/diagnostics/base44",
										"/diagnostics/context",
										"/diagnostics/policies",
										"/diagnostics/security",
										"/diagnostics/devices",
										"/diagnostics/notifications",
										"/diagnostics/timeline",
										"/diagnostics/reverify",
										"/diagnostics/resolve",
										"/diagnostics/privateid",
										"/privateid/webhook",
										"/privateid/callback",
										"/diagnostics/oidc/dashboard",
										"/diagnostics/claims",
										"/diagnostics/identity-record",
										"/diagnostics/privateid-webhook/{sessionId}",
										"/diagnostics/privateid-webhook-recent",
										"/diagnostics/routes"
								],
								oidc: [
										"/.well-known/openid-configuration",
										"/authorize",
										"/jwks",
										"/userinfo",
										"/token"
								],
								privateid: [
										"/privateid/webhook",
										"/privateid/callback"
								]
						};

				}

		);

}
