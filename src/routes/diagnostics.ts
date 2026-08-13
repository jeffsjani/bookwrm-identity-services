import { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { featureFlags } from "../config/FeatureFlagService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityService } from "../identity/IdentityService.js";
import { PrivateIDClient } from "../privateid/PrivateIDClient.js";
import { oidcService } from "../oidc/OIDCService.js";

type ResolveBody = {
		privateIdUserId?: string;
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
						const baseUrl = configuration.getBase44BaseUrl();
						const identityApiPath = configuration.getIdentityApiPath();
						const identityApiKey = configuration.getIdentityApiKey();
						const requestBody = JSON.stringify({
							version: "v1",
							action: "health"
						});

						try {
							const response = await fetch(`${baseUrl}${identityApiPath}`, {
								method: "POST",
								headers: {
									"Content-Type": "application/json",
									Authorization: `Bearer ${identityApiKey}`
								},
								body: requestBody
							});

							const responseBody = await response.text();

							if (!response.ok) {
								reply.code(response.status);
								const contentType = response.headers.get("content-type") ?? "application/json";
								reply.header("content-type", contentType);
								return responseBody;
							}

							let parsedBody: unknown = {};
							if (responseBody.trim().length > 0) {
								try {
									parsedBody = JSON.parse(responseBody) as unknown;
								} catch {
									parsedBody = responseBody;
								}
							}

							return {
								configured: true,
								authenticated: true,
								identityApiReachable: true,
								response: parsedBody
							};
						} catch (error) {
							return reply.code(503).send({
								configured: true,
								authenticated: false,
								identityApiReachable: false,
								response: {
									error: error instanceof Error ? error.message : "Base44 identity API unreachable"
								}
							});
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

				"/diagnostics/oidc",

				async ()=>{
						return {
								discovery: true,
								jwks: true,
								authorize: true,
								token: true,
								userinfo: true,
								pkce: true
						};

				}

		);

		app.get(

				"/diagnostics/oidc/dashboard",

				async ()=>{
						return oidcService.getDashboardSnapshot();

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
										"/diagnostics/oidc",
										"/diagnostics/oidc/dashboard",
										"/diagnostics/oidc/base44",
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

		app.get(

				"/diagnostics/oidc/base44",

				async ()=>{
						return oidcService.getBase44IntegrationStatus();

				}

		);

}