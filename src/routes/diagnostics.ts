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
				privateIdEnabled: boolean;
				launchUrlConfigured: boolean;
				credentialsConfigured: boolean;
				configured: boolean;
		};
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
		const privateIdEnabled = featureFlags.isPrivateIdEnabled();
		const launchUrlConfigured = Boolean(configuration.get("PRIVATEID_LAUNCH_URL"));
		const credentials = secretProvider.getPrivateIdCredentials();
		const credentialsConfigured = Boolean(credentials.clientId && credentials.clientSecret);
		const configured = privateIdEnabled && launchUrlConfigured && credentialsConfigured;

		if (!configured) {
				return {
						configuration: {
								privateIdEnabled,
								launchUrlConfigured,
								credentialsConfigured,
								configured
						},
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
								privateIdEnabled,
								launchUrlConfigured,
								credentialsConfigured,
								configured
						},
						privateIdReachable: true,
						authenticationSessionCreated: true,
						launchUrlReturned: Boolean(session.launchUrl),
						session,
						launchUrl: session.launchUrl
				};
		} catch (error) {
				return {
						configuration: {
								privateIdEnabled,
								launchUrlConfigured,
								credentialsConfigured,
								configured
						},
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