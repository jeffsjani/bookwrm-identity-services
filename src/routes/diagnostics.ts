import { FastifyInstance } from "fastify";

import { identityService } from "../identity/IdentityService.js";
import { oidcService } from "../oidc/OIDCService.js";

type ResolveBody = {
		privateIdUserId?: string;
};

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