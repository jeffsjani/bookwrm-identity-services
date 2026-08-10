import type { FastifyInstance } from "fastify";
import type Provider from "oidc-provider";

export type OidcRouteOptions = {
		mountPath?: string;
};

export function resolveOidcMountPath(options?: OidcRouteOptions): string {
		return options?.mountPath ?? "/oidc";
}

export async function registerOidcRoutes(
		app: FastifyInstance,
		provider: Provider,
		options?: OidcRouteOptions
): Promise<void> {
		const mountPath = resolveOidcMountPath(options);

		app.all(`${mountPath}/*`, async (request, reply) => {
				provider.callback()(request.raw, reply.raw);
				reply.hijack();
		});
}
