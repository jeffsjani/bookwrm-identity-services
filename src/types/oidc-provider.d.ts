declare module "oidc-provider" {
		export default class Provider {
				constructor(issuer: string, configuration?: unknown);
				callback(): (req: unknown, res: unknown) => void;
		}
}
