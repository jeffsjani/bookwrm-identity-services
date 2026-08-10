declare module "redlock" {
		export default class Redlock {
				constructor(clients: unknown[], options?: unknown);
				acquire(resources: string[], duration: number): Promise<{
						release(): Promise<void>;
				}>;
		}
}
