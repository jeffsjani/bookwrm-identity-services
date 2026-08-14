import { IdentityService } from "../identity/IdentityService.js";
import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";

export type OIDCClaimsProfile = {
		sub: string;
		email: string;
		emailVerified: boolean;
		name: string;
};

export class ClaimsService {
		constructor(private readonly identityService: IdentityService = new IdentityService()) {}

		async toOIDCClaims(user: AuthenticatedUser): Promise<OIDCClaimsProfile> {
				let subject = user.sub;

				try {
						const context = await this.identityService.getIdentityContext(user.id);
						if (context?.data?.userId && context.data.userId.trim().length > 0) {
								subject = context.data.userId;
						}
				} catch {
						// Keep OIDC auth flow available in development even if identity context is unavailable.
				}

				return {
						sub: subject,
						email: user.email,
						emailVerified: user.emailVerified,
						name: user.name
				};
		}
}
