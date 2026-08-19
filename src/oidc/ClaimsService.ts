import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";

export type OIDCClaimsProfile = {
		sub: string;
		email: string;
		emailVerified: boolean;
		name: string;
};

// Claims originate exclusively from AuthenticatedUser (itself sourced from IdentitySubject); no Bookwrm/Base44 lookups.
export class ClaimsService {
		async toOIDCClaims(user: AuthenticatedUser): Promise<OIDCClaimsProfile> {
				return {
						sub: user.sub,
						email: user.email,
						emailVerified: user.emailVerified,
						name: user.name
				};
		}
}
