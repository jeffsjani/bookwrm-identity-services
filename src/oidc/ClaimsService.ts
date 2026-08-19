import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";

export type OIDCClaimsProfile = {
		sub: string;
		email?: string;
		emailVerified?: boolean;
		name?: string;
};

// Claims originate exclusively from AuthenticatedUser (itself sourced from IdentitySubject); no Bookwrm/Base44 lookups.
export class ClaimsService {
		async toOIDCClaims(user: AuthenticatedUser): Promise<OIDCClaimsProfile> {
				return {
					sub: user.sub,
					...(user.email !== undefined ? { email: user.email } : {}),
					...(user.emailVerified !== undefined ? { emailVerified: user.emailVerified } : {}),
					...(user.name !== undefined ? { name: user.name } : {})
				};
		}
}
