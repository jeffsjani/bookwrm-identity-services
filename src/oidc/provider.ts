import Provider from "oidc-provider";

import { oidcClaims } from "./claims.js";
import { oidcConfiguration } from "./configuration.js";

export function createOidcProvider(issuer: string): Provider {
		return new Provider(issuer, {
				...oidcConfiguration,
				claims: oidcClaims
		});
}
