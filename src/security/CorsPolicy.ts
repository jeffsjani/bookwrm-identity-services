import cors from "@fastify/cors";
import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { parseExactHttpsOriginList } from "../config/IssuerPolicy.js";

// Default allowlist: the existing Bookwrm production browser origins. Used verbatim whenever
// CORS_TRUSTED_ORIGINS is not configured, so existing Bookwrm behavior is preserved by default.
export const PRODUCTION_CORS_ORIGINS = new Set([
	"https://bookwrm.com",
	"https://www.bookwrm.com",
	"https://app.base44.com",
	"https://identity.bookwrm.com"
]);

// HAPI ID V2-E Stage 0: explicit environment-configured trusted origins. Each deployed issuer
// environment (production, staging) supplies its own CORS_TRUSTED_ORIGINS allowlist -- origins
// are matched exactly, wildcards and non-https origins are rejected, and a malformed or empty
// configured list fails closed at registration time. CORS trust is deliberately independent of
// the issuer hostname and of OAuth redirect-URI authorization.
export function resolveTrustedCorsOrigins(): ReadonlySet<string> {
	const raw = configuration.get("CORS_TRUSTED_ORIGINS");
	if (raw === undefined) {
		return PRODUCTION_CORS_ORIGINS;
	}

	return parseExactHttpsOriginList(raw, "CORS_TRUSTED_ORIGINS origin");
}

export async function registerCorsPolicy(app: FastifyInstance): Promise<void> {
	const trustedOrigins = resolveTrustedCorsOrigins();
	await app.register(cors, {
		// Exact origin matching only; credentialed responses are never issued for a wildcard,
		// an unlisted origin, or a request without an Origin header.
		origin: (origin, callback) => {
			callback(null, origin !== undefined && trustedOrigins.has(origin));
		},
		credentials: true
	});
}
