import { configuration } from "./ConfigurationService.js";

// HAPI ID V2-E Stage 0: single authoritative issuer/origin policy for multi-issuer readiness.
// The configured issuer is the authoritative expected value everywhere -- discovery, ID-token
// `iss`, and issuer-bound stored artifacts. Validation is exact-match HTTPS only: no wildcard,
// no suffix matching, fail closed on malformed or conflicting configuration.

export const DEFAULT_OIDC_ISSUER = "https://identity.bookwrm.com";

// Validates that `value` is exactly an https origin (scheme + host [+ explicit non-default
// port]) with no credentials, path, query, fragment, wildcard, or trailing slash.
export function parseExactHttpsOrigin(value: string, label: string): string {
		const trimmed = value.trim();
		if (!trimmed) {
				throw new Error(`${label} must not be empty`);
		}
		if (trimmed.includes("*")) {
				throw new Error(`${label} must not contain wildcards: "${trimmed}"`);
		}

		let url: URL;
		try {
				url = new URL(trimmed);
		} catch {
				throw new Error(`${label} is not a valid URL: "${trimmed}"`);
		}

		if (url.protocol !== "https:") {
				throw new Error(`${label} must use the https scheme: "${trimmed}"`);
		}
		if (url.username || url.password) {
				throw new Error(`${label} must not contain credentials: "${trimmed}"`);
		}
		if (url.origin !== trimmed) {
				throw new Error(
						`${label} must be an exact https origin with no path, query, fragment, or trailing slash: "${trimmed}"`
				);
		}

		return url.origin;
}

// Parses a comma-separated list of exact https origins; fails closed when the list is present
// but empty or when any entry is invalid.
export function parseExactHttpsOriginList(raw: string, label: string): Set<string> {
		const entries = raw.split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
		if (entries.length === 0) {
				throw new Error(`${label} is configured but contains no origins`);
		}

		return new Set(entries.map((entry) => parseExactHttpsOrigin(entry, label)));
}

// Resolves the authoritative issuer for this process: injected issuer (tests) -> OIDC_ISSUER
// env -> DEFAULT_OIDC_ISSUER. The result is always validated, and when OIDC_ALLOWED_ISSUERS is
// configured the resolved issuer must be an exact member of that allowlist (conflicting
// configuration fails closed at resolution time).
export function resolveConfiguredIssuer(injectedIssuer?: string): string {
		const configured = configuration.get("OIDC_ISSUER")?.trim();
		const candidate = injectedIssuer ?? (configured && configured.length > 0 ? configured : DEFAULT_OIDC_ISSUER);
		const issuer = parseExactHttpsOrigin(candidate, "OIDC issuer");

		const allowedRaw = configuration.get("OIDC_ALLOWED_ISSUERS");
		if (allowedRaw !== undefined) {
				const allowed = parseExactHttpsOriginList(allowedRaw, "OIDC_ALLOWED_ISSUERS entry");
				if (!allowed.has(issuer)) {
						throw new Error(`OIDC issuer "${issuer}" is not present in OIDC_ALLOWED_ISSUERS`);
				}
		}

		return issuer;
}

// HAPI ID V2-E Stage 1: deployment-time isolation pin, enforced once at service boot. The
// default Bookwrm issuer keeps its existing optional-allowlist behavior so production is
// unchanged. Any other environment-configured issuer (e.g. the staging service at
// https://id-staging.hapiinc.com) must fail closed at boot unless:
//   1. OIDC_ALLOWED_ISSUERS is explicitly configured and allows ONLY that issuer (a single
//      exact entry -- a looser allowlist that also names another issuer is a misconfiguration);
//   2. CORS_TRUSTED_ORIGINS is explicitly configured (otherwise the service would silently
//      fall back to the production Bookwrm browser-origin allowlist).
// This is boot-time deployment policy only; resolveConfiguredIssuer() semantics (Stage 0) are
// unchanged for library and test use.
export function enforceDeploymentIssuerPin(): string {
		const issuer = resolveConfiguredIssuer();
		if (issuer === DEFAULT_OIDC_ISSUER) {
				return issuer;
		}

		const allowedRaw = configuration.get("OIDC_ALLOWED_ISSUERS");
		if (allowedRaw === undefined) {
				throw new Error(
						`OIDC_ALLOWED_ISSUERS must be configured when OIDC_ISSUER is not the default issuer: set it to exactly "${issuer}"`
				);
		}

		const allowed = parseExactHttpsOriginList(allowedRaw, "OIDC_ALLOWED_ISSUERS entry");
		if (allowed.size !== 1 || !allowed.has(issuer)) {
				throw new Error(
						`OIDC_ALLOWED_ISSUERS must allow only the configured issuer "${issuer}" (found: ${[...allowed].join(", ")})`
				);
		}

		if (configuration.get("CORS_TRUSTED_ORIGINS") === undefined) {
				throw new Error(
						`CORS_TRUSTED_ORIGINS must be explicitly configured when OIDC_ISSUER is not the default issuer (the production Bookwrm default allowlist must never apply to "${issuer}")`
				);
		}

		return issuer;
}

// Issuer binding for stored OAuth artifacts (authorization codes, access tokens, legacy refresh
// tokens). Records minted before Stage 0 carry no issuer and remain honored ONLY by the default
// Bookwrm issuer, preserving production behavior across the deploy; every other issuer requires
// an exact issuer match, so artifacts can never cross issuer environments through a shared store.
export function recordIssuerAccepted(recordIssuer: string | undefined, expectedIssuer: string): boolean {
		if (recordIssuer === undefined) {
				return expectedIssuer === DEFAULT_OIDC_ISSUER;
		}

		return recordIssuer === expectedIssuer;
}
