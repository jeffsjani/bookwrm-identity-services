import { configuration } from "../config/ConfigurationService.js";

export type RegisteredOIDCClient = {
		client_id: string;
		client_secret: string;
		redirect_uris: string[];
		scope: string;
		grant_types: string[];
		response_types: string[];
		token_endpoint_auth_method: "client_secret_post" | "client_secret_basic" | "none";
		require_pkce: boolean;
};

const DEFAULT_SCOPES = ["openid", "profile", "email"];
const DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"];

function parseCsv(value: string | undefined, fallback: string[]): string[] {
		if (!value || value.trim().length === 0) {
				return fallback;
		}

		const parsed = value
				.split(",")
				.map((entry) => entry.trim())
				.filter((entry) => entry.length > 0);

		return parsed.length > 0 ? parsed : fallback;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
		if (!value) {
				return fallback;
		}

		const normalized = value.trim().toLowerCase();
		if (normalized === "true") {
				return true;
		}

		if (normalized === "false") {
				return false;
		}

		return fallback;
}

function resolveRedirectUris(): string[] {
		const fromPlural = configuration.get("OIDC_BASE44_REDIRECT_URIS");
		if (fromPlural && fromPlural.trim().length > 0) {
				return parseCsv(fromPlural, []);
		}

		const fromSingle = configuration.get("OIDC_BASE44_REDIRECT_URI")?.trim();
		if (fromSingle && fromSingle.length > 0) {
				return [fromSingle];
		}

		return [];
}

export function registerOIDCClients(): RegisteredOIDCClient[] {
		const clientId = configuration.get("OIDC_BASE44_CLIENT_ID")?.trim();
		const clientSecret = configuration.get("OIDC_BASE44_CLIENT_SECRET")?.trim();

		if (!clientId || !clientSecret) {
				return [];
		}

		const redirectUris = resolveRedirectUris();
		if (redirectUris.length === 0) {
				throw new Error(
						"OIDC client configuration missing: set OIDC_BASE44_REDIRECT_URI or OIDC_BASE44_REDIRECT_URIS"
				);
		}

		const scopes = parseCsv(configuration.get("OIDC_BASE44_SCOPES"), DEFAULT_SCOPES);
		const grantTypes = parseCsv(configuration.get("OIDC_BASE44_GRANT_TYPES"), DEFAULT_GRANT_TYPES);
		const requirePkce = parseBoolean(configuration.get("OIDC_BASE44_PKCE_REQUIRED"), true);
		const tokenAuthMethodRaw = configuration.get("OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD")?.trim();

		const tokenEndpointAuthMethod: RegisteredOIDCClient["token_endpoint_auth_method"] =
				tokenAuthMethodRaw === "none" || tokenAuthMethodRaw === "client_secret_basic"
						? tokenAuthMethodRaw
						: "client_secret_post";

		return [
				{
						client_id: clientId,
						client_secret: clientSecret,
						redirect_uris: redirectUris,
						scope: scopes.join(" "),
						grant_types: grantTypes,
						response_types: ["code"],
						token_endpoint_auth_method: tokenEndpointAuthMethod,
						require_pkce: requirePkce
				}
		];
}
