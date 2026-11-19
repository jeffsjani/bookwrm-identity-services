import { configuration } from "./ConfigurationService.js";

export class FeatureFlagService {
		isOidcEnabled(): boolean {
				return configuration.getFeatureFlag("OIDC_ENABLED", true);
		}

		isPrivateIdMockMode(): boolean {
				return configuration.getFeatureFlag("PRIVATEID_MOCK_MODE", false);
		}

		isMockAuthEnabled(): boolean {
				return configuration.getFeatureFlag("MOCK_AUTH_ENABLED", true);
		}

		isRedisEnabled(): boolean {
				return configuration.getFeatureFlag("REDIS_ENABLED", true);
		}

		isCacheEnabled(): boolean {
				return configuration.getFeatureFlag("CACHE_ENABLED", true);
		}

		isMetricsEnabled(): boolean {
				return configuration.getFeatureFlag("METRICS_ENABLED", true);
		}

		// HAPI ID V2-C: persistent server-side HAPI sessions. Default OFF -- existing Bookwrm
		// authentication behavior is unchanged until this is explicitly enabled.
		isPersistentSessionsEnabled(): boolean {
				return configuration.getFeatureFlag("HAPI_PERSISTENT_SESSIONS_ENABLED", false);
		}

		// HAPI ID V2-C: rotating refresh-token families + grant_type=refresh_token. Default OFF --
		// the refresh grant is never active in production without an explicit opt-in.
		isRefreshGrantEnabled(): boolean {
				return configuration.getFeatureFlag("HAPI_REFRESH_GRANT_ENABLED", false);
		}

		// HAPI ID V2-D: HAPI-hosted "Continue with Apple" upstream federation. Default OFF -- no
		// Apple authorization is ever launched in production without an explicit opt-in.
		isAppleFederationEnabled(): boolean {
				return configuration.getFeatureFlag("HAPI_APPLE_FEDERATION_ENABLED", false);
		}

		// HAPI ID V2-D: HAPI-hosted "Continue with Google" upstream federation. Default OFF.
		isGoogleFederationEnabled(): boolean {
				return configuration.getFeatureFlag("HAPI_GOOGLE_FEDERATION_ENABLED", false);
		}

		// HAPI ID V2-D: authenticated account-linking API (V2-C Phase 4 design). Default OFF.
		isAccountLinkingApiEnabled(): boolean {
				return configuration.getFeatureFlag("HAPI_ACCOUNT_LINKING_API_ENABLED", false);
		}
}

export const featureFlags = new FeatureFlagService();