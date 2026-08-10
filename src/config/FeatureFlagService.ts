import { configuration } from "./ConfigurationService.js";

export class FeatureFlagService {
		isOidcEnabled(): boolean {
				return configuration.getFeatureFlag("OIDC_ENABLED", true);
		}

		isPrivateIdEnabled(): boolean {
				return configuration.getFeatureFlag("PRIVATEID_ENABLED", false);
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
}

export const featureFlags = new FeatureFlagService();