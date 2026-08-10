import { configuration } from "./ConfigurationService.js";

export class SecretProvider {
		getJwtPrivateKeys(): string[] {
				return configuration.getOIDCKeyConfiguration().privateKey;
		}

		getJwtPublicKeys(): string[] {
				return configuration.getOIDCKeyConfiguration().publicKey;
		}

		getOidcJwksJson(): string | undefined {
				return configuration.getOIDCKeyConfiguration().jwksJson;
		}

		getBase44ApiKey(): string {
				return configuration.getIdentityApiKey();
		}

		getPrivateIdAuthConfiguration(): {
				authApiKey?: string;
				webhookSharedSecret?: string;
				clientId?: string;
				clientSecret?: string;
		} {
				return {
						authApiKey: configuration.get("PRIVATEID_AUTH_API_KEY")?.trim() || undefined,
						webhookSharedSecret: configuration.get("PRIVATEID_WEBHOOK_SHARED_SECRET")?.trim() || undefined,
						clientId: configuration.get("PRIVATEID_AUTH_CLIENT_ID")?.trim() || undefined,
						clientSecret: configuration.get("PRIVATEID_AUTH_CLIENT_SECRET")?.trim() || undefined
				};
		}

		reload(): void {
				configuration.reload();
		}
}

export const secretProvider = new SecretProvider();