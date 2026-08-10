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

		getPrivateIdCredentials(): { clientId?: string; clientSecret?: string } {
				return {
						clientId: configuration.get("PRIVATEID_CLIENT_ID")?.trim() || undefined,
						clientSecret: configuration.get("PRIVATEID_CLIENT_SECRET")?.trim() || undefined
				};
		}

		reload(): void {
				configuration.reload();
		}
}

export const secretProvider = new SecretProvider();