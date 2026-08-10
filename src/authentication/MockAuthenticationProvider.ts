import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticationProvider, AuthenticatedUser, AuthenticationStatus } from "./AuthenticationProvider.js";

export class MockAuthenticationProvider implements AuthenticationProvider {
		private activeStatus: AuthenticationStatus = {
				state: "idle"
		};

		async authenticate(): Promise<AuthenticatedUser> {
				this.activeStatus = {
						state: "ready"
				};
				const id = configuration.get("OIDC_TEST_USER_ID")?.trim();
				const email = configuration.get("OIDC_TEST_USER_EMAIL")?.trim();
				const name = configuration.get("OIDC_TEST_USER_NAME")?.trim();

				if (!id || !email || !name) {
						throw new Error(
								"MockAuthenticationProvider configuration missing: set OIDC_TEST_USER_ID, OIDC_TEST_USER_EMAIL, and OIDC_TEST_USER_NAME."
						);
				}

				return {
						id,
						sub: id,
						email,
						name
				};
		}

		async cancel(): Promise<void> {
				this.activeStatus = {
						state: "cancelled"
				};
		}

		async status(): Promise<AuthenticationStatus> {
				return this.activeStatus;
		}

		async logout(): Promise<void> {
				this.activeStatus = {
						state: "idle"
				};
		}
}
