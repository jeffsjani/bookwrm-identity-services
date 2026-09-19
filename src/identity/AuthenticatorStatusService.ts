import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticatorProvider, UserAuthenticatorStatus } from "../models/UserAuthenticator.js";
import { UserAuthenticatorRepository } from "./UserAuthenticatorRepository.js";
import { inMemoryUserAuthenticatorRepository } from "./InMemoryUserAuthenticatorRepository.js";
import { IdentityAccountLinkRepository } from "./IdentityAccountLinkRepository.js";
import { inMemoryIdentityAccountLinkRepository } from "./InMemoryIdentityAccountLinkRepository.js";
import { PostgresIdentityAccountLinkRepository } from "./PostgresIdentityAccountLinkRepository.js";

type AuthenticatorStore = Pick<UserAuthenticatorRepository, "findByUser">;
type AccountLinkStore = Pick<IdentityAccountLinkRepository, "findByExternalUserId">;

function defaultAuthenticatorStore(): AuthenticatorStore {
		return configuration.getIdentityRegistryDriver() === "memory"
				? inMemoryUserAuthenticatorRepository
				: new UserAuthenticatorRepository();
}

function defaultAccountLinkStore(): AccountLinkStore {
		return configuration.getIdentityRegistryDriver() === "memory"
				? inMemoryIdentityAccountLinkRepository
				: new PostgresIdentityAccountLinkRepository();
}

export type AuthenticatorStatusResult = {
		provider: AuthenticatorProvider;
		enrolled: boolean;
		status: UserAuthenticatorStatus | "not_enrolled";
};

// Sole authoritative endpoint boundary for "is this Bookwrm account enrolled with this authenticator
// provider" -- Base44 must never read IdentityAccountLink/IdentitySubject/UserAuthenticator directly.
// Chain: externalUserId -> IdentityAccountLink -> IdentitySubject.id -> UserAuthenticator (Release C5.2).
export class AuthenticatorStatusService {
		constructor(
				private readonly links: AccountLinkStore = defaultAccountLinkStore(),
				private readonly authenticators: AuthenticatorStore = defaultAuthenticatorStore()
		) {}

		async getStatus(externalUserId: string, provider: AuthenticatorProvider): Promise<AuthenticatorStatusResult> {
				const link = await this.links.findByExternalUserId("bookwrm", externalUserId);
				if (!link) {
						return { provider, enrolled: false, status: "not_enrolled" };
				}

				const authenticators = await this.authenticators.findByUser(link.identitySubjectId);
				const authenticator = authenticators.find((candidate) => candidate.provider === provider);
				if (!authenticator) {
						return { provider, enrolled: false, status: "not_enrolled" };
				}

				return {
						provider,
						enrolled: authenticator.status === "active",
						status: authenticator.status
				};
		}
}

export const authenticatorStatusService = new AuthenticatorStatusService();
