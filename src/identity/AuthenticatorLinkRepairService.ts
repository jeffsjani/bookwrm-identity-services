import { configuration } from "../config/ConfigurationService.js";
import { identityRegistry } from "./IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "./InMemoryUserAuthenticatorRepository.js";
import { UserAuthenticatorRepository } from "./UserAuthenticatorRepository.js";
import type { AuthenticatorProvider } from "../models/UserAuthenticator.js";
import type { IdentityProvider } from "../models/IdentitySubject.js";

export type AuthenticatorLinkRepairResult = {
	repaired: boolean;
	authenticatorFound: boolean;
	previousUserId?: string;
	correctedUserId?: string;
};

type AuthenticatorStore = Pick<UserAuthenticatorRepository, "findByProviderSubject" | "updateUserId">;

function defaultAuthenticators(): AuthenticatorStore {
	return configuration.getIdentityRegistryDriver() === "memory"
		? inMemoryUserAuthenticatorRepository
		: new UserAuthenticatorRepository();
}

// Release C4.9: repairs a UserAuthenticator whose userId still points at a legacy Bookwrm ObjectId
// (pre-C4.2/C4.2B) instead of the identity_subjects.id AuthenticatorLoginResolver expects. Reuses the
// existing IdentityRegistry.resolveOrCreate() service (never mints/duplicates identity logic) to find
// the canonical IdentitySubject for (identityProvider, providerSubject), then re-points the
// authenticator's userId to it. Idempotent: running it again when userId is already correct is a no-op.
export async function repairUserAuthenticatorLink(
	authenticatorProvider: AuthenticatorProvider,
	identityProvider: IdentityProvider,
	providerSubject: string,
	authenticators: AuthenticatorStore = defaultAuthenticators()
): Promise<AuthenticatorLinkRepairResult> {
	const authenticator = await authenticators.findByProviderSubject(authenticatorProvider, providerSubject);
	if (!authenticator) {
		return { repaired: false, authenticatorFound: false };
	}

	const identitySubject = await identityRegistry.resolveOrCreate({ provider: identityProvider, providerSubject });

	if (authenticator.userId === identitySubject.id) {
		return { repaired: false, authenticatorFound: true, previousUserId: authenticator.userId, correctedUserId: identitySubject.id };
	}

	await authenticators.updateUserId(authenticator.id, identitySubject.id);
	return { repaired: true, authenticatorFound: true, previousUserId: authenticator.userId, correctedUserId: identitySubject.id };
}
