import { Counter } from "prom-client";

import { getSharedMetricsRegistry } from "../../oidc/infrastructure/OIDCMetrics.js";

const registry = getSharedMetricsRegistry();

const newIdentities = new Counter({
		name: "identity_new_identities_total",
		help: "New IdentitySubject rows minted",
		registers: [registry]
});

const returningLogins = new Counter({
		name: "identity_returning_logins_total",
		help: "Logins that resolved to an existing IdentitySubject",
		registers: [registry]
});

const failedLinking = new Counter({
		name: "identity_failed_linking_total",
		help: "Failed attempts to link/create an IdentitySubject",
		registers: [registry]
});

const emailVerificationFailures = new Counter({
		name: "identity_email_verification_failures_total",
		help: "Rejected identity creation/claim attempts due to unverified email",
		registers: [registry]
});

const claimUpdates = new Counter({
		name: "identity_claim_updates_total",
		help: "Accepted or updated identity claims",
		labelNames: ["claim", "decision"] as const,
		registers: [registry]
});

const authenticatorAdds = new Counter({
		name: "identity_authenticator_adds_total",
		help: "Authenticators linked to an existing IdentitySubject",
		registers: [registry]
});

const authenticatorFailures = new Counter({
		name: "identity_authenticator_failures_total",
		help: "Failed authenticator link/unlink attempts",
		registers: [registry]
});

const oidcLogins = new Counter({
		name: "identity_oidc_logins_total",
		help: "OIDC logins that reached token issuance via Identity Registry",
		registers: [registry]
});

const oidcFailures = new Counter({
		name: "identity_oidc_failures_total",
		help: "OIDC logins that failed identity resolution",
		registers: [registry]
});

// Single counting surface for Task 2; callers increment, nothing here decides business logic.
export const identityMetrics = {
		recordNewIdentity(): void {
				newIdentities.inc();
		},
		recordReturningLogin(): void {
				returningLogins.inc();
		},
		recordFailedLinking(): void {
				failedLinking.inc();
		},
		recordEmailVerificationFailure(): void {
				emailVerificationFailures.inc();
		},
		recordClaimUpdate(claim: string, decision: string): void {
				claimUpdates.inc({ claim, decision });
		},
		recordAuthenticatorAdd(): void {
				authenticatorAdds.inc();
		},
		recordAuthenticatorFailure(): void {
				authenticatorFailures.inc();
		},
		recordOidcLogin(): void {
				oidcLogins.inc();
		},
		recordOidcFailure(): void {
				oidcFailures.inc();
		}
};
