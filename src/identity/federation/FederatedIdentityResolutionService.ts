import { randomUUID } from "node:crypto";

import type { IdentitySubject } from "../../models/IdentitySubject.js";
import type { ExternalIdentity, ExternalIdentityProvider } from "../../models/ExternalIdentity.js";
import { identityFederationService, type IdentityFederationService } from "../IdentityFederationService.js";
import { identityRegistry, type IdentityRegistry } from "../IdentityRegistry.js";
import type { VerifiedFederatedIdentity } from "./FederatedIdentityTypes.js";

// Maps the federation provider discriminator onto the Identity Registry's provider union for
// first-time subject creation. identity_subjects remains the single authoritative registry.
const REGISTRY_PROVIDER: Record<ExternalIdentityProvider, "Apple" | "Google"> = {
		APPLE: "Apple",
		GOOGLE: "Google"
};

export type FederatedLoginResolution =
		// The exact (provider, issuer, subject) triple is actively linked to a live HAPI subject.
		| { status: "linked"; subject: IdentitySubject; externalIdentity: ExternalIdentity }
		// The provider identity is unknown: the caller must offer explicit account creation or
		// explicit linking -- NEVER an automatic email-based match.
		| { status: "unlinked" }
		// The link exists but its HAPI subject is missing, locked, or disabled: fail closed.
		| { status: "subject_inactive" };

export type FederatedRegistrationResult =
		| { status: "registered"; subject: IdentitySubject; externalIdentity: ExternalIdentity }
		// Lost a race: the provider identity became linked elsewhere between resolution and
		// registration. The database uniqueness constraint is the final arbiter.
		| { status: "conflict" };

// HAPI ID V2-D: the ONLY bridge from a server-verified provider identity to a HAPI identity.
// Both Apple and Google resolve through identity_subjects + external_identities exclusively; the
// verified email NEVER participates in any lookup here -- matching emails cannot log a user into,
// merge, or link an account.
export class FederatedIdentityResolutionService {
		constructor(
				private readonly federation: IdentityFederationService = identityFederationService,
				private readonly registry: IdentityRegistry = identityRegistry,
				private readonly now: () => Date = () => new Date()
		) {}

		// Returning-user resolution for HAPI-hosted sign-in with a provider.
		async resolveForLogin(verified: VerifiedFederatedIdentity): Promise<FederatedLoginResolution> {
				const externalIdentity = await this.federation.findActiveByProviderIdentity(
						verified.provider, verified.providerIssuer, verified.providerSubject);
				if (!externalIdentity) {
						return { status: "unlinked" };
				}
				const subject = await this.registry.findById(externalIdentity.identitySubjectId);
				if (!subject || subject.status !== "ACTIVE") {
						return { status: "subject_inactive" };
				}
				await this.federation.markAuthenticated(externalIdentity.id, this.now().toISOString());
				return { status: "linked", subject, externalIdentity };
		}

		// Safe first-time registration: mints a brand-new HAPI subject for an unknown provider
		// identity and links it explicitly. Never attaches to any existing subject -- explicit
		// linking of existing accounts happens only through the authenticated account-linking API.
		async registerFirstTime(verified: VerifiedFederatedIdentity, correlationId?: string): Promise<FederatedRegistrationResult> {
				const subject = await this.registry.resolveOrCreate({
						provider: REGISTRY_PROVIDER[verified.provider],
						providerSubject: verified.providerSubject,
						// Contact/display hint only (Google: verified-only; Apple: possibly a private relay
						// alias). Recorded for communication, never consulted for identity resolution.
						...(verified.email !== undefined ? { email: verified.email } : {}),
						...(verified.emailVerified !== undefined ? { emailVerified: verified.emailVerified } : {})
				});

				const linked = await this.federation.linkExternalIdentity({
						identitySubjectId: subject.id,
						provider: verified.provider,
						providerIssuer: verified.providerIssuer,
						providerSubject: verified.providerSubject,
						providerClientContext: verified.audience,
						evidenceReference: verified.evidenceReference,
						correlationId: correlationId ?? randomUUID()
				});

				switch (linked.status) {
						case "linked":
						case "already_linked":
								return { status: "registered", subject, externalIdentity: linked.externalIdentity };
						default:
								// conflict/rejected: fail closed. The freshly minted (or re-resolved) subject is
								// left untouched; no identity was ever usable without a committed link.
								return { status: "conflict" };
				}
		}

		// Shared post-verification eligibility check for authorization-code redemption: the provider
		// link must STILL be active at /token time, so provider-side revocation or an unlink between
		// code issuance and redemption fails the exchange.
		async isSubjectLinkActive(identitySubjectId: string, provider: ExternalIdentityProvider): Promise<boolean> {
				const identities = await this.federation.listExternalIdentities(identitySubjectId);
				return identities.some((identity) => identity.provider === provider && identity.status === "linked");
		}
}

export const federatedIdentityResolutionService = new FederatedIdentityResolutionService();
