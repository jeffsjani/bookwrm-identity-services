import { randomUUID } from "node:crypto";

import { configuration } from "../../config/ConfigurationService.js";
import type { IdentitySubject } from "../../models/IdentitySubject.js";
import type { ExternalIdentity, ExternalIdentityProvider } from "../../models/ExternalIdentity.js";
import { IdentityFederationService, identityFederationService } from "../IdentityFederationService.js";
import { IdentityRegistry, identityRegistry } from "../IdentityRegistry.js";
import { PostgresExternalIdentityRepository } from "../PostgresExternalIdentityRepository.js";
import { PostgresIdentitySubjectRepository } from "../PostgresIdentitySubjectRepository.js";
import { withPostgresTransaction, type PostgresClient } from "../infrastructure/PostgresInfrastructure.js";
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

type RegistrationServices = {
		registry: IdentityRegistry;
		federation: IdentityFederationService;
		atomic: boolean;
};
type RegistrationTransaction = <T>(operation: (services: RegistrationServices) => Promise<T>) => Promise<T>;

class RegistrationConflict extends Error {}

function isProviderBindingConflict(error: unknown): boolean {
		if (!error || typeof error !== "object") return false;
		const postgresError = error as { code?: string; constraint?: string };
		return postgresError.code === "23505" && [
				"external_identities_provider_identity_active_key",
				"external_identities_subject_provider_active_key"
		].includes(postgresError.constraint ?? "");
}

// HAPI ID V2-D: the ONLY bridge from a server-verified provider identity to a HAPI identity.
// Both Apple and Google resolve through identity_subjects + external_identities exclusively; the
// verified email NEVER participates in any lookup here -- matching emails cannot log a user into,
// merge, or link an account.
export class FederatedIdentityResolutionService {
		private readonly registrationTransaction: RegistrationTransaction;

		constructor(
				private readonly federation: IdentityFederationService = identityFederationService,
				private readonly registry: IdentityRegistry = identityRegistry,
				private readonly now: () => Date = () => new Date(),
				registrationTransaction?: RegistrationTransaction
		) {
				this.registrationTransaction = registrationTransaction ?? (async (operation) => {
						if (configuration.getIdentityRegistryDriver() !== "postgres") {
								return operation({ registry: this.registry, federation: this.federation, atomic: false });
						}
						return withPostgresTransaction((client) => operation({ ...this.transactionServices(client), atomic: true }));
				});
		}

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

		linkExisting(identitySubjectId: string, verified: VerifiedFederatedIdentity) {
				return this.federation.linkExternalIdentity({
						identitySubjectId,
						provider: verified.provider,
						providerIssuer: verified.providerIssuer,
						providerSubject: verified.providerSubject,
						providerClientContext: verified.audience,
						evidenceReference: verified.evidenceReference
				});
		}

		// Safe first-time registration: mints a brand-new HAPI subject for an unknown provider
		// identity and links it explicitly. In PostgreSQL, both writes and the link audit share
		// one transaction. Never attaches to any existing subject based on email.
		async registerFirstTime(verified: VerifiedFederatedIdentity, correlationId?: string): Promise<FederatedRegistrationResult> {
				try {
						const result = await this.registrationTransaction(async ({ registry, federation, atomic }) => {
								const { subject, created } = await registry.resolveOrCreateWithStatus({
										provider: REGISTRY_PROVIDER[verified.provider],
										providerSubject: verified.providerSubject,
										// Contact/display hint only (Google: verified-only; Apple: possibly a private relay
										// alias). Recorded for communication, never consulted for identity resolution.
										...(verified.email !== undefined ? { email: verified.email } : {}),
										...(verified.emailVerified !== undefined ? { emailVerified: verified.emailVerified } : {})
								}, { deferCreationSideEffects: true });

								try {
										const linked = await federation.linkExternalIdentity({
												identitySubjectId: subject.id,
												provider: verified.provider,
												providerIssuer: verified.providerIssuer,
												providerSubject: verified.providerSubject,
												providerClientContext: verified.audience,
												evidenceReference: verified.evidenceReference,
												correlationId: correlationId ?? randomUUID()
										});

										if (linked.status !== "linked" && linked.status !== "already_linked") {
												throw new RegistrationConflict();
										}
										return { status: "registered" as const, subject, externalIdentity: linked.externalIdentity, created };
								} catch (error) {
										if (!atomic && created) {
												await registry.delete(subject.oidcSubject);
										}
										throw error;
								}
						});
						if (result.created) {
								this.registry.recordCreatedIdentity(result.subject);
						}
						return { status: result.status, subject: result.subject, externalIdentity: result.externalIdentity };
				} catch (error) {
						if (error instanceof RegistrationConflict || isProviderBindingConflict(error)) {
								return { status: "conflict" };
						}
						throw error;
				}
		}

		private transactionServices(client: PostgresClient): RegistrationServices {
				return {
						registry: new IdentityRegistry(new PostgresIdentitySubjectRepository(client)),
						federation: new IdentityFederationService(new PostgresExternalIdentityRepository(undefined, client)),
						atomic: true
				};
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
