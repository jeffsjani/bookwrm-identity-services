import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import { identityMetrics } from "./infrastructure/IdentityMetrics.js";
import { recordIdentityAudit } from "./IdentityAudit.js";
import type { IdentityProvider, IdentitySubject } from "../models/IdentitySubject.js";
import { InMemoryIdentitySubjectRepository } from "./InMemoryIdentitySubjectRepository.js";
import { PostgresIdentitySubjectRepository } from "./PostgresIdentitySubjectRepository.js";
import type { IdentitySubjectRepository, UpdateIdentitySubjectInput } from "./IdentitySubjectRepository.js";

export type IdentityLinkRequest = {
		provider: IdentityProvider;
		providerSubject: string;
		email: string;
		emailVerified: boolean;
		displayName: string;
};

function defaultRepository(): IdentitySubjectRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? new InMemoryIdentitySubjectRepository()
				: new PostgresIdentitySubjectRepository();
}

// IdentitySubject is the only component permitted to mint an OIDC Subject.
// All storage goes through IdentitySubjectRepository; this class never touches the database directly (Task 8).
export class IdentityRegistry {
		constructor(private readonly repository: IdentitySubjectRepository = defaultRepository()) {}

		findByProvider(provider: IdentityProvider, providerSubject: string): Promise<IdentitySubject | undefined> {
				return this.repository.findByProviderSubject(provider, providerSubject);
		}

		findByOidcSubject(oidcSubject: string): Promise<IdentitySubject | undefined> {
				return this.repository.findByOidcSubject(oidcSubject);
		}

		// Read-only listing/search for the Identity Administration API (Phase 4).
		listSubjects(): Promise<IdentitySubject[]> {
				return this.repository.list();
		}

		findByEmail(email: string): Promise<IdentitySubject[]> {
				return this.repository.findByEmail(email);
		}

		// Reuses the existing subject for a known provider identity, or mints a new one on first authentication.
		// Atomicity under concurrent calls is guaranteed by the repository (database uniqueness), not by this method.
		async resolveOrCreate(request: IdentityLinkRequest): Promise<IdentitySubject> {
				if (!request.emailVerified) {
						identityMetrics.recordEmailVerificationFailure();
						identityMetrics.recordFailedLinking();
						throw new Error("IdentitySubject cannot be created without verified email");
				}

				try {
						const existing = await this.repository.findByProviderSubject(request.provider, request.providerSubject);
						const subject = await this.repository.resolveOrCreate({
								id: randomUUID(),
								oidcSubject: randomUUID(),
								primaryProvider: request.provider,
								primaryProviderSubject: request.providerSubject,
								email: request.email,
								emailVerified: request.emailVerified,
								displayName: request.displayName,
								status: "ACTIVE"
						});

						if (existing) {
								identityMetrics.recordReturningLogin();
						} else {
								identityMetrics.recordNewIdentity();							recordIdentityAudit(subject.oidcSubject, "IDENTITY_CREATED", {
									provider: request.provider,
									providerSubject: request.providerSubject
							});
							recordIdentityAudit(subject.oidcSubject, "AUTHENTICATOR_LINKED", {
									provider: request.provider,
									providerSubject: request.providerSubject
							});						}

						return subject;
				} catch (error) {
						identityMetrics.recordFailedLinking();
						throw error;
				}
		}

		touchAuthentication(oidcSubject: string): Promise<IdentitySubject | undefined> {
				return this.repository.touchLastAuthentication(oidcSubject);
		}

		// Only entry point for persisting a claim decision made by IdentityClaimResolver/IdentityClaimPolicy.
		applyClaimUpdate(oidcSubject: string, changes: UpdateIdentitySubjectInput): Promise<IdentitySubject | undefined> {
				return this.repository.update(oidcSubject, changes);
		}

		// Only entry point used by IdentityRecoveryService to re-point the primary authenticator identifier.
		relinkAuthenticator(oidcSubject: string, newProviderSubject: string): Promise<IdentitySubject | undefined> {
				return this.repository.relinkPrimaryProviderSubject(oidcSubject, newProviderSubject);
		}
}

export const identityRegistry = new IdentityRegistry();
