import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import { identityMetrics } from "./infrastructure/IdentityMetrics.js";
import { recordIdentityAudit } from "./IdentityAudit.js";
import type { IdentityProvider, IdentitySubject } from "../models/IdentitySubject.js";
import { inMemoryIdentitySubjectRepository } from "./InMemoryIdentitySubjectRepository.js";
import { PostgresIdentitySubjectRepository } from "./PostgresIdentitySubjectRepository.js";
import type { IdentitySubjectRepository, UpdateIdentitySubjectInput } from "./IdentitySubjectRepository.js";
import { BOOKWRM_APPLICATION_ID } from "./WellKnownIdentities.js";

export type IdentityLinkRequest = {
		provider: IdentityProvider;
		providerSubject: string;
		email?: string;
		emailVerified?: boolean;
		displayName?: string;
		// HAPI ID H1: defaults to Bookwrm's Application so existing callers are unaffected.
		applicationId?: string;
};

export type IdentityResolveOptions = {
		deferCreationSideEffects?: boolean;
};

function defaultRepository(): IdentitySubjectRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
					? inMemoryIdentitySubjectRepository
				: new PostgresIdentitySubjectRepository();
}

// IdentitySubject is the only component permitted to mint an OIDC Subject.
// All storage goes through IdentitySubjectRepository; this class never touches the database directly (Task 8).
export class IdentityRegistry {
		constructor(private readonly repository: IdentitySubjectRepository = defaultRepository()) {}

		findByProvider(provider: IdentityProvider, providerSubject: string): Promise<IdentitySubject | undefined> {
				return this.repository.findByProviderSubject(provider, providerSubject);
		}

		findById(id: string): Promise<IdentitySubject | undefined> {
			return this.repository.findById(id);
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
		async resolveOrCreate(request: IdentityLinkRequest, options: IdentityResolveOptions = {}): Promise<IdentitySubject> {
				return (await this.resolveOrCreateWithStatus(request, options)).subject;
		}

		async resolveOrCreateWithStatus(
				request: IdentityLinkRequest,
				options: IdentityResolveOptions = {}
		): Promise<{ subject: IdentitySubject; created: boolean }> {
				try {
						const input = {
								id: randomUUID(),
								oidcSubject: randomUUID(),
								applicationId: request.applicationId ?? BOOKWRM_APPLICATION_ID,
								primaryProvider: request.provider,
								primaryProviderSubject: request.providerSubject,
								email: request.email,
								emailVerified: request.emailVerified,
								displayName: request.displayName,
								status: "ACTIVE" as const
						};
						let result: { subject: IdentitySubject; created: boolean };
						if (this.repository.resolveOrCreateWithStatus) {
								result = await this.repository.resolveOrCreateWithStatus(input);
						} else {
								const existing = await this.repository.findByProviderSubject(request.provider, request.providerSubject);
								result = {
										subject: await this.repository.resolveOrCreate(input),
										created: !existing
								};
						}

						if (!result.created) {
								identityMetrics.recordReturningLogin();
						} else if (!options.deferCreationSideEffects) {
								this.recordCreatedIdentity(result.subject);
						}

						return result;
				} catch (error) {
						identityMetrics.recordFailedLinking();
						throw error;
				}
		}

		recordCreatedIdentity(subject: IdentitySubject): void {
				identityMetrics.recordNewIdentity();
				recordIdentityAudit(subject.oidcSubject, "IDENTITY_CREATED", {
						provider: subject.primaryProvider,
						providerSubject: subject.primaryProviderSubject
				});
				recordIdentityAudit(subject.oidcSubject, "AUTHENTICATOR_LINKED", {
						provider: subject.primaryProvider,
						providerSubject: subject.primaryProviderSubject
				});
		}

		delete(oidcSubject: string): Promise<boolean> {
				return this.repository.delete(oidcSubject);
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
