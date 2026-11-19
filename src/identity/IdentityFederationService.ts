import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import type {
		ExternalIdentity,
		ExternalIdentityProvider,
		IdentityAuthenticationMethod,
		IdentityLinkAuditEntry
} from "../models/ExternalIdentity.js";
import type { ExternalIdentityRepository } from "./ExternalIdentityRepository.js";
import { InMemoryExternalIdentityRepository } from "./InMemoryExternalIdentityRepository.js";
import { PostgresExternalIdentityRepository } from "./PostgresExternalIdentityRepository.js";
import { identityRegistry } from "./IdentityRegistry.js";

const KNOWN_PROVIDERS: readonly ExternalIdentityProvider[] = ["APPLE", "GOOGLE"];

export class IdentityFederationError extends Error {
		constructor(message: string, readonly statusCode = 400) {
				super(message);
				this.name = "IdentityFederationError";
		}
}

export type LinkRequest = {
		// The authenticated HAPI subject initiating the link -- always an identity_subjects.id,
		// never derived from an email address or a provider claim.
		identitySubjectId: string;
		provider: ExternalIdentityProvider;
		providerIssuer: string;
		providerSubject: string;
		providerClientContext?: string;
		evidenceReference?: string;
		correlationId?: string;
};

export type ConflictCheck =
		| { state: "unlinked" }
		| { state: "linked_to_subject"; externalIdentity: ExternalIdentity }
		| { state: "linked_to_other_subject" };

// HAPI ID V2-B linking policy layer. Deliberately NOT wired to any HTTP route and NOT capable of
// authenticating with Apple or Google -- callers must supply already-validated provider identities
// (issuer + subject). Email addresses play no role anywhere in this service: matching emails never
// link, merge, or resolve accounts.
export class IdentityFederationService {
		constructor(private readonly repository: ExternalIdentityRepository = defaultRepository()) {}

		async linkExternalIdentity(request: LinkRequest) {
				this.assertProvider(request.provider);
				this.assertNonEmpty(request.providerIssuer, "providerIssuer");
				this.assertNonEmpty(request.providerSubject, "providerSubject");
				this.assertNonEmpty(request.identitySubjectId, "identitySubjectId");

				return this.repository.link({
						externalIdentityId: randomUUID(),
						methodId: randomUUID(),
						identitySubjectId: request.identitySubjectId,
						provider: request.provider,
						providerIssuer: request.providerIssuer.trim(),
						providerSubject: request.providerSubject.trim(),
						...(request.providerClientContext !== undefined
								? { providerClientContext: request.providerClientContext } : {}),
						...(request.evidenceReference !== undefined
								? { evidenceReference: request.evidenceReference } : {}),
						correlationId: request.correlationId ?? randomUUID()
				});
		}

		// Classifies the exact provider identity relative to a subject without mutating anything.
		async detectConflict(
				identitySubjectId: string,
				provider: ExternalIdentityProvider,
				providerIssuer: string,
				providerSubject: string
		): Promise<ConflictCheck> {
				this.assertProvider(provider);
				const existing = await this.repository.findActiveByProviderIdentity(
						provider, providerIssuer.trim(), providerSubject.trim());
				if (!existing) {
						return { state: "unlinked" };
				}
				return existing.identitySubjectId === identitySubjectId
						? { state: "linked_to_subject", externalIdentity: existing }
						// The owning subject is deliberately not revealed to the caller.
						: { state: "linked_to_other_subject" };
		}

		async unlinkExternalIdentity(request: {
				identitySubjectId: string;
				externalIdentityId: string;
				evidenceReference?: string;
				correlationId?: string;
		}) {
				this.assertNonEmpty(request.identitySubjectId, "identitySubjectId");
				this.assertNonEmpty(request.externalIdentityId, "externalIdentityId");
				return this.repository.unlink({
						identitySubjectId: request.identitySubjectId,
						externalIdentityId: request.externalIdentityId,
						...(request.evidenceReference !== undefined
								? { evidenceReference: request.evidenceReference } : {}),
						correlationId: request.correlationId ?? randomUUID()
				});
		}

		listExternalIdentities(identitySubjectId: string): Promise<ExternalIdentity[]> {
				return this.repository.listBySubject(identitySubjectId);
		}

		listAuthenticationMethods(identitySubjectId: string): Promise<IdentityAuthenticationMethod[]> {
				return this.repository.listAuthenticationMethods(identitySubjectId);
		}

		listLinkAudit(identitySubjectId: string): Promise<IdentityLinkAuditEntry[]> {
				return this.repository.listAudit(identitySubjectId);
		}

		private assertProvider(provider: string): void {
				if (!KNOWN_PROVIDERS.includes(provider as ExternalIdentityProvider)) {
						throw new IdentityFederationError(`Unsupported external identity provider: ${provider}`);
				}
		}

		private assertNonEmpty(value: string, field: string): void {
				if (typeof value !== "string" || value.trim().length === 0) {
						throw new IdentityFederationError(`${field} is required`);
				}
		}
}

function defaultRepository(): ExternalIdentityRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? new InMemoryExternalIdentityRepository((id) => identityRegistry.findById(id))
				: new PostgresExternalIdentityRepository();
}

export const identityFederationService = new IdentityFederationService();
