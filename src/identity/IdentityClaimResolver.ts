import type { IdentityClaimName, IdentitySubject } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";
import { evaluateClaim, type ClaimDecision } from "./IdentityClaimPolicy.js";
import { recordClaimAudit } from "./IdentityClaimAudit.js";
import type { IdentityClaimSourceStore } from "./IdentityClaimSourceStore.js";
import { inMemoryIdentityClaimSourceStore } from "./InMemoryIdentityClaimSourceStore.js";
import { PostgresIdentityClaimSourceStore } from "./PostgresIdentityClaimSourceStore.js";
import { identityRegistry } from "./IdentityRegistry.js";
import { identityMetrics } from "./infrastructure/IdentityMetrics.js";
import type { UpdateIdentitySubjectInput } from "./IdentitySubjectRepository.js";
import { configuration } from "../config/ConfigurationService.js";

export type SuggestedClaims = {
		email?: string;
		emailVerified?: boolean;
		displayName?: string;
};

export type ClaimResolutionOutcome = {
		claim: IdentityClaimName;
		decision: ClaimDecision;
		reason: string;
};

export type ClaimResolutionResult = {
		subject: IdentitySubject;
		outcomes: ClaimResolutionOutcome[];
};

const CLAIM_VALUE_FIELDS = ["email", "emailVerified", "displayName"] as const;

function defaultClaimSourceStore(): IdentityClaimSourceStore {
		return configuration.getIdentityRegistryDriver() === "memory"
					? inMemoryIdentityClaimSourceStore
				: new PostgresIdentityClaimSourceStore();
}

// Only path allowed to turn authenticator-suggested claims into persisted IdentitySubject fields.
// Authenticators propose; this resolver (via IdentityClaimPolicy) decides; IdentityRegistry persists.
export class IdentityClaimResolver {
		constructor(private readonly claimSources: IdentityClaimSourceStore = defaultClaimSourceStore()) {}

		async resolve(oidcSubject: string, source: IdentityClaimSource, suggested: SuggestedClaims): Promise<ClaimResolutionResult> {
				// Rule 1: the OIDC Subject never changes -- reject any attempt to smuggle it in as a "claim".
				const suggestedAsRecord = suggested as Record<string, unknown>;
				if ("sub" in suggestedAsRecord || "oidcSubject" in suggestedAsRecord) {
						throw new Error("OIDC Subject is immutable and cannot be proposed as a claim");
				}

				const subject = await identityRegistry.findByOidcSubject(oidcSubject);
				if (!subject) {
						throw new Error(`Unknown IdentitySubject: ${oidcSubject}`);
				}

				const outcomes: ClaimResolutionOutcome[] = [];
				const changes: UpdateIdentitySubjectInput = {};
				// Task 2: durable provenance is keyed by the immutable identity_subjects.id, not oidcSubject.
				const claimSources = await this.claimSources.getClaimSources(subject.id);
				const claimUpdatedAt = await this.claimSources.getClaimUpdatedAt(subject.id);

				for (const claim of CLAIM_VALUE_FIELDS) {
						if (suggested[claim] === undefined) {
								continue;
						}

						const currentValue = subject[claim];
						const proposedValue = suggested[claim] as string | boolean;
						const { decision, reason } = evaluateClaim({
								claim,
								currentValue,
								currentSource: claimSources[claim],
								proposedValue,
								proposedSource: source
						});

						outcomes.push({ claim, decision, reason });
						identityMetrics.recordClaimUpdate(claim, decision);

						if (decision === "accept" || decision === "update") {
								recordClaimAudit({ oidcSubject, claim, oldValue: currentValue, newValue: proposedValue, source, reason });
								if (claim === "email") {
										changes.email = suggested.email;
								} else if (claim === "emailVerified") {
										changes.emailVerified = suggested.emailVerified;
								} else if (claim === "displayName") {
										changes.displayName = suggested.displayName;
								}
								const timestamp = new Date().toISOString();
								await this.claimSources.recordClaimSource(subject.id, claim, source, timestamp);
								claimSources[claim] = source;
								claimUpdatedAt[claim] = timestamp;
						}
				}

				if (Object.keys(changes).length === 0) {
						return { subject, outcomes };
				}

				const persisted = await identityRegistry.applyClaimUpdate(oidcSubject, changes);
				const finalSubject: IdentitySubject = {
						...(persisted ?? subject),
						claimSources,
						claimUpdatedAt
				};

				return { subject: finalSubject, outcomes };
		}
}

export const identityClaimResolver = new IdentityClaimResolver();

