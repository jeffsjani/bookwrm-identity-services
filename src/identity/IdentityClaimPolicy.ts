import type { IdentityClaimName } from "../models/IdentitySubject.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";

export type ClaimDecision = "accept" | "ignore" | "update" | "reject";

export type ClaimDecisionResult = {
		decision: ClaimDecision;
		reason: string;
};

export type ClaimEvaluationInput = {
		claim: IdentityClaimName;
		currentValue: unknown;
		currentSource?: IdentityClaimSource;
		proposedValue: unknown;
		proposedSource: IdentityClaimSource;
};

const ADMINISTRATIVE_SOURCES: readonly IdentityClaimSource[] = ["MANUAL", "SYSTEM"];

function isAdministrative(source: IdentityClaimSource): boolean {
		return ADMINISTRATIVE_SOURCES.includes(source);
}

function hasNoCurrentValue(value: unknown): boolean {
		return value === undefined || value === null || value === "";
}

// Sole authority for accept/ignore/update/reject decisions (Task 1). IdentityRegistry is the
// only component permitted to act on the result and persist a claim.
export function evaluateClaim(input: ClaimEvaluationInput): ClaimDecisionResult {
		const { claim, currentValue, currentSource, proposedValue, proposedSource } = input;

		if (claim === "email" && hasNoCurrentValue(proposedValue)) {
				return { decision: "ignore", reason: "No Claim" };
		}

		if (proposedValue === currentValue) {
				return { decision: "ignore", reason: "Proposed value matches current value" };
		}

		// Rule 4: display name may always update, and is always audited.
		if (claim === "displayName") {
				return { decision: "accept", reason: "Display name changes are always accepted and audited" };
		}

		if (hasNoCurrentValue(currentValue) || currentSource === undefined) {
				return { decision: "accept", reason: "No current value recorded for this claim" };
		}

		// Rule 3: emailVerified may only transition false -> true automatically; true -> false requires an administrative source.
		if (claim === "emailVerified") {
				if (proposedValue === true && currentValue === false) {
						return { decision: "update", reason: "Email verification may transition false to true" };
				}

				if (proposedValue === false && currentValue === true) {
						return isAdministrative(proposedSource)
								? { decision: "update", reason: "Administrative action may revoke email verification" }
								: { decision: "reject", reason: "Automatic sources may never revoke email verification" };
				}
		}

		if (isAdministrative(proposedSource)) {
				return { decision: "update", reason: "Administrative source may override any claim" };
		}

		// Rule 2: only the source that owns the current value (or an administrator) may change it.
		if (proposedSource === currentSource) {
				return { decision: "update", reason: "Same source updating its own previously proposed value" };
		}

		return {
				decision: "reject",
				reason: `Conflicting claim from ${proposedSource}; current value is owned by ${currentSource}`
		};
}
