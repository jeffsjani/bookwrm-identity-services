import { identityRegistry } from "./IdentityRegistry.js";
import { identityClaimResolver } from "./IdentityClaimResolver.js";
import { recordIdentityAudit } from "./IdentityAudit.js";
import type { IdentityClaimSource } from "./IdentityClaimSource.js";
import type { IdentitySubject } from "../models/IdentitySubject.js";

export type MergeRequest = {
		survivorOidcSubject: string;
		loserOidcSubject: string;
		reason: string;
};

export type MergeResult = {
		survivor: IdentitySubject;
		loserOidcSubject: string;
};

// Implements the Phase 4 Identity Merge design (claim reconciliation + loser retirement).
// LIMITATION: current schema models exactly one primaryProvider/primaryProviderSubject per
// IdentitySubject, so the loser's authenticator link is NOT re-attached to the survivor here --
// that requires a multi-authenticator table, tracked as future work (see Phase 4 design notes).
export async function mergeIdentities(request: MergeRequest): Promise<MergeResult> {
		if (request.survivorOidcSubject === request.loserOidcSubject) {
				throw new Error("Cannot merge an IdentitySubject into itself");
		}

		const [survivor, loser] = await Promise.all([
				identityRegistry.findByOidcSubject(request.survivorOidcSubject),
				identityRegistry.findByOidcSubject(request.loserOidcSubject)
		]);

		if (!survivor) {
				throw new Error(`Unknown survivor IdentitySubject: ${request.survivorOidcSubject}`);
		}
		if (!loser) {
				throw new Error(`Unknown loser IdentitySubject: ${request.loserOidcSubject}`);
		}

		// Merges are administrator-initiated; claims are reconciled as an administrative source so
		// they always take effect (per IdentityClaimPolicy Rule 2/3), never silently dropped.
		const adminSource: IdentityClaimSource = "MANUAL";
		const { subject: reconciled } = await identityClaimResolver.resolve(survivor.oidcSubject, adminSource, {
				email: loser.email !== survivor.email ? loser.email : undefined,
				emailVerified: loser.emailVerified && !survivor.emailVerified ? true : undefined,
				displayName: loser.displayName !== survivor.displayName ? loser.displayName : undefined
		});

		const disabledLoser = await identityRegistry.applyClaimUpdate(loser.oidcSubject, { status: "DISABLED" });
		if (!disabledLoser) {
				throw new Error(`Failed to retire loser IdentitySubject: ${loser.oidcSubject}`);
		}

		recordIdentityAudit(survivor.oidcSubject, "MERGE", {
				role: "survivor",
				mergedFrom: loser.oidcSubject,
				reason: request.reason
		});
		recordIdentityAudit(loser.oidcSubject, "MERGE", {
				role: "loser",
				mergedInto: survivor.oidcSubject,
				reason: request.reason
		});

		return { survivor: reconciled, loserOidcSubject: loser.oidcSubject };
}
