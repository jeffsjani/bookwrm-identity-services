import { identityRegistry } from "./IdentityRegistry.js";
import { recordIdentityAudit } from "./IdentityAudit.js";
import { identityMetrics } from "./infrastructure/IdentityMetrics.js";
import type { IdentitySubject } from "../models/IdentitySubject.js";

export type RecoveryRequest = {
		existingOidcSubject: string;
		newPrivateIdUserId: string;
		// Recovery is never automatic (see Phase 4 design): an administrator must vouch that the
		// new privateIdUserId belongs to the same person as the existing IdentitySubject.
		adminApproved: boolean;
		reason: string;
};

// Implements the Phase 4 Identity Recovery design: a new PrivateID enrollment re-links onto the
// SAME oidcSubject instead of minting a new one, once an administrator has approved the match.
export async function recoverIdentity(request: RecoveryRequest): Promise<IdentitySubject> {
		if (!request.adminApproved) {
				identityMetrics.recordAuthenticatorFailure();
				throw new Error("Identity recovery requires explicit administrative approval");
		}

		const subject = await identityRegistry.findByOidcSubject(request.existingOidcSubject);
		if (!subject) {
				identityMetrics.recordAuthenticatorFailure();
				throw new Error(`Unknown IdentitySubject: ${request.existingOidcSubject}`);
		}

		const conflict = await identityRegistry.findByProvider(subject.primaryProvider, request.newPrivateIdUserId);
		if (conflict && conflict.oidcSubject !== subject.oidcSubject) {
				identityMetrics.recordAuthenticatorFailure();
				throw new Error(`privateIdUserId is already linked to a different IdentitySubject: ${conflict.oidcSubject}`);
		}

		try {
				const updated = await identityRegistry.relinkAuthenticator(request.existingOidcSubject, request.newPrivateIdUserId);
				if (!updated) {
						throw new Error(`Unknown IdentitySubject: ${request.existingOidcSubject}`);
				}

				recordIdentityAudit(subject.oidcSubject, "RECOVERY", {
						previousProviderSubject: subject.primaryProviderSubject,
						newProviderSubject: request.newPrivateIdUserId,
						reason: request.reason
				});
				identityMetrics.recordAuthenticatorAdd();
				return updated;
		} catch (error) {
				identityMetrics.recordAuthenticatorFailure();
				throw error;
		}
}
