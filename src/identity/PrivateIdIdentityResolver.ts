import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";
import { identityRegistry } from "./IdentityRegistry.js";
import { identityMetrics } from "./infrastructure/IdentityMetrics.js";
import { beginPendingIdentity, markBlocked, markPersisted } from "./PendingIdentity.js";

export type PrivateIdIdentityCandidate = {
		email?: string;
		emailVerified?: boolean;
		displayName?: string;
};

function pickString(source: Record<string, unknown>, keys: string[]): string | undefined {
		for (const key of keys) {
				const value = source[key];
				if (typeof value === "string" && value.trim().length > 0) {
						return value.trim();
				}
		}

		return undefined;
}

function pickBoolean(source: Record<string, unknown>, keys: string[]): boolean | undefined {
		for (const key of keys) {
				const value = source[key];
				if (typeof value === "boolean") {
						return value;
				}
		}

		return undefined;
}

// PrivateID is the only source of identity fields here -- never Bookwrm/Base44 IdentityContext.
export function extractIdentityCandidateFromRawResponse(rawResponse: unknown): PrivateIdIdentityCandidate {
		if (!rawResponse || typeof rawResponse !== "object") {
				return {};
		}

		const source = rawResponse as Record<string, unknown>;
		return {
				email: pickString(source, ["email", "userEmail"]),
				emailVerified: pickBoolean(source, ["emailVerified", "email_verified"]),
				displayName: pickString(source, ["name", "displayName", "fullName"])
		};
}

function resolveCandidate(candidate: PrivateIdIdentityCandidate): { email: string; emailVerified: boolean; displayName: string } {
		const fallbackName = configuration.get("PRIVATEID_FALLBACK_NAME", "PrivateID User") ?? "PrivateID User";

		if (candidate.email) {
				return {
						email: candidate.email,
						emailVerified: candidate.emailVerified ?? false,
						displayName: candidate.displayName ?? fallbackName
				};
		}

		if (configuration.getBoolean("PRIVATEID_MOCK_MODE", false)) {
				const fallbackEmail = configuration.get("PRIVATEID_FALLBACK_EMAIL", "privateid.user@bookwrm.local") ?? "privateid.user@bookwrm.local";
				return { email: fallbackEmail, emailVerified: true, displayName: candidate.displayName ?? fallbackName };
		}

		return { email: "", emailVerified: false, displayName: candidate.displayName ?? fallbackName };
}

// PrivateID -> privateIdUserId -> IdentityRegistry.resolveOrCreate() -> PendingIdentity -> persisted IdentitySubject.
// Throws if email is not verified: identity is never created without one (RC1-F).
export async function resolveAuthenticatedUserFromPrivateId(
		privateIdUserId: string,
		candidate: PrivateIdIdentityCandidate
): Promise<AuthenticatedUser> {
		const { email, emailVerified, displayName } = resolveCandidate(candidate);
		beginPendingIdentity(privateIdUserId, email, emailVerified, displayName);

		if (!emailVerified) {
				markBlocked(privateIdUserId, "Identity cannot be created without a verified email");
				identityMetrics.recordOidcFailure();
				throw new Error("IdentitySubject cannot be created without verified email");
		}

		let identitySubject;
		try {
				identitySubject = await identityRegistry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: privateIdUserId,
						email,
						emailVerified,
						displayName
				});
		} catch (error) {
				identityMetrics.recordOidcFailure();
				throw error;
		}

		identityMetrics.recordOidcLogin();
		markPersisted(privateIdUserId, identitySubject);

		return {
				id: privateIdUserId,
				sub: identitySubject.oidcSubject,
				email: identitySubject.email,
				emailVerified: identitySubject.emailVerified,
				name: identitySubject.displayName
		};
}
