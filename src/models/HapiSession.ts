// HAPI ID V2-C: persistent server-side HAPI sessions. The browser holds only an opaque
// high-entropy secret; the server persists exclusively its hash. Sessions carry the HAPI subject,
// the authenticated client context, recent-authentication evidence, and independent idle and
// absolute expirations.

export type HapiSessionStatus = "active" | "revoked" | "expired";

export type HapiSessionAuthenticationMethod = "HAPI_EMAIL" | "PRIVATEID_FACE" | "APPLE" | "GOOGLE" | "PASSKEY";

export type HapiSession = {
		id: string;
		identitySubjectId: string;
		// SHA-256 (base64url) of the opaque session secret; the raw secret is never persisted.
		tokenHash: string;
		// SHA-256 (base64url) of the per-session CSRF token (double-submit secret).
		csrfTokenHash: string;
		clientId?: string;
		authenticationMethod: HapiSessionAuthenticationMethod;
		authenticatedAt: string;
		deviceLabel?: string;
		userAgentFingerprint?: string;
		status: HapiSessionStatus;
		idleExpiresAt: string;
		absoluteExpiresAt: string;
		lastSeenAt: string;
		revokedAt?: string;
		revocationReason?: string;
		createdAt: string;
		updatedAt: string;
};

// The public, cookie-safe view of a session for device/session management UIs and account
// selection. Never exposes token or CSRF hashes.
export type HapiSessionView = {
		id: string;
		identitySubjectId: string;
		clientId?: string;
		authenticationMethod: HapiSessionAuthenticationMethod;
		authenticatedAt: string;
		deviceLabel?: string;
		status: HapiSessionStatus;
		lastSeenAt: string;
		createdAt: string;
		idleExpiresAt: string;
		absoluteExpiresAt: string;
};

export function toHapiSessionView(session: HapiSession): HapiSessionView {
		return {
				id: session.id,
				identitySubjectId: session.identitySubjectId,
				...(session.clientId !== undefined ? { clientId: session.clientId } : {}),
				authenticationMethod: session.authenticationMethod,
				authenticatedAt: session.authenticatedAt,
				...(session.deviceLabel !== undefined ? { deviceLabel: session.deviceLabel } : {}),
				status: session.status,
				lastSeenAt: session.lastSeenAt,
				createdAt: session.createdAt,
				idleExpiresAt: session.idleExpiresAt,
				absoluteExpiresAt: session.absoluteExpiresAt
		};
}
