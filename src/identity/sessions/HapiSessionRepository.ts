import type { HapiSession, HapiSessionAuthenticationMethod } from "../../models/HapiSession.js";

export type CreateHapiSessionCommand = {
		// Server-generated identifiers and hashes (never caller-supplied protocol values).
		id: string;
		identitySubjectId: string;
		tokenHash: string;
		csrfTokenHash: string;
		clientId?: string;
		authenticationMethod: HapiSessionAuthenticationMethod;
		authenticatedAt: string;
		deviceLabel?: string;
		userAgentFingerprint?: string;
		idleExpiresAt: string;
		absoluteExpiresAt: string;
		lastSeenAt: string;
};

export type RevokeSessionResult =
		| { status: "revoked"; session: HapiSession }
		| { status: "rejected"; reason: "not_found" | "not_active" | "wrong_subject" };

// Server-side session system of record. Implementations must guarantee:
// (1) sessions resolve only by exact token hash; (2) touch never extends a session past its
// absolute expiry and only applies to active sessions; (3) revocation is terminal; (4) a subject
// can only ever revoke its own sessions through revokeForSubject.
export interface HapiSessionRepository {
		create(command: CreateHapiSessionCommand): Promise<HapiSession>;
		findByTokenHash(tokenHash: string): Promise<HapiSession | undefined>;
		findById(id: string): Promise<HapiSession | undefined>;
		// Updates last_seen_at and the sliding idle expiry; returns undefined when the session is
		// no longer active.
		touch(id: string, lastSeenAt: string, idleExpiresAt: string): Promise<HapiSession | undefined>;
		markExpired(id: string, at: string): Promise<void>;
		revoke(id: string, reason: string, at: string): Promise<HapiSession | undefined>;
		// Revokes one session owned by the subject (device/session management); fails closed when the
		// session belongs to a different subject.
		revokeForSubject(identitySubjectId: string, sessionId: string, reason: string, at: string): Promise<RevokeSessionResult>;
		revokeAllForSubject(identitySubjectId: string, reason: string, at: string): Promise<number>;
		listBySubject(identitySubjectId: string): Promise<HapiSession[]>;
}
