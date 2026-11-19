import { createHash, randomBytes, randomUUID } from "node:crypto";

import { configuration } from "../../config/ConfigurationService.js";
import { constantTimeStringEqual } from "../../security/ServiceAuthentication.js";
import {
		toHapiSessionView,
		type HapiSession,
		type HapiSessionAuthenticationMethod,
		type HapiSessionView
} from "../../models/HapiSession.js";
import type { HapiSessionRepository, RevokeSessionResult } from "./HapiSessionRepository.js";
import { InMemoryHapiSessionRepository } from "./InMemoryHapiSessionRepository.js";
import { PostgresHapiSessionRepository } from "./PostgresHapiSessionRepository.js";

// __Host- prefix: Secure, host-only, Path=/ -- the session cookie can never be scoped to another
// domain or path, and never crosses origins. SameSite=Lax blocks cross-site POSTs while keeping
// top-level OIDC redirect navigation working.
export const HAPI_SESSION_COOKIE = "__Host-hapi_sid";

const SESSION_SECRET_BYTES = 32;
const CSRF_SECRET_BYTES = 32;

export type HapiSessionErrorCode =
		| "session_not_found"
		| "session_expired"
		| "session_revoked"
		| "csrf_token_invalid";

export class HapiSessionError extends Error {
		constructor(readonly code: HapiSessionErrorCode, message: string) {
				super(message);
				this.name = "HapiSessionError";
		}
}

export type HapiSessionPolicy = {
		// Sliding idle window (refreshed on activity, capped by the absolute ceiling).
		idleTtlMs: number;
		// Hard ceiling from establishment; never extended.
		absoluteTtlMs: number;
};

// Browser session defaults: 30 days idle, 90 days absolute.
export const DEFAULT_SESSION_POLICY: HapiSessionPolicy = {
		idleTtlMs: 30 * 24 * 60 * 60 * 1000,
		absoluteTtlMs: 90 * 24 * 60 * 60 * 1000
};

export type EstablishSessionInput = {
		identitySubjectId: string;
		authenticationMethod: HapiSessionAuthenticationMethod;
		clientId?: string;
		deviceLabel?: string;
		userAgent?: string;
		authenticatedAt?: string;
		// Session fixation protection: the pre-authentication session token (if any) presented by
		// this browser. It is revoked in the same establishment step; authentication NEVER upgrades
		// an existing session token in place.
		supersedesSessionToken?: string;
};

export type EstablishedHapiSession = {
		session: HapiSession;
		// Returned exactly once; only hashes are persisted.
		sessionToken: string;
		csrfToken: string;
		setCookie: string;
};

export function hashSessionToken(token: string): string {
		return createHash("sha256").update(token).digest("base64url");
}

// HAPI ID V2-C persistent session service. Default-off: nothing in the existing Bookwrm
// authentication path constructs or consumes this service unless HAPI_PERSISTENT_SESSIONS_ENABLED
// is explicitly turned on. Raw session secrets exist only in the return value of
// establishSession and in the browser cookie -- never in storage or logs.
export class HapiSessionService {
		constructor(
				private readonly repository: HapiSessionRepository = defaultRepository(),
				private readonly policy: HapiSessionPolicy = DEFAULT_SESSION_POLICY,
				private readonly now: () => Date = () => new Date()
		) {}

		async establishSession(input: EstablishSessionInput): Promise<EstablishedHapiSession> {
				this.assertNonEmpty(input.identitySubjectId, "identitySubjectId");
				const at = this.now();

				// Fixation protection: any session the browser held before authenticating is revoked
				// before the new one exists, so a pre-planted token can never become authenticated.
				if (input.supersedesSessionToken) {
						const previous = await this.repository.findByTokenHash(
								hashSessionToken(input.supersedesSessionToken));
						if (previous && previous.status === "active") {
								await this.repository.revoke(previous.id, "superseded_by_authentication", at.toISOString());
						}
				}

				const sessionToken = `hsid_${randomBytes(SESSION_SECRET_BYTES).toString("base64url")}`;
				const csrfToken = `hcsrf_${randomBytes(CSRF_SECRET_BYTES).toString("base64url")}`;
				const idleExpiresAt = new Date(Math.min(
						at.getTime() + this.policy.idleTtlMs,
						at.getTime() + this.policy.absoluteTtlMs));
				const absoluteExpiresAt = new Date(at.getTime() + this.policy.absoluteTtlMs);

				const session = await this.repository.create({
						id: randomUUID(),
						identitySubjectId: input.identitySubjectId,
						tokenHash: hashSessionToken(sessionToken),
						csrfTokenHash: hashSessionToken(csrfToken),
						...(input.clientId !== undefined ? { clientId: input.clientId } : {}),
						authenticationMethod: input.authenticationMethod,
						authenticatedAt: input.authenticatedAt ?? at.toISOString(),
						...(input.deviceLabel !== undefined ? { deviceLabel: input.deviceLabel } : {}),
						...(input.userAgent !== undefined
								? { userAgentFingerprint: this.fingerprintUserAgent(input.userAgent) } : {}),
						idleExpiresAt: idleExpiresAt.toISOString(),
						absoluteExpiresAt: absoluteExpiresAt.toISOString(),
						lastSeenAt: at.toISOString()
				});

				return {
						session,
						sessionToken,
						csrfToken,
						setCookie: this.buildSessionCookie(sessionToken, absoluteExpiresAt, at)
				};
		}

		// Resolves and (by default) touches a session: sliding idle extension, absolute ceiling.
		// Expired sessions are terminally marked expired as a side effect. Throws typed errors so
		// callers can distinguish re-authentication (expired/revoked) from an unknown cookie.
		async resolveSession(sessionToken: string, options: { touch?: boolean } = {}): Promise<HapiSession> {
				const session = await this.repository.findByTokenHash(hashSessionToken(sessionToken));
				if (!session) {
						throw new HapiSessionError("session_not_found", "Unknown session");
				}
				if (session.status === "revoked") {
						throw new HapiSessionError("session_revoked", "Session has been revoked");
				}
				const at = this.now();
				if (session.status === "expired"
						|| Date.parse(session.idleExpiresAt) <= at.getTime()
						|| Date.parse(session.absoluteExpiresAt) <= at.getTime()) {
						await this.repository.markExpired(session.id, at.toISOString());
						throw new HapiSessionError("session_expired", "Session has expired");
				}
				if (options.touch === false) {
						return session;
				}
				const touched = await this.repository.touch(
						session.id,
						at.toISOString(),
						new Date(at.getTime() + this.policy.idleTtlMs).toISOString());
				return touched ?? session;
		}

		// Double-submit CSRF: the browser presents the CSRF token in a header/body field; it is
		// compared in constant time against the stored hash. The session cookie alone can never
		// authorize a state-changing request.
		verifyCsrfToken(session: HapiSession, presentedCsrfToken: string): void {
				if (typeof presentedCsrfToken !== "string" || presentedCsrfToken.length === 0
						|| !constantTimeStringEqual(session.csrfTokenHash, hashSessionToken(presentedCsrfToken))) {
						throw new HapiSessionError("csrf_token_invalid", "CSRF token validation failed");
				}
		}

		// Logout: terminal server-side invalidation plus an expired cookie for the browser.
		async logout(sessionToken: string): Promise<{ setCookie: string; revoked: boolean }> {
				const session = await this.repository.findByTokenHash(hashSessionToken(sessionToken));
				let revoked = false;
				if (session && session.status === "active") {
						revoked = Boolean(await this.repository.revoke(session.id, "logout", this.now().toISOString()));
				}
				return { setCookie: this.buildClearedSessionCookie(), revoked };
		}

		// Device/session management: a subject revokes one of its own sessions. Cross-subject
		// attempts fail closed without revealing the session's existence.
		async revokeSession(identitySubjectId: string, sessionId: string, reason = "user_revoked"): Promise<RevokeSessionResult> {
				return this.repository.revokeForSubject(identitySubjectId, sessionId, reason, this.now().toISOString());
		}

		async revokeAllSessions(identitySubjectId: string, reason = "user_revoked_all"): Promise<number> {
				return this.repository.revokeAllForSubject(identitySubjectId, reason, this.now().toISOString());
		}

		async listSessions(identitySubjectId: string): Promise<HapiSessionView[]> {
				const sessions = await this.repository.listBySubject(identitySubjectId);
				return sessions.map(toHapiSessionView);
		}

		// Account selection / session reuse: the still-valid sessions this browser or subject can
		// continue without re-authenticating, including recent-authentication context for step-up
		// decisions. Never exposes token or CSRF material.
		async listActiveSessions(identitySubjectId: string): Promise<HapiSessionView[]> {
				const at = this.now().getTime();
				const sessions = await this.repository.listBySubject(identitySubjectId);
				return sessions
						.filter((session) => session.status === "active"
								&& Date.parse(session.idleExpiresAt) > at
								&& Date.parse(session.absoluteExpiresAt) > at)
						.map(toHapiSessionView);
		}

		// Recent-authentication check for sensitive operations (step-up gate).
		isRecentlyAuthenticated(session: HapiSession, maxAgeMs: number): boolean {
				return this.now().getTime() - Date.parse(session.authenticatedAt) <= maxAgeMs;
		}

		buildSessionCookie(sessionToken: string, absoluteExpiresAt: Date, at: Date = this.now()): string {
				const maxAgeSeconds = Math.max(0, Math.floor((absoluteExpiresAt.getTime() - at.getTime()) / 1000));
				return `${HAPI_SESSION_COOKIE}=${sessionToken}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
		}

		buildClearedSessionCookie(): string {
				return `${HAPI_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
		}

		// Server-computed, non-reversible device fingerprint reference for session listings; never
		// used as an authorization factor.
		private fingerprintUserAgent(userAgent: string): string {
				return createHash("sha256").update(userAgent).digest("base64url").slice(0, 16);
		}

		private assertNonEmpty(value: string, field: string): void {
				if (typeof value !== "string" || value.trim().length === 0) {
						throw new Error(`${field} is required`);
				}
		}
}

function defaultRepository(): HapiSessionRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? new InMemoryHapiSessionRepository()
				: new PostgresHapiSessionRepository();
}
