import type { HapiSession } from "../../models/HapiSession.js";
import type {
		CreateHapiSessionCommand,
		HapiSessionRepository,
		RevokeSessionResult
} from "./HapiSessionRepository.js";

// Test-only mirror of PostgresHapiSessionRepository invariants.
export class InMemoryHapiSessionRepository implements HapiSessionRepository {
		private readonly sessions = new Map<string, HapiSession>();

		async create(command: CreateHapiSessionCommand): Promise<HapiSession> {
				for (const existing of this.sessions.values()) {
						if (existing.tokenHash === command.tokenHash) {
								throw Object.assign(new Error("duplicate session token hash"), { code: "23505" });
						}
				}
				const now = command.lastSeenAt;
				const session: HapiSession = {
						id: command.id,
						identitySubjectId: command.identitySubjectId,
						tokenHash: command.tokenHash,
						csrfTokenHash: command.csrfTokenHash,
						...(command.clientId !== undefined ? { clientId: command.clientId } : {}),
						authenticationMethod: command.authenticationMethod,
						authenticatedAt: command.authenticatedAt,
						...(command.deviceLabel !== undefined ? { deviceLabel: command.deviceLabel } : {}),
						...(command.userAgentFingerprint !== undefined
								? { userAgentFingerprint: command.userAgentFingerprint } : {}),
						status: "active",
						idleExpiresAt: command.idleExpiresAt,
						absoluteExpiresAt: command.absoluteExpiresAt,
						lastSeenAt: command.lastSeenAt,
						createdAt: now,
						updatedAt: now
				};
				this.sessions.set(session.id, session);
				return { ...session };
		}

		async findByTokenHash(tokenHash: string): Promise<HapiSession | undefined> {
				for (const session of this.sessions.values()) {
						if (session.tokenHash === tokenHash) {
								return { ...session };
						}
				}
				return undefined;
		}

		async findById(id: string): Promise<HapiSession | undefined> {
				const session = this.sessions.get(id);
				return session ? { ...session } : undefined;
		}

		async touch(id: string, lastSeenAt: string, idleExpiresAt: string): Promise<HapiSession | undefined> {
				const session = this.sessions.get(id);
				if (!session || session.status !== "active") {
						return undefined;
				}
				// Never extend the sliding window beyond the absolute ceiling.
				const cappedIdle = idleExpiresAt > session.absoluteExpiresAt
						? session.absoluteExpiresAt
						: idleExpiresAt;
				session.lastSeenAt = lastSeenAt;
				session.idleExpiresAt = cappedIdle;
				session.updatedAt = lastSeenAt;
				return { ...session };
		}

		async markExpired(id: string, at: string): Promise<void> {
				const session = this.sessions.get(id);
				if (session && session.status === "active") {
						session.status = "expired";
						session.updatedAt = at;
				}
		}

		async revoke(id: string, reason: string, at: string): Promise<HapiSession | undefined> {
				const session = this.sessions.get(id);
				if (!session || session.status !== "active") {
						return undefined;
				}
				session.status = "revoked";
				session.revokedAt = at;
				session.revocationReason = reason;
				session.updatedAt = at;
				return { ...session };
		}

		async revokeForSubject(
				identitySubjectId: string,
				sessionId: string,
				reason: string,
				at: string
		): Promise<RevokeSessionResult> {
				const session = this.sessions.get(sessionId);
				if (!session) {
						return { status: "rejected", reason: "not_found" };
				}
				if (session.identitySubjectId !== identitySubjectId) {
						// Never reveal whether the session exists for another subject.
						return { status: "rejected", reason: "wrong_subject" };
				}
				if (session.status !== "active") {
						return { status: "rejected", reason: "not_active" };
				}
				const revoked = await this.revoke(sessionId, reason, at);
				return revoked
						? { status: "revoked", session: revoked }
						: { status: "rejected", reason: "not_active" };
		}

		async revokeAllForSubject(identitySubjectId: string, reason: string, at: string): Promise<number> {
				let count = 0;
				for (const session of this.sessions.values()) {
						if (session.identitySubjectId === identitySubjectId && session.status === "active") {
								session.status = "revoked";
								session.revokedAt = at;
								session.revocationReason = reason;
								session.updatedAt = at;
								count += 1;
						}
				}
				return count;
		}

		async listBySubject(identitySubjectId: string): Promise<HapiSession[]> {
				return [...this.sessions.values()]
						.filter((session) => session.identitySubjectId === identitySubjectId)
						.sort((a, b) => a.createdAt.localeCompare(b.createdAt))
						.map((session) => ({ ...session }));
		}
}
