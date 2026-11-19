import { describe, expect, it } from "vitest";

import {
		DEFAULT_SESSION_POLICY,
		HAPI_SESSION_COOKIE,
		HapiSessionError,
		HapiSessionService,
		hashSessionToken
} from "../src/identity/sessions/HapiSessionService.js";
import { InMemoryHapiSessionRepository } from "../src/identity/sessions/InMemoryHapiSessionRepository.js";

// HAPI ID V2-C Phase 1/5: persistent-session policy certification (in-memory system-of-record
// mirror; the PostgreSQL invariants are proven in tests/HapiSession.postgres.test.ts).

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function buildService(options: { idleTtlMs?: number; absoluteTtlMs?: number } = {}) {
		let current = Date.parse("2026-11-19T12:00:00.000Z");
		const clock = {
				now: () => new Date(current),
				advance: (ms: number) => { current += ms; }
		};
		const repository = new InMemoryHapiSessionRepository();
		const service = new HapiSessionService(repository, {
				idleTtlMs: options.idleTtlMs ?? DEFAULT_SESSION_POLICY.idleTtlMs,
				absoluteTtlMs: options.absoluteTtlMs ?? DEFAULT_SESSION_POLICY.absoluteTtlMs
		}, clock.now);
		return { service, repository, clock };
}

const subject = (suffix = "1") => `00000000-0000-4000-8000-00000000000${suffix}`;

async function establish(service: HapiSessionService, subjectId = subject()) {
		return service.establishSession({
				identitySubjectId: subjectId,
				authenticationMethod: "HAPI_EMAIL",
				clientId: "bookwrm-web",
				deviceLabel: "Test Browser",
				userAgent: "Mozilla/5.0 (test)"
		});
}

describe("V2-C persistent HAPI sessions", () => {
		it("establishes a session with a hardened HttpOnly cookie and returns the secret exactly once", async () => {
				const { service } = buildService();
				const established = await establish(service);

				expect(established.sessionToken).toMatch(/^hsid_[A-Za-z0-9_-]{43}$/);
				expect(established.csrfToken).toMatch(/^hcsrf_[A-Za-z0-9_-]{43}$/);
				expect(established.setCookie).toContain(`${HAPI_SESSION_COOKIE}=${established.sessionToken}`);
				expect(established.setCookie).toContain("HttpOnly");
				expect(established.setCookie).toContain("Secure");
				expect(established.setCookie).toContain("SameSite=Lax");
				expect(established.setCookie).toContain("Path=/");
				expect(HAPI_SESSION_COOKIE.startsWith("__Host-")).toBe(true);

				expect(established.session.identitySubjectId).toBe(subject());
				expect(established.session.authenticationMethod).toBe("HAPI_EMAIL");
				expect(established.session.clientId).toBe("bookwrm-web");
		});

		it("persists only hashes -- never the raw session secret or CSRF token", async () => {
				const { service, repository } = buildService();
				const established = await establish(service);

				const stored = await repository.findById(established.session.id);
				expect(stored).toBeDefined();
				const serialized = JSON.stringify(stored);
				expect(serialized).not.toContain(established.sessionToken);
				expect(serialized).not.toContain(established.csrfToken);
				expect(stored?.tokenHash).toBe(hashSessionToken(established.sessionToken));
				expect(stored?.csrfTokenHash).toBe(hashSessionToken(established.csrfToken));
		});

		it("resolves and touches an active session, sliding the idle window forward", async () => {
				const { service, clock } = buildService({ idleTtlMs: 2 * DAY });
				const established = await establish(service);
				const initialIdle = established.session.idleExpiresAt;

				clock.advance(DAY);
				const resolved = await service.resolveSession(established.sessionToken);
				expect(resolved.id).toBe(established.session.id);
				expect(Date.parse(resolved.idleExpiresAt)).toBeGreaterThan(Date.parse(initialIdle));
		});

		it("rejects an unknown session token", async () => {
				const { service } = buildService();
				await expect(service.resolveSession("hsid_" + "a".repeat(43)))
						.rejects.toMatchObject({ code: "session_not_found" });
		});

		it("enforces idle expiration terminally", async () => {
				const { service, clock } = buildService({ idleTtlMs: HOUR });
				const established = await establish(service);

				clock.advance(HOUR + 1);
				await expect(service.resolveSession(established.sessionToken))
						.rejects.toMatchObject({ code: "session_expired" });
				// Terminal: the session cannot come back even if the clock moved backwards.
				clock.advance(-HOUR);
				await expect(service.resolveSession(established.sessionToken))
						.rejects.toMatchObject({ code: "session_expired" });
		});

		it("never extends a session beyond its absolute expiration, regardless of activity", async () => {
				const { service, clock } = buildService({ idleTtlMs: DAY, absoluteTtlMs: 3 * DAY });
				const established = await establish(service);
				const absolute = Date.parse(established.session.absoluteExpiresAt);

				// Keep the session maximally active right up to the ceiling.
				for (let i = 0; i < 5; i += 1) {
						clock.advance(12 * HOUR);
						if (clock.now().getTime() < absolute) {
								const resolved = await service.resolveSession(established.sessionToken);
								expect(Date.parse(resolved.idleExpiresAt)).toBeLessThanOrEqual(absolute);
								expect(Date.parse(resolved.absoluteExpiresAt)).toBe(absolute);
						}
				}
				clock.advance(DAY);
				await expect(service.resolveSession(established.sessionToken))
						.rejects.toMatchObject({ code: "session_expired" });
		});

		it("protects against session fixation: authentication always mints a new session and revokes the presented one", async () => {
				const { service } = buildService();
				const preAuth = await establish(service);

				const postAuth = await service.establishSession({
						identitySubjectId: subject("2"),
						authenticationMethod: "PRIVATEID_FACE",
						supersedesSessionToken: preAuth.sessionToken
				});

				expect(postAuth.session.id).not.toBe(preAuth.session.id);
				expect(postAuth.sessionToken).not.toBe(preAuth.sessionToken);
				// The pre-authentication token can never ride into the authenticated context.
				await expect(service.resolveSession(preAuth.sessionToken))
						.rejects.toMatchObject({ code: "session_revoked" });
		});

		it("validates CSRF tokens in constant time against the stored hash", async () => {
				const { service } = buildService();
				const established = await establish(service);
				const session = await service.resolveSession(established.sessionToken);

				expect(() => service.verifyCsrfToken(session, established.csrfToken)).not.toThrow();
				expect(() => service.verifyCsrfToken(session, "hcsrf_" + "x".repeat(43)))
						.toThrow(HapiSessionError);
				expect(() => service.verifyCsrfToken(session, "")).toThrow(HapiSessionError);
		});

		it("logout invalidates server-side state and clears the cookie", async () => {
				const { service } = buildService();
				const established = await establish(service);

				const result = await service.logout(established.sessionToken);
				expect(result.revoked).toBe(true);
				expect(result.setCookie).toContain(`${HAPI_SESSION_COOKIE}=;`);
				expect(result.setCookie).toContain("Max-Age=0");

				await expect(service.resolveSession(established.sessionToken))
						.rejects.toMatchObject({ code: "session_revoked" });
				// Idempotent: a second logout with the dead cookie is harmless.
				const again = await service.logout(established.sessionToken);
				expect(again.revoked).toBe(false);
		});

		it("revokes an individual device session without touching the subject's other sessions", async () => {
				const { service } = buildService();
				const phone = await establish(service);
				const laptop = await establish(service);

				const result = await service.revokeSession(subject(), phone.session.id, "device_revoked");
				expect(result.status).toBe("revoked");

				await expect(service.resolveSession(phone.sessionToken))
						.rejects.toMatchObject({ code: "session_revoked" });
				await expect(service.resolveSession(laptop.sessionToken)).resolves.toBeDefined();
		});

		it("enforces cross-user isolation: a subject can never revoke another subject's session", async () => {
				const { service } = buildService();
				const victim = await establish(service, subject("1"));
				const attacker = subject("2");

				const result = await service.revokeSession(attacker, victim.session.id);
				expect(result).toEqual({ status: "rejected", reason: "wrong_subject" });
				await expect(service.resolveSession(victim.sessionToken)).resolves.toBeDefined();
		});

		it("supports account selection and session reuse through active-session listings without exposing secrets", async () => {
				const { service, clock } = buildService({ idleTtlMs: HOUR });
				const first = await establish(service);
				await service.logout(first.sessionToken);
				const second = await establish(service);
				const third = await establish(service);
				clock.advance(30 * 60 * 1000);
				// Reuse: the still-valid session resolves without re-authentication.
				await expect(service.resolveSession(second.sessionToken)).resolves.toBeDefined();

				const active = await service.listActiveSessions(subject());
				expect(active.map((view) => view.id).sort())
						.toEqual([second.session.id, third.session.id].sort());
				for (const view of active) {
						const serialized = JSON.stringify(view);
						expect(serialized).not.toContain("tokenHash");
						expect(serialized).not.toContain("csrfTokenHash");
						expect(view.authenticationMethod).toBe("HAPI_EMAIL");
						expect(view.authenticatedAt).toBeDefined();
				}
		});

		it("tracks recent authentication for step-up decisions", async () => {
				const { service, clock } = buildService();
				const established = await establish(service);
				const session = await service.resolveSession(established.sessionToken);

				expect(service.isRecentlyAuthenticated(session, 10 * 60 * 1000)).toBe(true);
				clock.advance(11 * 60 * 1000);
				expect(service.isRecentlyAuthenticated(session, 10 * 60 * 1000)).toBe(false);
		});

		it("revokes every session for a subject at once (global sign-out)", async () => {
				const { service } = buildService();
				const a = await establish(service);
				const b = await establish(service);
				const other = await establish(service, subject("2"));

				const count = await service.revokeAllSessions(subject());
				expect(count).toBe(2);
				await expect(service.resolveSession(a.sessionToken)).rejects.toMatchObject({ code: "session_revoked" });
				await expect(service.resolveSession(b.sessionToken)).rejects.toMatchObject({ code: "session_revoked" });
				await expect(service.resolveSession(other.sessionToken)).resolves.toBeDefined();
		});
});
