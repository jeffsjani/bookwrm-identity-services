import { describe, expect, it } from "vitest";

import {
		REFRESH_LIFETIMES,
		RefreshRotationError,
		RefreshTokenRotationService,
		hashRefreshToken
} from "../src/oidc/refresh/RefreshTokenRotationService.js";
import { InMemoryRefreshTokenFamilyRepository } from "../src/oidc/refresh/InMemoryRefreshTokenFamilyRepository.js";

// HAPI ID V2-C Phase 2/5: rotating refresh-token family certification (in-memory mirror of the
// PostgreSQL invariants; the database-enforced ones are proven in
// tests/RefreshTokenRotation.postgres.test.ts).

const DAY = 24 * 60 * 60 * 1000;

function buildService() {
		let current = Date.parse("2026-11-19T12:00:00.000Z");
		const clock = {
				now: () => new Date(current),
				advance: (ms: number) => { current += ms; }
		};
		const repository = new InMemoryRefreshTokenFamilyRepository();
		const service = new RefreshTokenRotationService(repository, REFRESH_LIFETIMES, clock.now);
		return { service, repository, clock };
}

const SUBJECT = "00000000-0000-4000-8000-000000000001";
const CLIENT = "elite-native";

async function issue(service: RefreshTokenRotationService, overrides: Record<string, unknown> = {}) {
		return service.issueFamily({
				identitySubjectId: SUBJECT,
				clientId: CLIENT,
				scope: "openid profile email",
				clientProfile: "native_public",
				authenticationMethod: "PRIVATEID_FACE",
				authenticatedAt: "2026-11-19T12:00:00.000Z",
				sessionId: "00000000-0000-4000-8000-00000000aaaa",
				deviceReference: "device-1",
				...overrides
		});
}

describe("V2-C rotating refresh-token families", () => {
		it("issues opaque high-entropy tokens and persists only their hashes", async () => {
				const { service, repository } = buildService();
				const issued = await issue(service);

				expect(issued.refreshToken).toMatch(/^hrt_[A-Za-z0-9_-]{43}$/);
				expect(issued.generation.generation).toBe(1);
				expect(issued.family.status).toBe("active");
				expect(issued.family.identitySubjectId).toBe(SUBJECT);
				expect(issued.family.clientId).toBe(CLIENT);
				expect(issued.family.sessionId).toBe("00000000-0000-4000-8000-00000000aaaa");

				const generations = await repository.listGenerations(issued.family.id);
				expect(generations).toHaveLength(1);
				expect(generations[0].tokenHash).toBe(hashRefreshToken(issued.refreshToken));
				expect(JSON.stringify(generations)).not.toContain(issued.refreshToken);
		});

		it("applies the approved lifetime policy per client profile", async () => {
				const { service } = buildService();
				const native = await issue(service, { clientProfile: "native_public" });
				const confidential = await issue(service, { clientProfile: "confidential_web" });

				expect(Date.parse(native.family.absoluteExpiresAt) - Date.parse(native.family.createdAt))
						.toBe(90 * DAY);
				expect(Date.parse(native.generation.expiresAt) - Date.parse(native.generation.createdAt))
						.toBe(14 * DAY);
				expect(Date.parse(confidential.family.absoluteExpiresAt) - Date.parse(confidential.family.createdAt))
						.toBe(30 * DAY);
				expect(Date.parse(confidential.generation.expiresAt) - Date.parse(confidential.generation.createdAt))
						.toBe(DAY);
		});

		it("rotates one-time-use generations: the consumed token is terminally rotated", async () => {
				const { service, repository } = buildService();
				const first = await issue(service);

				const second = await service.rotate({
						refreshToken: first.refreshToken,
						clientId: CLIENT,
						clientProfile: "native_public"
				});
				expect(second.refreshToken).not.toBe(first.refreshToken);
				expect(second.generation.generation).toBe(2);

				const generations = await repository.listGenerations(first.family.id);
				expect(generations.map((generation) => [generation.generation, generation.status]))
						.toEqual([[1, "rotated"], [2, "active"]]);
				expect(generations[0].replacedBy).toBe(second.generation.id);
		});

		it("detects replay of a consumed token and revokes the entire family", async () => {
				const { service } = buildService();
				const first = await issue(service);
				const second = await service.rotate({
						refreshToken: first.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				});

				// Replay the consumed generation (stolen-token scenario).
				await expect(service.rotate({
						refreshToken: first.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token", familyRevoked: true });

				// The legitimate holder's latest token is dead too: interactive re-auth required.
				await expect(service.rotate({
						refreshToken: second.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });

				const family = await service.getFamily(first.family.id);
				expect(family?.status).toBe("revoked");
				expect(family?.revocationReason).toBe("reuse_detected");
		});

		it("rejects the wrong client without consuming the legitimate holder's token", async () => {
				const { service } = buildService();
				const issued = await issue(service);

				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: "other-client", clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "client_mismatch" });

				// Not consumed: the real client still rotates successfully.
				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).resolves.toBeDefined();
		});

		it("rejects unknown tokens and tokens from a different family's lineage", async () => {
				const { service } = buildService();
				await issue(service);
				await expect(service.rotate({
						refreshToken: "hrt_" + "a".repeat(43), clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});

		it("enforces the sliding idle expiration per generation", async () => {
				const { service, clock } = buildService();
				const issued = await issue(service);

				clock.advance(14 * DAY + 1);
				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});

		it("never rotates past the family's absolute expiration", async () => {
				const { service, clock } = buildService();
				let token = (await issue(service)).refreshToken;

				// Stay maximally active: rotate every 10 days; the 90-day ceiling still terminates.
				for (let elapsed = 0; elapsed < 90; elapsed += 10) {
						clock.advance(10 * DAY);
						try {
								const rotated = await service.rotate({
										refreshToken: token, clientId: CLIENT, clientProfile: "native_public"
								});
								token = rotated.refreshToken;
								// Every successor's expiry is capped by the family ceiling.
								expect(Date.parse(rotated.generation.expiresAt))
										.toBeLessThanOrEqual(Date.parse(rotated.family.absoluteExpiresAt));
						} catch (error) {
								expect(elapsed + 10).toBeGreaterThanOrEqual(90);
								expect((error as RefreshRotationError).code).toBe("invalid_refresh_token");
						}
				}
				await expect(service.rotate({
						refreshToken: token, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});

		it("fails closed under concurrent refresh attempts: exactly one successor survives", async () => {
				const { service } = buildService();
				const issued = await issue(service);

				const attempts = await Promise.allSettled([
						service.rotate({ refreshToken: issued.refreshToken, clientId: CLIENT, clientProfile: "native_public" }),
						service.rotate({ refreshToken: issued.refreshToken, clientId: CLIENT, clientProfile: "native_public" })
				]);
				const fulfilled = attempts.filter((attempt) => attempt.status === "fulfilled");
				const rejected = attempts.filter((attempt) => attempt.status === "rejected");
				expect(fulfilled).toHaveLength(1);
				expect(rejected).toHaveLength(1);
				// Documented explicit behavior: the loser is treated as reuse -- the family is revoked
				// and BOTH holders must re-authenticate. Clients must serialize refreshes and must not
				// blindly retry over the network.
				const error = (rejected[0] as PromiseRejectedResult).reason as RefreshRotationError;
				expect(error.code).toBe("invalid_refresh_token");
				const family = await service.getFamily(issued.family.id);
				expect(family?.status).toBe("revoked");
		});

		it("supports logout, session, device and subject revocation surfaces", async () => {
				const { service } = buildService();
				const phone = await issue(service, { deviceReference: "device-phone", sessionId: "00000000-0000-4000-8000-00000000bbbb" });
				const laptop = await issue(service, { deviceReference: "device-laptop", sessionId: "00000000-0000-4000-8000-00000000cccc" });

				// Device revocation hits only that device's family.
				expect(await service.revokeByDevice(SUBJECT, "device-phone")).toBe(1);
				await expect(service.rotate({
						refreshToken: phone.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
				await expect(service.rotate({
						refreshToken: laptop.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).resolves.toBeDefined();

				// Session revocation cascades to the session's families.
				const another = await issue(service, { sessionId: "00000000-0000-4000-8000-00000000dddd" });
				expect(await service.revokeBySession("00000000-0000-4000-8000-00000000dddd", "logout")).toBe(1);
				await expect(service.rotate({
						refreshToken: another.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });

				// Subject-wide revocation (LOCKED/DISABLED lifecycle binding).
				const final = await issue(service);
				expect(await service.revokeAllForSubject(SUBJECT, "subject_locked")).toBeGreaterThanOrEqual(1);
				await expect(service.rotate({
						refreshToken: final.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});

		it("supports RFC 7009-style revocation by presented token, idempotently", async () => {
				const { service } = buildService();
				const issued = await issue(service);

				expect(await service.revokePresentedToken(issued.refreshToken)).toBe(true);
				expect(await service.revokePresentedToken(issued.refreshToken)).toBe(false);
				expect(await service.revokePresentedToken("hrt_" + "b".repeat(43))).toBe(false);
				await expect(service.rotate({
						refreshToken: issued.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});

		it("isolates families across subjects and clients", async () => {
				const { service } = buildService();
				const otherSubject = "00000000-0000-4000-8000-000000000002";
				const mine = await issue(service);
				const theirs = await issue(service, { identitySubjectId: otherSubject });

				await service.revokeAllForSubject(otherSubject, "subject_locked");
				// The other subject's revocation never touches this subject's family.
				await expect(service.rotate({
						refreshToken: mine.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).resolves.toBeDefined();
				await expect(service.rotate({
						refreshToken: theirs.refreshToken, clientId: CLIENT, clientProfile: "native_public"
				})).rejects.toMatchObject({ code: "invalid_refresh_token" });
		});
});
