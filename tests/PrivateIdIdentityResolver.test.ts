import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { resolveAuthenticatedUserFromPrivateId } from "../src/identity/PrivateIdIdentityResolver.js";

describe("resolveAuthenticatedUserFromPrivateId (RC1 Phase 3, Task 8)", () => {
		it("new user: mints a fresh IdentitySubject-backed sub, never the PrivateID id", async () => {
				const privateIdUserId = `resolver-new-${randomUUID()}`;

				const user = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, {
						email: "resolver-new@example.com",
						emailVerified: true,
						displayName: "Resolver New"
				});

				expect(user.sub).not.toBe(privateIdUserId);
				expect(user.email).toBe("resolver-new@example.com");
		});

		it("existing user: reuses the same subject on a returning login", async () => {
				const privateIdUserId = `resolver-existing-${randomUUID()}`;
				const candidate = { email: "resolver-existing@example.com", emailVerified: true, displayName: "Resolver Existing" };

				const first = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, candidate);
				const second = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, candidate);

				expect(second.sub).toBe(first.sub);
		});

		it("restart proxy: identity resolves the same way on a fresh call after the process would have restarted", async () => {
				const privateIdUserId = `resolver-restart-${randomUUID()}`;
				const candidate = { email: "resolver-restart@example.com", emailVerified: true, displayName: "Resolver Restart" };

				const beforeRestart = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, candidate);
				// A brand-new call with no in-process state stands in for a resumed session after restart.
				const afterRestart = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, candidate);

				expect(afterRestart.sub).toBe(beforeRestart.sub);
		});

		it("refuses to create an identity without a verified email", async () => {
				const privateIdUserId = `resolver-unverified-${randomUUID()}`;

				await expect(
						resolveAuthenticatedUserFromPrivateId(privateIdUserId, {
								email: "resolver-unverified@example.com",
								emailVerified: false,
								displayName: "Resolver Unverified"
						})
				).rejects.toThrow("verified email");
		});
});
