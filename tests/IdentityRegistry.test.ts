import { describe, expect, it } from "vitest";

import { IdentityRegistry } from "../src/identity/IdentityRegistry.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";

function buildRegistry() {
		return new IdentityRegistry(new InMemoryIdentitySubjectRepository());
}

describe("IdentityRegistry", () => {
		it("creates a new subject for a first-time PrivateID login and persists it", async () => {
				const registry = buildRegistry();

				const subject = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: "privateid-user-1",
						email: "user@example.com",
						emailVerified: true,
						displayName: "Example User"
				});

				expect(subject.oidcSubject).toBeTruthy();
				expect(subject.primaryProvider).toBe("PrivateID");
				expect(subject.status).toBe("ACTIVE");

				const persisted = await registry.findByOidcSubject(subject.oidcSubject);
				expect(persisted).toEqual(subject);
		});

		it("reuses the existing subject on a returning PrivateID login instead of minting a new one", async () => {
				const registry = buildRegistry();

				const first = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: "privateid-user-2",
						email: "user2@example.com",
						emailVerified: true,
						displayName: "Returning User"
				});

				const second = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: "privateid-user-2",
						email: "user2@example.com",
						emailVerified: true,
						displayName: "Returning User"
				});

				expect(second.oidcSubject).toBe(first.oidcSubject);
				expect(second.id).toBe(first.id);
		});

		it("only ever creates one subject when two logins race for the same provider identity", async () => {
				const registry = buildRegistry();

				const [first, second] = await Promise.all([
						registry.resolveOrCreate({
								provider: "PrivateID",
								providerSubject: "privateid-user-race",
								email: "race@example.com",
								emailVerified: true,
								displayName: "Race User"
						}),
						registry.resolveOrCreate({
								provider: "PrivateID",
								providerSubject: "privateid-user-race",
								email: "race@example.com",
								emailVerified: true,
								displayName: "Race User"
						})
				]);

				expect(first.oidcSubject).toBe(second.oidcSubject);

				const byProvider = await registry.findByProvider("PrivateID", "privateid-user-race");
				expect(byProvider?.oidcSubject).toBe(first.oidcSubject);
		});

		it("creates an identity with an unverified email", async () => {
				const registry = buildRegistry();

				const subject = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: "privateid-user-unverified",
						email: "unverified@example.com",
						emailVerified: false,
						displayName: "Unverified User"
				});

				expect(subject.emailVerified).toBe(false);
		});

		it("creates an identity without email", async () => {
				const registry = buildRegistry();

				const subject = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: "privateid-user-no-email",
						displayName: undefined
				});

				expect(subject.oidcSubject).toBeTruthy();
				expect(subject.email).toBeUndefined();
		});

		it("updates lastAuthenticatedAt on repeat authentication without changing the subject", async () => {
				const registry = buildRegistry();

				const first = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: "privateid-user-3",
						email: "user3@example.com",
						emailVerified: true,
						displayName: "Repeat User"
				});

				await new Promise((resolve) => setTimeout(resolve, 5));

				const touched = await registry.touchAuthentication(first.oidcSubject);
				expect(touched?.oidcSubject).toBe(first.oidcSubject);
				expect(touched?.lastAuthenticatedAt).not.toBe(first.lastAuthenticatedAt);
		});
});
