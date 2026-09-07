import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { AuthenticatorLoginError, AuthenticatorLoginResolver } from "../src/identity/AuthenticatorLoginResolver.js";
import { InMemoryAuthenticatorLoginTransactionRepository } from "../src/identity/InMemoryAuthenticatorLoginTransactionRepository.js";
import { InMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";

function user(overrides: Partial<IdentitySubject> = {}): IdentitySubject {
	return { id: randomUUID(), oidcSubject: randomUUID(), primaryProvider: "PrivateID", primaryProviderSubject: "legacy", email: "canonical@example.test", emailVerified: true, displayName: "Canonical User", status: "ACTIVE", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), ...overrides };
}

describe("AuthenticatorLoginResolver", () => {
	it("resolves the existing canonical user from a known privateid PUID", async () => {
		const authenticators = new InMemoryUserAuthenticatorRepository();
		const canonicalUser = user();
		await authenticators.create({ id: randomUUID(), userId: canonicalUser.id, provider: "privateid", providerSubject: "puid-known", authenticatorType: "face", status: "active" });
		const resolver = new AuthenticatorLoginResolver(authenticators, { async findById(id) { return id === canonicalUser.id ? canonicalUser : undefined; } }, new InMemoryAuthenticatorLoginTransactionRepository());

		const resolved = await resolver.resolveLogin("privateid", randomUUID(), "puid-known");
		expect(resolved).toMatchObject({ id: canonicalUser.id, oidcSubject: canonicalUser.oidcSubject, email: "canonical@example.test" });
	});

	it("denies unknown and revoked faces without a user lookup", async () => {
		const authenticators = new InMemoryUserAuthenticatorRepository();
		let userLookups = 0;
		const resolver = new AuthenticatorLoginResolver(authenticators, { async findById() { userLookups += 1; return undefined; } }, new InMemoryAuthenticatorLoginTransactionRepository());
		await expect(resolver.resolveLogin("privateid", randomUUID(), "unknown-puid")).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
		const canonicalUser = user();
		await authenticators.create({ id: randomUUID(), userId: canonicalUser.id, provider: "privateid", providerSubject: "revoked-puid", authenticatorType: "face", status: "revoked" });
		await expect(resolver.resolveLogin("privateid", randomUUID(), "revoked-puid")).rejects.toMatchObject({ code: "AUTHENTICATOR_REVOKED" });
		expect(userLookups).toBe(0);
	});

	it("denies an inactive canonical user", async () => {
		const authenticators = new InMemoryUserAuthenticatorRepository();
		const inactiveUser = user({ status: "DISABLED" });
		await authenticators.create({ id: randomUUID(), userId: inactiveUser.id, provider: "privateid", providerSubject: "inactive-puid", authenticatorType: "face", status: "active" });
		const resolver = new AuthenticatorLoginResolver(authenticators, { async findById() { return inactiveUser; } }, new InMemoryAuthenticatorLoginTransactionRepository());
		await expect(resolver.resolveLogin("privateid", randomUUID(), "inactive-puid")).rejects.toBeInstanceOf(AuthenticatorLoginError);
	});

	it("does not permit duplicate PUID links", async () => {
		const authenticators = new InMemoryUserAuthenticatorRepository();
		await authenticators.create({ id: randomUUID(), userId: randomUUID(), provider: "privateid", providerSubject: "duplicate-puid", authenticatorType: "face", status: "active" });
		await expect(authenticators.create({ id: randomUUID(), userId: randomUUID(), provider: "privateid", providerSubject: "duplicate-puid", authenticatorType: "face", status: "active" })).rejects.toThrow("provider subject already linked");
	});
});