import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { AuthenticatorLoginResolver } from "../src/identity/AuthenticatorLoginResolver.js";
import { InMemoryAuthenticatorLoginTransactionRepository } from "../src/identity/InMemoryAuthenticatorLoginTransactionRepository.js";
import { InMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";

describe("face enrollment login continuity", () => {
	it("resolves an enrolled Face authenticator to the existing canonical HAPI Email subject", async () => {
		const authenticators = new InMemoryUserAuthenticatorRepository();
		const email = "before-enrollment@example.test";
		const user: IdentitySubject = {
			id: randomUUID(), oidcSubject: randomUUID(), primaryProvider: "HAPI_EMAIL", primaryProviderSubject: email,
			email, emailVerified: true, displayName: "Existing User", status: "ACTIVE",
			createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
		};
		await authenticators.create({ id: randomUUID(), userId: user.id, provider: "privateid",
			providerSubject: "puid-continuity", authenticatorType: "face", status: "active" });
		const login = new AuthenticatorLoginResolver(authenticators, { async findById(id) { return id === user.id ? user : undefined; } }, new InMemoryAuthenticatorLoginTransactionRepository());
		const resolved = await login.resolveLogin("privateid", randomUUID(), "puid-continuity");

		expect(resolved.id).toBe(user.id);
		expect(resolved.oidcSubject).toBe(user.oidcSubject);
		expect(resolved.email).toBe(user.email);
		expect((await authenticators.findByProviderSubject("privateid", "puid-continuity"))?.status).toBe("active");
	});
});