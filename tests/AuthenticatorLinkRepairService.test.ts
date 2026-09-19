import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { repairUserAuthenticatorLink } from "../src/identity/AuthenticatorLinkRepairService.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";

describe("Release C4.9: AuthenticatorLinkRepairService", () => {
	it("repairs a UserAuthenticator.userId still pointing at a legacy Bookwrm ObjectId to the correct IdentitySubject.id", async () => {
		const providerSubject = `puid-${randomUUID()}`;
		const legacyBookwrmObjectId = randomUUID();

		await inMemoryUserAuthenticatorRepository.create({
			id: randomUUID(),
			userId: legacyBookwrmObjectId,
			provider: "privateid",
			providerSubject,
			authenticatorType: "face",
			status: "active"
		});

		const correctIdentitySubject = await identityRegistry.resolveOrCreate({ provider: "PrivateID", providerSubject });
		expect(correctIdentitySubject.id).not.toBe(legacyBookwrmObjectId);

		const first = await repairUserAuthenticatorLink("privateid", "PrivateID", providerSubject, inMemoryUserAuthenticatorRepository);
		expect(first).toMatchObject({ repaired: true, authenticatorFound: true, previousUserId: legacyBookwrmObjectId, correctedUserId: correctIdentitySubject.id });

		const repaired = await inMemoryUserAuthenticatorRepository.findByProviderSubject("privateid", providerSubject);
		expect(repaired?.userId).toBe(correctIdentitySubject.id);
	});

	it("is idempotent: repairing an already-correct link is a no-op and reports repaired=false", async () => {
		const providerSubject = `puid-${randomUUID()}`;
		const legacyBookwrmObjectId = randomUUID();

		await inMemoryUserAuthenticatorRepository.create({
			id: randomUUID(),
			userId: legacyBookwrmObjectId,
			provider: "privateid",
			providerSubject,
			authenticatorType: "face",
			status: "active"
		});

		const first = await repairUserAuthenticatorLink("privateid", "PrivateID", providerSubject, inMemoryUserAuthenticatorRepository);
		expect(first.repaired).toBe(true);

		const second = await repairUserAuthenticatorLink("privateid", "PrivateID", providerSubject, inMemoryUserAuthenticatorRepository);
		expect(second.repaired).toBe(false);
		expect(second.correctedUserId).toBe(first.correctedUserId);

		const authenticator = await inMemoryUserAuthenticatorRepository.findByProviderSubject("privateid", providerSubject);
		expect(authenticator?.userId).toBe(first.correctedUserId);
	});

	it("reports authenticatorFound=false when no UserAuthenticator exists for the (provider, providerSubject)", async () => {
		const result = await repairUserAuthenticatorLink("privateid", "PrivateID", `puid-${randomUUID()}`, inMemoryUserAuthenticatorRepository);
		expect(result).toEqual({ repaired: false, authenticatorFound: false });
	});
});
