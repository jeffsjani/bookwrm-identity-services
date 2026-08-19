import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { identityClaimResolver } from "../src/identity/IdentityClaimResolver.js";
import { evaluateClaim } from "../src/identity/IdentityClaimPolicy.js";
import { getClaimAudit } from "../src/identity/IdentityClaimAudit.js";

async function createTestSubject(email: string) {
		return identityRegistry.resolveOrCreate({
				provider: "PrivateID",
				providerSubject: `claim-governance-${randomUUID()}`,
				email,
				emailVerified: true,
				displayName: "Claim Governance User"
		});
}

describe("IdentityClaimPolicy", () => {
		it("accepts a brand-new claim with no prior source", () => {
				const result = evaluateClaim({
						claim: "email",
						currentValue: undefined,
						currentSource: undefined,
						proposedValue: "new@example.com",
						proposedSource: "PRIVATE_ID"
				});

				expect(result.decision).toBe("accept");
		});

			it("treats a missing email as no claim", () => {
					const result = evaluateClaim({
							claim: "email",
							currentValue: undefined,
							currentSource: undefined,
							proposedValue: undefined,
							proposedSource: "PRIVATE_ID"
					});

					expect(result.decision).toBe("ignore");
					expect(result.reason).toBe("No Claim");
			});

		it("rejects a conflicting proposal from a different source than the one that owns the current value", () => {
				const result = evaluateClaim({
						claim: "email",
						currentValue: "owner@example.com",
						currentSource: "PRIVATE_ID",
						proposedValue: "conflict@example.com",
						proposedSource: "GOOGLE"
				});

				expect(result.decision).toBe("reject");
		});

		it("never lets an automatic source revoke emailVerified from true to false", () => {
				const result = evaluateClaim({
						claim: "emailVerified",
						currentValue: true,
						currentSource: "PRIVATE_ID",
						proposedValue: false,
						proposedSource: "PRIVATE_ID"
				});

				expect(result.decision).toBe("reject");
		});
});

describe("IdentityClaimResolver (RC1 Phase 3.1)", () => {
		it("accepts a proposed email when no claim source is recorded yet for this subject", async () => {
				const subject = await createTestSubject("initial@example.com");

				const result = await identityClaimResolver.resolve(subject.oidcSubject, "GOOGLE", {
						email: "google-email@example.com"
				});

				const emailOutcome = result.outcomes.find((outcome) => outcome.claim === "email");
				expect(emailOutcome?.decision).toBe("accept");
				expect(result.subject.email).toBe("google-email@example.com");
		});

		it("ignores a proposal matching the current email", async () => {
				const subject = await createTestSubject("stable@example.com");

				const result = await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", {
						email: subject.email
				});

				const emailOutcome = result.outcomes.find((outcome) => outcome.claim === "email");
				expect(emailOutcome?.decision).toBe("ignore");
				expect(result.subject.email).toBe(subject.email);
		});

		it("rejects a conflicting email from a different provider than the one that set it", async () => {
				const subject = await createTestSubject("owned@example.com");

				await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", {
						email: "privateid-owned@example.com"
				});

				const conflicting = await identityClaimResolver.resolve(subject.oidcSubject, "GOOGLE", {
						email: "google-conflict@example.com"
				});

				const emailOutcome = conflicting.outcomes.find((outcome) => outcome.claim === "email");
				expect(emailOutcome?.decision).toBe("reject");
				expect(conflicting.subject.email).toBe("privateid-owned@example.com");
		});

		it("accepts a display name update and audits it", async () => {
				const subject = await createTestSubject("displayname@example.com");

				const result = await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", {
						displayName: "Updated Display Name"
				});

				const nameOutcome = result.outcomes.find((outcome) => outcome.claim === "displayName");
				expect(nameOutcome?.decision).toBe("accept");
				expect(result.subject.displayName).toBe("Updated Display Name");

				const audit = getClaimAudit(subject.oidcSubject);
				expect(audit.some((entry) => entry.claim === "displayName" && entry.newValue === "Updated Display Name")).toBe(true);
		});

		it("rejects any attempt to mutate the OIDC subject through a claim proposal", async () => {
				const subject = await createTestSubject("immutable-sub@example.com");

				await expect(
						identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", {
								sub: "hacked-subject"
						} as never)
				).rejects.toThrow("immutable");
		});

		it("records an audit entry with old value, new value, source, and reason for every accepted change", async () => {
				const subject = await createTestSubject("audited@example.com");

				await identityClaimResolver.resolve(subject.oidcSubject, "PRIVATE_ID", {
						displayName: "Audited Name"
				});

				const [entry] = getClaimAudit(subject.oidcSubject).filter((candidate) => candidate.claim === "displayName");
				expect(entry).toMatchObject({
						claim: "displayName",
						oldValue: "Claim Governance User",
						newValue: "Audited Name",
						source: "PRIVATE_ID"
				});
				expect(typeof entry.reason).toBe("string");
				expect(typeof entry.timestamp).toBe("string");
		});
});
