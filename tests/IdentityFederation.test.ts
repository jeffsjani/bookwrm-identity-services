import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";

import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { InMemoryExternalIdentityRepository } from "../src/identity/InMemoryExternalIdentityRepository.js";
import {
		IdentityFederationError,
		IdentityFederationService
} from "../src/identity/IdentityFederationService.js";

// HAPI ID V2-B isolated linking-policy suite. Synthetic provider identities only -- no Apple or
// Google integration exists or is exercised here.
const APPLE_ISSUER = "https://appleid.apple.com";
const GOOGLE_ISSUER = "https://accounts.google.com";

describe("IdentityFederationService (V2-B universal identity linking)", () => {
		let subjects: InMemoryIdentitySubjectRepository;
		let repository: InMemoryExternalIdentityRepository;
		let service: IdentityFederationService;
		let emailSubjectId: string;
		let otherEmailSubjectId: string;
		let faceOnlySubjectId: string;

		const createSubject = async (input: {
				primaryProvider?: "HAPI_EMAIL" | "PrivateID";
				email?: string;
				emailVerified?: boolean;
				status?: "ACTIVE" | "LOCKED" | "DISABLED";
		}) => {
				const id = randomUUID();
				const email = input.email ?? `${id}@example.com`;
				await subjects.create({
						id,
						oidcSubject: randomUUID(),
						primaryProvider: input.primaryProvider ?? "HAPI_EMAIL",
						primaryProviderSubject: input.primaryProvider === "PrivateID" ? `privateid-${id}` : email,
						...(input.primaryProvider === "PrivateID" && input.email === undefined ? {} : { email }),
						emailVerified: input.emailVerified ?? true,
						status: input.status ?? "ACTIVE"
				});
				return id;
		};

		beforeEach(async () => {
				subjects = new InMemoryIdentitySubjectRepository();
				repository = new InMemoryExternalIdentityRepository((id) => subjects.findById(id));
				service = new IdentityFederationService(repository);
				emailSubjectId = await createSubject({ email: "person@example.com" });
				otherEmailSubjectId = await createSubject({ email: "someone-else@example.com" });
				faceOnlySubjectId = await createSubject({ primaryProvider: "PrivateID", emailVerified: false });
		});

		it("links a synthetic Apple identity to an existing subject and audits the success atomically", async () => {
				const result = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId,
						provider: "APPLE",
						providerIssuer: APPLE_ISSUER,
						providerSubject: "apple-sub-001",
						providerClientContext: "com.hapi.web",
						evidenceReference: "evidence-ref-1"
				});

				expect(result.status).toBe("linked");
				const methods = await service.listAuthenticationMethods(emailSubjectId);
				expect(methods.map((method) => method.methodType).sort()).toEqual(["APPLE", "HAPI_EMAIL"]);
				const audit = await service.listLinkAudit(emailSubjectId);
				expect(audit).toHaveLength(1);
				expect(audit[0]).toMatchObject({ action: "LINK", outcome: "SUCCEEDED", provider: "APPLE" });
				// Raw provider subject never appears in audit rows -- only the keyed reference.
				expect(audit[0].providerSubjectRef).not.toContain("apple-sub-001");
		});

		it("treats re-linking the exact same provider identity to the same subject as an idempotent retry", async () => {
				const first = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-002"
				});
				const retry = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-002"
				});

				expect(first.status).toBe("linked");
				expect(retry.status).toBe("already_linked");
				expect(await service.listExternalIdentities(emailSubjectId)).toHaveLength(1);
				const audit = await service.listLinkAudit(emailSubjectId);
				expect(audit.map((entry) => entry.outcome)).toEqual(["SUCCEEDED", "IDEMPOTENT"]);
		});

		it("rejects linking a provider identity that is actively linked to another subject", async () => {
				await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-003"
				});

				const attacked = await service.linkExternalIdentity({
						identitySubjectId: otherEmailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-003"
				});

				expect(attacked).toEqual({ status: "conflict", reason: "provider_identity_linked_to_other_subject" });
				expect(await service.listExternalIdentities(otherEmailSubjectId)).toHaveLength(0);
				const audit = await service.listLinkAudit(otherEmailSubjectId);
				expect(audit).toHaveLength(1);
				expect(audit[0].outcome).toBe("REJECTED_CONFLICT");
		});

		it("rejects a second active identity for the same provider on one subject", async () => {
				await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: "google-sub-001"
				});
				const second = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: "google-sub-002"
				});

				expect(second).toEqual({ status: "conflict", reason: "subject_provider_already_linked" });
		});

		it("never links or merges based on a matching email address", async () => {
				// A second subject carries the SAME verified email claim as emailSubjectId (different
				// primary provider identity, since the registry itself keys HAPI_EMAIL subjects by email).
				// The service API cannot even express an email -- only the authenticated subject id counts.
				const sharedEmailSubject = await createSubject({ primaryProvider: "PrivateID", email: "person@example.com" });

				const result = await service.linkExternalIdentity({
						identitySubjectId: sharedEmailSubject, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: "google-sub-email-match"
				});

				expect(result.status).toBe("linked");
				// The identity landed on the explicitly chosen subject, not the earlier same-email subject.
				expect(await service.listExternalIdentities(emailSubjectId)).toHaveLength(0);
				const linked = await service.listExternalIdentities(sharedEmailSubject);
				expect(linked).toHaveLength(1);
				expect(linked[0].identitySubjectId).toBe(sharedEmailSubject);
		});

		it("detects conflicts without revealing the owning subject", async () => {
				expect(await service.detectConflict(emailSubjectId, "APPLE", APPLE_ISSUER, "apple-sub-004"))
						.toEqual({ state: "unlinked" });

				await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-004"
				});

				const own = await service.detectConflict(emailSubjectId, "APPLE", APPLE_ISSUER, "apple-sub-004");
				expect(own.state).toBe("linked_to_subject");

				const foreign = await service.detectConflict(otherEmailSubjectId, "APPLE", APPLE_ISSUER, "apple-sub-004");
				expect(foreign).toEqual({ state: "linked_to_other_subject" });
		});

		it("unlinks an identity when another usable method remains and audits the unlink", async () => {
				const linked = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-005"
				});
				if (linked.status !== "linked") throw new Error("fixture link failed");

				const unlinked = await service.unlinkExternalIdentity({
						identitySubjectId: emailSubjectId,
						externalIdentityId: linked.externalIdentity.id
				});

				expect(unlinked.status).toBe("unlinked");
				const methods = await service.listAuthenticationMethods(emailSubjectId);
				expect(methods.filter((method) => method.status !== "revoked").map((m) => m.methodType))
						.toEqual(["HAPI_EMAIL"]);
				const audit = await service.listLinkAudit(emailSubjectId);
				expect(audit.at(-1)).toMatchObject({ action: "UNLINK", outcome: "SUCCEEDED" });
		});

		it("allows the same provider identity to be explicitly re-linked to a different subject after unlinking", async () => {
				const linked = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-006"
				});
				if (linked.status !== "linked") throw new Error("fixture link failed");
				await service.unlinkExternalIdentity({
						identitySubjectId: emailSubjectId, externalIdentityId: linked.externalIdentity.id
				});

				const relinked = await service.linkExternalIdentity({
						identitySubjectId: otherEmailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-006"
				});

				expect(relinked.status).toBe("linked");
				// Revoked history on the original subject is preserved, never rewritten.
				const history = await service.listExternalIdentities(emailSubjectId);
				expect(history).toHaveLength(1);
				expect(history[0].status).toBe("revoked");
		});

		it("refuses to unlink the last usable authentication method", async () => {
				const linked = await service.linkExternalIdentity({
						identitySubjectId: faceOnlySubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-007"
				});
				if (linked.status !== "linked") throw new Error("fixture link failed");

				const rejected = await service.unlinkExternalIdentity({
						identitySubjectId: faceOnlySubjectId,
						externalIdentityId: linked.externalIdentity.id
				});

				expect(rejected).toEqual({ status: "rejected", reason: "last_method" });
				const identities = await service.listExternalIdentities(faceOnlySubjectId);
				expect(identities[0].status).toBe("linked");
				const audit = await service.listLinkAudit(faceOnlySubjectId);
				expect(audit.at(-1)).toMatchObject({ action: "UNLINK", outcome: "REJECTED_LAST_METHOD" });
		});

		it("rejects unlinking an identity that does not belong to the subject", async () => {
				const linked = await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-008"
				});
				if (linked.status !== "linked") throw new Error("fixture link failed");

				const rejected = await service.unlinkExternalIdentity({
						identitySubjectId: otherEmailSubjectId,
						externalIdentityId: linked.externalIdentity.id
				});

				expect(rejected).toEqual({ status: "rejected", reason: "not_found" });
				expect((await service.listExternalIdentities(emailSubjectId))[0].status).toBe("linked");
		});

		it("rejects linking for a non-active subject and audits the rejection", async () => {
				const locked = await createSubject({ status: "LOCKED" });

				const result = await service.linkExternalIdentity({
						identitySubjectId: locked, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: "google-sub-locked"
				});

				expect(result).toEqual({ status: "rejected", reason: "subject_not_active" });
				const audit = await service.listLinkAudit(locked);
				expect(audit.at(-1)?.outcome).toBe("REJECTED_SUBJECT_INELIGIBLE");
		});

		it("rejects unknown subjects and unsupported providers", async () => {
				await expect(service.linkExternalIdentity({
						identitySubjectId: randomUUID(), provider: "APPLE",
						providerIssuer: APPLE_ISSUER, providerSubject: "apple-sub-009"
				})).resolves.toEqual({ status: "rejected", reason: "subject_not_found" });

				await expect(service.linkExternalIdentity({
						identitySubjectId: emailSubjectId,
						provider: "FACEBOOK" as never,
						providerIssuer: "https://facebook.example", providerSubject: "fb-1"
				})).rejects.toBeInstanceOf(IdentityFederationError);
		});

		it("derives the HAPI_EMAIL method from the registry without rewriting existing subjects", async () => {
				const before = await subjects.findById(emailSubjectId);
				const methods = await service.listAuthenticationMethods(emailSubjectId);

				expect(methods).toHaveLength(1);
				expect(methods[0]).toMatchObject({ methodType: "HAPI_EMAIL", status: "verified", derived: true });

				await service.linkExternalIdentity({
						identitySubjectId: emailSubjectId, provider: "GOOGLE",
						providerIssuer: GOOGLE_ISSUER, providerSubject: "google-sub-derived"
				});

				const after = await subjects.findById(emailSubjectId);
				// The immutable HAPI identity is untouched by linking.
				expect(after?.oidcSubject).toBe(before?.oidcSubject);
				expect(after?.primaryProvider).toBe(before?.primaryProvider);
				expect(after?.primaryProviderSubject).toBe(before?.primaryProviderSubject);
		});
});
