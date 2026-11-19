import { randomUUID } from "node:crypto";

import type { IdentitySubject } from "../models/IdentitySubject.js";
import type {
		ExternalIdentity,
		ExternalIdentityProvider,
		IdentityAuthenticationMethod,
		IdentityLinkAuditEntry
} from "../models/ExternalIdentity.js";
import {
		providerSubjectRef,
		type ExternalIdentityRepository,
		type LinkExternalIdentityCommand,
		type LinkExternalIdentityResult,
		type NewIdentityLinkAuditEntry,
		type UnlinkExternalIdentityCommand,
		type UnlinkExternalIdentityResult
} from "./ExternalIdentityRepository.js";

export type SubjectLookup = (id: string) => Promise<IdentitySubject | undefined>;

// Test-only stand-in for PostgresExternalIdentityRepository; never used in production. Mirrors the
// same invariants: exact-provider-identity uniqueness among active links, one active identity per
// provider per subject, last-usable-method protection, and append-only audit.
export class InMemoryExternalIdentityRepository implements ExternalIdentityRepository {
		private readonly identities = new Map<string, ExternalIdentity>();
		private readonly methods = new Map<string, IdentityAuthenticationMethod>();
		private readonly audit: IdentityLinkAuditEntry[] = [];

		constructor(private readonly findSubject: SubjectLookup) {}

		async link(command: LinkExternalIdentityCommand): Promise<LinkExternalIdentityResult> {
				const subject = await this.findSubject(command.identitySubjectId);
				if (!subject) {
						return { status: "rejected", reason: "subject_not_found" };
				}
				if (subject.status !== "ACTIVE") {
						this.record(this.auditFor(command, "LINK", "REJECTED_SUBJECT_INELIGIBLE", `subject status ${subject.status}`));
						return { status: "rejected", reason: "subject_not_active" };
				}

				const existing = [...this.identities.values()].find((identity) =>
						identity.status === "linked" && identity.provider === command.provider
						&& identity.providerIssuer === command.providerIssuer
						&& identity.providerSubject === command.providerSubject);
				if (existing) {
						if (existing.identitySubjectId === command.identitySubjectId) {
								this.record(this.auditFor(command, "LINK", "IDEMPOTENT", undefined, existing.id));
								return { status: "already_linked", externalIdentity: { ...existing } };
						}
						this.record(this.auditFor(command, "LINK", "REJECTED_CONFLICT",
								"provider identity actively linked to another subject"));
						return { status: "conflict", reason: "provider_identity_linked_to_other_subject" };
				}

				const subjectProvider = [...this.identities.values()].find((identity) =>
						identity.status === "linked" && identity.provider === command.provider
						&& identity.identitySubjectId === command.identitySubjectId);
				if (subjectProvider) {
						this.record(this.auditFor(command, "LINK", "REJECTED_CONFLICT",
								"subject already has an active identity for this provider", subjectProvider.id));
						return { status: "conflict", reason: "subject_provider_already_linked" };
				}

				const now = new Date().toISOString();
				const identity: ExternalIdentity = {
						id: command.externalIdentityId,
						identitySubjectId: command.identitySubjectId,
						provider: command.provider,
						providerIssuer: command.providerIssuer,
						providerSubject: command.providerSubject,
						...(command.providerClientContext !== undefined
								? { providerClientContext: command.providerClientContext } : {}),
						status: "linked",
						linkedAt: now,
						createdAt: now,
						updatedAt: now
				};
				this.identities.set(identity.id, identity);
				this.methods.set(command.methodId, {
						id: command.methodId,
						identitySubjectId: command.identitySubjectId,
						methodType: command.provider,
						externalIdentityId: identity.id,
						status: "linked",
						createdAt: now,
						updatedAt: now
				});
				this.record(this.auditFor(command, "LINK", "SUCCEEDED", undefined, identity.id));
				return { status: "linked", externalIdentity: { ...identity } };
		}

		async unlink(command: UnlinkExternalIdentityCommand): Promise<UnlinkExternalIdentityResult> {
				const subject = await this.findSubject(command.identitySubjectId);
				if (!subject) {
						return { status: "rejected", reason: "not_found" };
				}
				const identity = this.identities.get(command.externalIdentityId);
				if (!identity || identity.identitySubjectId !== command.identitySubjectId) {
						return { status: "rejected", reason: "not_found" };
				}
				if (identity.status !== "linked") {
						this.record(this.unlinkAudit(command, identity, "REJECTED_NOT_FOUND", "identity already revoked"));
						return { status: "rejected", reason: "not_found" };
				}

				const otherMethods = [...this.methods.values()].filter((method) =>
						method.identitySubjectId === command.identitySubjectId && method.status !== "revoked"
						&& method.externalIdentityId !== command.externalIdentityId);
				const emailUsable = subject.primaryProvider === "HAPI_EMAIL" && subject.emailVerified === true
						&& subject.status === "ACTIVE";
				if (otherMethods.length === 0 && !emailUsable) {
						this.record(this.unlinkAudit(command, identity, "REJECTED_LAST_METHOD",
								"unlinking would remove the last usable authentication method"));
						return { status: "rejected", reason: "last_method" };
				}

				const now = new Date().toISOString();
				const revoked: ExternalIdentity = { ...identity, status: "revoked", revokedAt: now, updatedAt: now };
				this.identities.set(identity.id, revoked);
				for (const [id, method] of this.methods) {
						if (method.externalIdentityId === identity.id && method.status !== "revoked") {
								this.methods.set(id, { ...method, status: "revoked", revokedAt: now, updatedAt: now });
						}
				}
				this.record(this.unlinkAudit(command, revoked, "SUCCEEDED"));
				return { status: "unlinked", externalIdentity: { ...revoked } };
		}

		async findActiveByProviderIdentity(
				provider: ExternalIdentityProvider,
				providerIssuer: string,
				providerSubject: string
		): Promise<ExternalIdentity | undefined> {
				const identity = [...this.identities.values()].find((candidate) =>
						candidate.status === "linked" && candidate.provider === provider
						&& candidate.providerIssuer === providerIssuer && candidate.providerSubject === providerSubject);
				return identity ? { ...identity } : undefined;
		}

		async listBySubject(identitySubjectId: string): Promise<ExternalIdentity[]> {
				return [...this.identities.values()]
						.filter((identity) => identity.identitySubjectId === identitySubjectId)
						.map((identity) => ({ ...identity }));
		}

		async markAuthenticated(externalIdentityId: string, at: string): Promise<void> {
				const identity = this.identities.get(externalIdentityId);
				if (!identity || identity.status !== "linked") return;
				this.identities.set(externalIdentityId, { ...identity, lastAuthenticatedAt: at, updatedAt: at });
				for (const [id, method] of this.methods) {
						if (method.externalIdentityId === externalIdentityId && method.status !== "revoked") {
								this.methods.set(id, { ...method, lastUsedAt: at, updatedAt: at });
						}
				}
		}

		async listAuthenticationMethods(identitySubjectId: string): Promise<IdentityAuthenticationMethod[]> {
				const methods = [...this.methods.values()]
						.filter((method) => method.identitySubjectId === identitySubjectId)
						.map((method) => ({ ...method }));
				const subject = await this.findSubject(identitySubjectId);
				const hasExplicitEmailMethod = methods.some(
						(method) => method.methodType === "HAPI_EMAIL" && method.status !== "revoked");
				if (subject && !hasExplicitEmailMethod && subject.primaryProvider === "HAPI_EMAIL"
						&& subject.emailVerified === true) {
						methods.unshift({
								id: `derived-hapi-email-${subject.id}`,
								identitySubjectId: subject.id,
								methodType: "HAPI_EMAIL",
								status: "verified",
								createdAt: subject.createdAt,
								updatedAt: subject.updatedAt,
								derived: true
						});
				}
				return methods;
		}

		async listAudit(identitySubjectId: string): Promise<IdentityLinkAuditEntry[]> {
				return this.audit
						.filter((entry) => entry.identitySubjectId === identitySubjectId)
						.map((entry) => ({ ...entry }));
		}

		private record(entry: NewIdentityLinkAuditEntry): void {
				this.audit.push({ ...entry, occurredAt: new Date().toISOString() });
		}

		private auditFor(
				command: LinkExternalIdentityCommand,
				action: IdentityLinkAuditEntry["action"],
				outcome: IdentityLinkAuditEntry["outcome"],
				detail?: string,
				externalIdentityId?: string
		): NewIdentityLinkAuditEntry {
				return {
						id: randomUUID(),
						identitySubjectId: command.identitySubjectId,
						provider: command.provider,
						...(externalIdentityId !== undefined ? { externalIdentityId } : {}),
						providerIssuer: command.providerIssuer,
						providerSubjectRef: providerSubjectRef(command.providerSubject),
						...(command.evidenceReference !== undefined ? { evidenceReference: command.evidenceReference } : {}),
						correlationId: command.correlationId,
						action,
						outcome,
						...(detail !== undefined ? { detail } : {})
				};
		}

		private unlinkAudit(
				command: UnlinkExternalIdentityCommand,
				identity: ExternalIdentity,
				outcome: IdentityLinkAuditEntry["outcome"],
				detail?: string
		): NewIdentityLinkAuditEntry {
				return {
						id: randomUUID(),
						identitySubjectId: command.identitySubjectId,
						provider: identity.provider,
						externalIdentityId: identity.id,
						providerIssuer: identity.providerIssuer,
						providerSubjectRef: providerSubjectRef(identity.providerSubject),
						...(command.evidenceReference !== undefined ? { evidenceReference: command.evidenceReference } : {}),
						correlationId: command.correlationId,
						action: "UNLINK",
						outcome,
						...(detail !== undefined ? { detail } : {})
				};
		}
}
