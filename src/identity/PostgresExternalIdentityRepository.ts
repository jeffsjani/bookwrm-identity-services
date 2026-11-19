import type pg from "pg";
import { randomUUID } from "node:crypto";

import type {
		ExternalIdentity,
		ExternalIdentityProvider,
		ExternalIdentityStatus,
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
import {
		getPostgresPool,
		withPostgresTransaction,
		type PostgresClient
} from "./infrastructure/PostgresInfrastructure.js";

const UNIQUE_VIOLATION = "23505";

type ExternalIdentityRow = {
		id: string;
		identity_subject_id: string;
		provider: string;
		provider_issuer: string;
		provider_subject: string;
		provider_client_context: string | null;
		status: string;
		linked_at: string | Date;
		revoked_at: string | Date | null;
		last_authenticated_at: string | Date | null;
		created_at: string | Date;
		updated_at: string | Date;
};

type AuthenticationMethodRow = {
		id: string;
		identity_subject_id: string;
		method_type: string;
		external_identity_id: string | null;
		credential_reference: string | null;
		status: string;
		last_used_at: string | Date | null;
		created_at: string | Date;
		updated_at: string | Date;
		revoked_at: string | Date | null;
};

type AuditRow = {
		id: string;
		identity_subject_id: string;
		provider: string;
		external_identity_id: string | null;
		provider_issuer: string;
		provider_subject_ref: string;
		evidence_reference: string | null;
		correlation_id: string;
		action: string;
		outcome: string;
		detail: string | null;
		occurred_at: string | Date;
};

type SubjectRow = {
		id: string;
		status: string;
		primary_provider: string;
		email_verified: boolean | null;
};

function toIso(value: string | Date): string {
		return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toExternalIdentity(row: ExternalIdentityRow): ExternalIdentity {
		return {
				id: row.id,
				identitySubjectId: row.identity_subject_id,
				provider: row.provider as ExternalIdentityProvider,
				providerIssuer: row.provider_issuer,
				providerSubject: row.provider_subject,
				...(row.provider_client_context !== null ? { providerClientContext: row.provider_client_context } : {}),
				status: row.status as ExternalIdentityStatus,
				linkedAt: toIso(row.linked_at),
				...(row.revoked_at !== null ? { revokedAt: toIso(row.revoked_at) } : {}),
				...(row.last_authenticated_at !== null ? { lastAuthenticatedAt: toIso(row.last_authenticated_at) } : {}),
				createdAt: toIso(row.created_at),
				updatedAt: toIso(row.updated_at)
		};
}

function toMethod(row: AuthenticationMethodRow): IdentityAuthenticationMethod {
		return {
				id: row.id,
				identitySubjectId: row.identity_subject_id,
				methodType: row.method_type as IdentityAuthenticationMethod["methodType"],
				...(row.external_identity_id !== null ? { externalIdentityId: row.external_identity_id } : {}),
				...(row.credential_reference !== null ? { credentialReference: row.credential_reference } : {}),
				status: row.status as IdentityAuthenticationMethod["status"],
				...(row.last_used_at !== null ? { lastUsedAt: toIso(row.last_used_at) } : {}),
				createdAt: toIso(row.created_at),
				updatedAt: toIso(row.updated_at),
				...(row.revoked_at !== null ? { revokedAt: toIso(row.revoked_at) } : {})
		};
}

function toAuditEntry(row: AuditRow): IdentityLinkAuditEntry {
		return {
				id: row.id,
				identitySubjectId: row.identity_subject_id,
				provider: row.provider as ExternalIdentityProvider,
				...(row.external_identity_id !== null ? { externalIdentityId: row.external_identity_id } : {}),
				providerIssuer: row.provider_issuer,
				providerSubjectRef: row.provider_subject_ref,
				...(row.evidence_reference !== null ? { evidenceReference: row.evidence_reference } : {}),
				correlationId: row.correlation_id,
				action: row.action as IdentityLinkAuditEntry["action"],
				outcome: row.outcome as IdentityLinkAuditEntry["outcome"],
				...(row.detail !== null ? { detail: row.detail } : {}),
				occurredAt: toIso(row.occurred_at)
		};
}

function isUniqueViolation(error: unknown): boolean {
		return Boolean(error) && typeof error === "object" && (error as { code?: string }).code === UNIQUE_VIOLATION;
}

// System-of-record implementation. Concurrency model: every link/unlink first takes FOR UPDATE on
// the identity_subjects row, serializing all linking mutations per subject; cross-subject races on
// the same provider identity are decided by the partial unique index (the loser fails closed with
// a unique violation and is reported -- and audited -- as a conflict).
export class PostgresExternalIdentityRepository implements ExternalIdentityRepository {
		constructor(private readonly pool?: pg.Pool) {}

		private get reader(): PostgresClient {
				return (this.pool as PostgresClient | undefined) ?? getPostgresPool();
		}

		private withTransaction<T>(fn: (client: PostgresClient) => Promise<T>): Promise<T> {
				return withPostgresTransaction(fn, this.pool);
		}

		async link(command: LinkExternalIdentityCommand): Promise<LinkExternalIdentityResult> {
				try {
						return await this.withTransaction(async (client) => {
								const subject = await this.lockSubject(client, command.identitySubjectId);
								if (!subject) {
										return { status: "rejected", reason: "subject_not_found" };
								}
								if (subject.status !== "ACTIVE") {
										await this.insertAudit(client, this.auditFor(command, "LINK", "REJECTED_SUBJECT_INELIGIBLE",
												`subject status ${subject.status}`));
										return { status: "rejected", reason: "subject_not_active" };
								}

								const existing = await client.query<ExternalIdentityRow>(
										`SELECT * FROM external_identities
										 WHERE provider = $1 AND provider_issuer = $2 AND provider_subject = $3 AND status = 'linked'
										 FOR UPDATE`,
										[command.provider, command.providerIssuer, command.providerSubject]
								);
								if (existing.rows[0]) {
										if (existing.rows[0].identity_subject_id === command.identitySubjectId) {
												await this.insertAudit(client, this.auditFor(command, "LINK", "IDEMPOTENT",
														undefined, existing.rows[0].id));
												return { status: "already_linked", externalIdentity: toExternalIdentity(existing.rows[0]) };
										}
										// Never reveal the other subject; the audit row references only the keyed identity.
										await this.insertAudit(client, this.auditFor(command, "LINK", "REJECTED_CONFLICT",
												"provider identity actively linked to another subject"));
										return { status: "conflict", reason: "provider_identity_linked_to_other_subject" };
								}

								const subjectProvider = await client.query<{ id: string }>(
										`SELECT id FROM external_identities
										 WHERE identity_subject_id = $1 AND provider = $2 AND status = 'linked'
										 FOR UPDATE`,
										[command.identitySubjectId, command.provider]
								);
								if (subjectProvider.rows[0]) {
										await this.insertAudit(client, this.auditFor(command, "LINK", "REJECTED_CONFLICT",
												"subject already has an active identity for this provider", subjectProvider.rows[0].id));
										return { status: "conflict", reason: "subject_provider_already_linked" };
								}

								const now = new Date();
								const inserted = await client.query<ExternalIdentityRow>(
										`INSERT INTO external_identities
												(id, identity_subject_id, provider, provider_issuer, provider_subject,
												 provider_client_context, status, linked_at, created_at, updated_at)
										 VALUES ($1, $2, $3, $4, $5, $6, 'linked', $7, $7, $7)
										 RETURNING *`,
										[command.externalIdentityId, command.identitySubjectId, command.provider,
												command.providerIssuer, command.providerSubject,
												command.providerClientContext ?? null, now]
								);
								await client.query(
										`INSERT INTO identity_authentication_methods
												(id, identity_subject_id, method_type, external_identity_id, status, created_at, updated_at)
										 VALUES ($1, $2, $3, $4, 'linked', $5, $5)`,
										[command.methodId, command.identitySubjectId, command.provider,
												command.externalIdentityId, now]
								);
								await this.insertAudit(client, this.auditFor(command, "LINK", "SUCCEEDED",
										undefined, command.externalIdentityId));
								return { status: "linked", externalIdentity: toExternalIdentity(inserted.rows[0]) };
						});
				} catch (error) {
						if (!isUniqueViolation(error)) {
								throw error;
						}
						// Lost a cross-subject race: the transaction rolled back, so record the rejection now.
						await this.insertAudit(this.reader, this.auditFor(command, "LINK", "REJECTED_CONFLICT",
								"concurrent linking rejected by uniqueness constraint"));
						return { status: "conflict", reason: "provider_identity_linked_to_other_subject" };
				}
		}

		async unlink(command: UnlinkExternalIdentityCommand): Promise<UnlinkExternalIdentityResult> {
				return this.withTransaction(async (client) => {
						const subject = await this.lockSubject(client, command.identitySubjectId);
						if (!subject) {
								return { status: "rejected", reason: "not_found" };
						}

						const target = await client.query<ExternalIdentityRow>(
								`SELECT * FROM external_identities
								 WHERE id = $1 AND identity_subject_id = $2
								 FOR UPDATE`,
								[command.externalIdentityId, command.identitySubjectId]
						);
						const row = target.rows[0];
						if (!row || row.status !== "linked") {
								// Audit only when the identity exists (already revoked); an unknown id has no
								// provider identity to key an audit row to and changes nothing.
								if (row) {
										await this.insertAudit(client, this.unlinkAudit(command, row, "REJECTED_NOT_FOUND",
												"identity already revoked"));
								}
								return { status: "rejected", reason: "not_found" };
						}

						// The subject row lock serializes unlinks per subject, so this count cannot race to zero.
						const otherMethods = await client.query<{ count: string }>(
								`SELECT count(*)::text AS count FROM identity_authentication_methods
								 WHERE identity_subject_id = $1 AND status <> 'revoked'
								   AND (external_identity_id IS NULL OR external_identity_id <> $2)`,
								[command.identitySubjectId, command.externalIdentityId]
						);
						const emailUsable = subject.primary_provider === "HAPI_EMAIL" && subject.email_verified === true
								&& subject.status === "ACTIVE";
						if (Number(otherMethods.rows[0].count) === 0 && !emailUsable) {
								await this.insertAudit(client, this.unlinkAudit(command, row, "REJECTED_LAST_METHOD",
										"unlinking would remove the last usable authentication method"));
								return { status: "rejected", reason: "last_method" };
						}

						const now = new Date();
						const revoked = await client.query<ExternalIdentityRow>(
								`UPDATE external_identities
								 SET status = 'revoked', revoked_at = $2, updated_at = $2
								 WHERE id = $1
								 RETURNING *`,
								[command.externalIdentityId, now]
						);
						await client.query(
								`UPDATE identity_authentication_methods
								 SET status = 'revoked', revoked_at = $2, updated_at = $2
								 WHERE external_identity_id = $1 AND status <> 'revoked'`,
								[command.externalIdentityId, now]
						);
						await this.insertAudit(client, this.unlinkAudit(command, row, "SUCCEEDED"));
						return { status: "unlinked", externalIdentity: toExternalIdentity(revoked.rows[0]) };
				});
		}

		async findActiveByProviderIdentity(
				provider: ExternalIdentityProvider,
				providerIssuer: string,
				providerSubject: string
		): Promise<ExternalIdentity | undefined> {
				const result = await this.reader.query<ExternalIdentityRow>(
						`SELECT * FROM external_identities
						 WHERE provider = $1 AND provider_issuer = $2 AND provider_subject = $3 AND status = 'linked'`,
						[provider, providerIssuer, providerSubject]
				);
				return result.rows[0] ? toExternalIdentity(result.rows[0]) : undefined;
		}

		async listBySubject(identitySubjectId: string): Promise<ExternalIdentity[]> {
				const result = await this.reader.query<ExternalIdentityRow>(
						`SELECT * FROM external_identities WHERE identity_subject_id = $1 ORDER BY created_at`,
						[identitySubjectId]
				);
				return result.rows.map(toExternalIdentity);
		}

		async markAuthenticated(externalIdentityId: string, at: string): Promise<void> {
				await this.reader.query(
						`UPDATE external_identities SET last_authenticated_at = $2, updated_at = $2
						 WHERE id = $1 AND status = 'linked'`,
						[externalIdentityId, at]
				);
				await this.reader.query(
						`UPDATE identity_authentication_methods SET last_used_at = $2, updated_at = $2
						 WHERE external_identity_id = $1 AND status <> 'revoked'`,
						[externalIdentityId, at]
				);
		}

		async listAuthenticationMethods(identitySubjectId: string): Promise<IdentityAuthenticationMethod[]> {
				const [methods, subject] = await Promise.all([
						this.reader.query<AuthenticationMethodRow>(
								`SELECT * FROM identity_authentication_methods WHERE identity_subject_id = $1 ORDER BY created_at`,
								[identitySubjectId]
						),
						this.reader.query<SubjectRow & { created_at: string | Date; updated_at: string | Date }>(
								`SELECT id, status, primary_provider, email_verified, created_at, updated_at
								 FROM identity_subjects WHERE id = $1`,
								[identitySubjectId]
						)
				]);

				const mapped = methods.rows.map(toMethod);
				const subjectRow = subject.rows[0];
				const hasExplicitEmailMethod = mapped.some(
						(method) => method.methodType === "HAPI_EMAIL" && method.status !== "revoked"
				);
				if (subjectRow && !hasExplicitEmailMethod && subjectRow.primary_provider === "HAPI_EMAIL"
						&& subjectRow.email_verified === true) {
						mapped.unshift({
								id: `derived-hapi-email-${subjectRow.id}`,
								identitySubjectId: subjectRow.id,
								methodType: "HAPI_EMAIL",
								status: "verified",
								createdAt: toIso(subjectRow.created_at),
								updatedAt: toIso(subjectRow.updated_at),
								derived: true
						});
				}
				return mapped;
		}

		async listAudit(identitySubjectId: string): Promise<IdentityLinkAuditEntry[]> {
				const result = await this.reader.query<AuditRow>(
						`SELECT * FROM identity_link_audit WHERE identity_subject_id = $1 ORDER BY occurred_at, id`,
						[identitySubjectId]
				);
				return result.rows.map(toAuditEntry);
		}

		private async lockSubject(client: PostgresClient, identitySubjectId: string): Promise<SubjectRow | undefined> {
				const result = await client.query<SubjectRow>(
						`SELECT id, status, primary_provider, email_verified
						 FROM identity_subjects WHERE id = $1 FOR UPDATE`,
						[identitySubjectId]
				);
				return result.rows[0];
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
				row: ExternalIdentityRow,
				outcome: IdentityLinkAuditEntry["outcome"],
				detail?: string
		): NewIdentityLinkAuditEntry {
				return {
						id: randomUUID(),
						identitySubjectId: command.identitySubjectId,
						provider: row.provider as ExternalIdentityProvider,
						externalIdentityId: row.id,
						providerIssuer: row.provider_issuer,
						providerSubjectRef: providerSubjectRef(row.provider_subject),
						...(command.evidenceReference !== undefined ? { evidenceReference: command.evidenceReference } : {}),
						correlationId: command.correlationId,
						action: "UNLINK",
						outcome,
						...(detail !== undefined ? { detail } : {})
				};
		}

		private async insertAudit(client: PostgresClient, entry: NewIdentityLinkAuditEntry): Promise<void> {
				await client.query(
						`INSERT INTO identity_link_audit
								(id, identity_subject_id, provider, external_identity_id, provider_issuer,
								 provider_subject_ref, evidence_reference, correlation_id, action, outcome, detail, occurred_at)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
						[entry.id, entry.identitySubjectId, entry.provider, entry.externalIdentityId ?? null,
								entry.providerIssuer, entry.providerSubjectRef, entry.evidenceReference ?? null,
								entry.correlationId, entry.action, entry.outcome, entry.detail ?? null, new Date()]
				);
		}
}
