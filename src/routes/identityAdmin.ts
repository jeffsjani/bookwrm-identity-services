import type { FastifyInstance } from "fastify";

import { identityAdministrationService } from "../identity/IdentityAdministrationService.js";
import { recoverIdentity } from "../identity/IdentityRecoveryService.js";
import { mergeIdentities } from "../identity/IdentityMergeService.js";
import type { IdentityProvider, IdentitySubject } from "../models/IdentitySubject.js";

const VALID_PROVIDERS: readonly IdentityProvider[] = ["PrivateID", "Google", "Apple", "Passkey", "Enterprise"];
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidProvider(value: string): value is IdentityProvider {
		return (VALID_PROVIDERS as readonly string[]).includes(value);
}

// Composes the read-only subject detail view: identity + history + authenticators + timeline (Tasks 2-4).
function toSubjectDetail(subject: IdentitySubject) {
		return {
				subject,
				history: identityAdministrationService.getHistory(subject),
				authenticators: identityAdministrationService.getAuthenticators(subject),
				timeline: identityAdministrationService.getTimeline(subject)
		};
}

// Read-only Identity Administration API (Phase 4). Namespaced under /identity/admin to avoid
// colliding with the existing Bookwrm-facing /identity/* routes in routes/identity.ts.
export async function registerIdentityAdminRoutes(app: FastifyInstance): Promise<void> {
		app.get("/identity/admin/subjects", async () => {
				const subjects = await identityAdministrationService.listSubjects();
				return { subjects: subjects.map((subject) => toSubjectDetail(subject)) };
		});

		app.get<{ Params: { id: string } }>("/identity/admin/subject/:id", async (request, reply) => {
				if (!UUID_PATTERN.test(request.params.id)) {
						reply.code(404);
						return { error: "not_found", error_description: "No IdentitySubject for this oidcSubject" };
				}

				const subject = await identityAdministrationService.getSubject(request.params.id);
				if (!subject) {
						reply.code(404);
						return { error: "not_found", error_description: "No IdentitySubject for this oidcSubject" };
				}

				return toSubjectDetail(subject);
		});

		app.get<{ Params: { id: string } }>("/identity/admin/subject/:id/audit", async (request, reply) => {
				if (!UUID_PATTERN.test(request.params.id)) {
						reply.code(404);
						return { error: "not_found", error_description: "No IdentitySubject for this oidcSubject" };
				}

				const subject = await identityAdministrationService.getSubject(request.params.id);
				if (!subject) {
						reply.code(404);
						return { error: "not_found", error_description: "No IdentitySubject for this oidcSubject" };
				}

				return { oidcSubject: subject.oidcSubject, audit: identityAdministrationService.getAudit(subject.oidcSubject) };
		});

		app.get<{ Params: { provider: string; subject: string } }>("/identity/admin/provider/:provider/:subject", async (request, reply) => {
				const { provider, subject: providerSubject } = request.params;
				if (!isValidProvider(provider)) {
						reply.code(400);
						return { error: "invalid_request", error_description: `Unknown provider: ${provider}` };
				}

				const subject = await identityAdministrationService.getByProvider(provider, providerSubject);
				if (!subject) {
						reply.code(404);
						return { error: "not_found", error_description: "No IdentitySubject for this provider identity" };
				}

				return toSubjectDetail(subject);
		});

		app.get<{ Params: { email: string } }>("/identity/admin/email/:email", async (request) => {
				const subjects = await identityAdministrationService.getByEmail(decodeURIComponent(request.params.email));
				return { subjects: subjects.map((subject) => toSubjectDetail(subject)) };
		});

		app.get("/identity/admin/health", async (_request, reply) => {
				const health = await identityAdministrationService.getHealth();
				const { schemaVersion, migrationStatus, ...componentHealthEntries } = health;
				const unhealthy = Object.values(componentHealthEntries).some((component) => component.status === "unhealthy");
				if (unhealthy) {
						reply.code(503);
				}

				return health;
		});

		// Mutation endpoints (Phase 5 Tasks 8-9) -- both require explicit administrative intent, never automatic.
		app.post<{ Params: { id: string }; Body: { newPrivateIdUserId?: string; adminApproved?: boolean; reason?: string } }>(
				"/identity/admin/subject/:id/recover",
				async (request, reply) => {
						const { newPrivateIdUserId, adminApproved, reason } = request.body ?? {};
						if (!newPrivateIdUserId || !reason) {
								reply.code(400);
								return { error: "invalid_request", error_description: "newPrivateIdUserId and reason are required" };
						}

						try {
								const subject = await recoverIdentity({
										existingOidcSubject: request.params.id,
										newPrivateIdUserId,
										adminApproved: Boolean(adminApproved),
										reason
								});
								return toSubjectDetail(subject);
						} catch (error) {
								reply.code(409);
								return { error: "recovery_failed", error_description: error instanceof Error ? error.message : "Recovery failed" };
						}
				}
		);

		app.post<{ Body: { survivorOidcSubject?: string; loserOidcSubject?: string; reason?: string } }>(
				"/identity/admin/merge",
				async (request, reply) => {
						const { survivorOidcSubject, loserOidcSubject, reason } = request.body ?? {};
						if (!survivorOidcSubject || !loserOidcSubject || !reason) {
								reply.code(400);
								return { error: "invalid_request", error_description: "survivorOidcSubject, loserOidcSubject, and reason are required" };
						}

						try {
								const result = await mergeIdentities({ survivorOidcSubject, loserOidcSubject, reason });
								return { survivor: toSubjectDetail(result.survivor), loserOidcSubject: result.loserOidcSubject };
						} catch (error) {
								reply.code(409);
								return { error: "merge_failed", error_description: error instanceof Error ? error.message : "Merge failed" };
						}
				}
		);
}
