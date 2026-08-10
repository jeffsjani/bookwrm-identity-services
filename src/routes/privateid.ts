import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityService } from "../identity/IdentityService.js";
import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";
import type { PrivateIDResult } from "../privateid/PrivateIDResult.js";
import {
		resolvePrivateIDSessionRecord,
		storePrivateIDAuthenticatedUser,
		storePrivateIDResult,
		updatePrivateIDSessionStatus
} from "../privateid/PrivateIDSessionStore.js";

type QueryRecord = Record<string, unknown>;
type WebhookBody = Record<string, unknown>;

const PRIVATEID_WEBHOOK_STATUSES = new Set(["SUCCESS", "FAILURE", "PENDING", "REQUIRES_INPUT", "EXPIRED"]);

function normalizedKey(value: string): string {
		return value.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function pickQueryValue(query: QueryRecord, aliases: string[]): string | undefined {
		const aliasSet = new Set(aliases.map((alias) => normalizedKey(alias)));
		for (const [key, rawValue] of Object.entries(query)) {
				if (!aliasSet.has(normalizedKey(key))) {
						continue;
				}

				const value = Array.isArray(rawValue) ? rawValue[0] : rawValue;
				if (typeof value === "string" && value.trim().length > 0) {
						return value.trim();
				}
		}

		return undefined;
}

function pickObjectValue(payload: Record<string, unknown>, aliases: string[]): string | undefined {
		const aliasSet = new Set(aliases.map((alias) => normalizedKey(alias)));
		for (const [key, rawValue] of Object.entries(payload)) {
				if (!aliasSet.has(normalizedKey(key))) {
						continue;
				}

				const value = Array.isArray(rawValue) ? rawValue[0] : rawValue;
				if (typeof value === "string" && value.trim().length > 0) {
						return value.trim();
				}
		}

		return undefined;
}

function createAuthenticatedUser(privateIdUserId: string, fallbackSessionId: string, fallbackTransactionId: string): AuthenticatedUser {
		const fallbackEmail = configuration.get("PRIVATEID_FALLBACK_EMAIL", "privateid.user@bookwrm.local") ?? "privateid.user@bookwrm.local";
		const fallbackName = configuration.get("PRIVATEID_FALLBACK_NAME", "PrivateID User") ?? "PrivateID User";

		return {
				id: privateIdUserId || fallbackSessionId,
				sub: privateIdUserId || fallbackTransactionId,
				email: fallbackEmail,
				name: fallbackName
		};
}

export async function registerPrivateIdRoutes(app: FastifyInstance): Promise<void> {
		app.post("/privateid/webhook", async (request, reply) => {
				const headers = request.headers;
				const body = (request.body ?? {}) as WebhookBody;
				app.log.info(
						{
								path: request.url,
								method: request.method,
								headers,
								body
						},
						"PrivateID webhook received"
				);

				const configuredSecret = secretProvider.getPrivateIdAuthConfiguration().webhookSharedSecret;
				if (!configuredSecret) {
					reply.code(500);
					return {
							error: "server_configuration_error",
							error_description: "PRIVATEID_WEBHOOK_SHARED_SECRET is not configured"
					};
				}

				const receivedSecretHeader = headers["x-storythink-webhook-secret"];
				const receivedSecret = Array.isArray(receivedSecretHeader) ? receivedSecretHeader[0] : receivedSecretHeader;
				if (typeof receivedSecret !== "string" || receivedSecret !== configuredSecret) {
					reply.code(401);
					return {
							error: "unauthorized",
							error_description: "Invalid webhook secret"
					};
				}

				const status = pickObjectValue(body, ["status", "reason"]);
				if (!status || !PRIVATEID_WEBHOOK_STATUSES.has(status)) {
					reply.code(400);
					return {
							error: "invalid_request",
							error_description: "Webhook status must be one of SUCCESS, FAILURE, PENDING, REQUIRES_INPUT, EXPIRED"
					};
				}

				const sessionId = pickObjectValue(body, ["sessionId", "session_id", "sid"]);
				const transactionId = pickObjectValue(body, ["transactionId", "transaction_id", "txId", "txnId"]);
				const record = resolvePrivateIDSessionRecord(sessionId, transactionId);
				if (!record) {
					reply.code(202);
					return {
							status: "pending",
							message: "Webhook accepted but no active PrivateID session was found yet"
					};
				}

				if (status === "SUCCESS") {
						updatePrivateIDSessionStatus(record.session.sessionId, "ready", Date.now());
						const privateIdUserId = pickObjectValue(body, ["privateIdUserId", "privateiduserid", "userId", "subject"]) ?? record.session.transactionId;
						const result: PrivateIDResult = {
								success: true,
								privateIdUserId,
								confidence: configuration.getNumber("PRIVATEID_FALLBACK_CONFIDENCE", 0.99),
								risk: configuration.getNumber("PRIVATEID_FALLBACK_RISK", 0.01),
								liveness: true,
								sessionId: record.session.sessionId,
								transactionId: record.session.transactionId,
								rawResponse: body
						};
						storePrivateIDResult(record.session.sessionId, result);

						try {
								await identityService.resolveIdentity(privateIdUserId);
						} catch (error) {
								app.log.warn({ error, privateIdUserId }, "Identity resolution failed during PrivateID webhook processing");
						}

						const authenticatedUser = createAuthenticatedUser(privateIdUserId, record.session.sessionId, record.session.transactionId);
						storePrivateIDAuthenticatedUser(record.session.sessionId, authenticatedUser);
				} else if (status === "FAILURE") {
						updatePrivateIDSessionStatus(record.session.sessionId, "failed", Date.now());
				} else if (status === "EXPIRED") {
						updatePrivateIDSessionStatus(record.session.sessionId, "expired", Date.now());
				} else {
						updatePrivateIDSessionStatus(record.session.sessionId, "waiting");
				}

				reply.code(200);
				return {
						status,
						sessionId: record.session.sessionId,
						transactionId: record.session.transactionId,
						completed: Boolean(record.session.completed)
				};
		});

		app.get("/privateid/callback", async (request, reply) => {
				const query = (request.query ?? {}) as QueryRecord;
				app.log.info(
						{
								path: request.url,
								method: request.method,
								query,
								headers: request.headers
						},
						"PrivateID callback received"
				);

				const reason = pickQueryValue(query, ["reason", "status", "result"]);
				const sessionId = pickQueryValue(query, ["sessionId", "session_id", "sid"]);
				const transactionId = pickQueryValue(query, ["transactionId", "transaction_id", "txId", "txnId"]);

				if (!reason) {
						reply.code(400);
						return {
							error: "invalid_request",
							error_description: "PrivateID callback must include reason"
						};
				}

				if (reason.trim().toLowerCase() !== "success") {
					reply.code(200);
					reply.type("text/plain");
					return "authentication failed";
				}

				const resolvedRecord = resolvePrivateIDSessionRecord(sessionId, transactionId);

				if (!resolvedRecord) {
					reply.code(202);
					return {
							status: "pending",
							reason,
							message: "Authentication still processing...",
							retry: true
					};
				}

				const isComplete = resolvedRecord.session.status === "ready" && Boolean(resolvedRecord.session.completed);
				if (!isComplete) {
					reply.code(202);
					return {
							status: resolvedRecord.session.status,
							reason,
							sessionId: resolvedRecord.session.sessionId,
							transactionId: resolvedRecord.session.transactionId,
							message: "Authentication still processing...",
							retry: true
					};
				}

				reply.code(200);
				return {
						status: resolvedRecord.session.status,
						reason,
						sessionId: resolvedRecord.session.sessionId,
						transactionId: resolvedRecord.session.transactionId,
						message: "Continue OIDC authorization"
				};
		});
}