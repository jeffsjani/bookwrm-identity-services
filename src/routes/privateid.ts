import type { FastifyInstance } from "fastify";

import { configuration } from "../config/ConfigurationService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { identityService } from "../identity/IdentityService.js";
import { extractIdentityCandidateFromRawResponse, resolveAuthenticatedUserFromPrivateId } from "../identity/PrivateIdIdentityResolver.js";
import { oidcService } from "../oidc/OIDCService.js";
import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";
import type { PrivateIDResult } from "../privateid/PrivateIDResult.js";
import type { IdentityContext } from "../models/IdentityContext.js";
import {
		resolvePrivateIDSessionRecord,
		storePendingAuthorizationRequest,
		storePrivateIDAuthenticatedUser,
		storePrivateIDIdentityContext,
		storePrivateIDResult,
		updatePrivateIDSessionStatus
} from "../privateid/PrivateIDSessionStore.js";
import { consumeByCorrelationId } from "../oidc/CorrelationStore.js";

type QueryRecord = Record<string, unknown>;
type WebhookBody = Record<string, unknown>;

const PRIVATEID_WEBHOOK_STATUSES = new Set(["SUCCESS", "FAILURE", "PENDING", "REQUIRES_INPUT", "EXPIRED"]);
const SENSITIVE_HEADERS = new Set(["x-storythink-webhook-secret", "authorization", "cookie", "set-cookie"]);

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

function sanitizeHeaders(headers: Record<string, unknown>): Record<string, unknown> {
		const sanitized: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(headers)) {
				if (SENSITIVE_HEADERS.has(key.toLowerCase())) {
						sanitized[key] = "[REDACTED]";
						continue;
				}

				sanitized[key] = value;
		}

		return sanitized;
}

function readHeader(headers: Record<string, unknown>, key: string): string | undefined {
		const value = headers[key];
		if (Array.isArray(value)) {
				const first = value[0];
				return typeof first === "string" ? first : undefined;
		}

		return typeof value === "string" ? value : undefined;
}

// Reads metadata.correlationId echoed back on the PrivateID webhook body (Task 3/4, Sprint 9.1).
function readMetadataCorrelationId(body: WebhookBody): string | undefined {
		const metadata = body.metadata;
		if (!metadata || typeof metadata !== "object") {
				return undefined;
		}

		const correlationId = (metadata as Record<string, unknown>).correlationId;
		return typeof correlationId === "string" && correlationId.trim().length > 0 ? correlationId.trim() : undefined;
}

function resolveCorrelationId(requestId: string, headers: Record<string, unknown>): string {
		return readHeader(headers, "x-correlation-id")
				?? readHeader(headers, "x-request-id")
				?? requestId;
}

// Legacy Bookwrm-native path only (no correlationId): still sources identity from Base44's IdentityContext, unchanged.
function createBookwrmLegacyAuthenticatedUser(privateIdUserId: string, fallbackSessionId: string, fallbackTransactionId: string, identityContext?: IdentityContext): AuthenticatedUser {
		const fallbackName = configuration.get("PRIVATEID_FALLBACK_NAME", "PrivateID User") ?? "PrivateID User";
		const { email, emailVerified } = resolveEmailFromIdentityContext(identityContext);

		return {
				id: privateIdUserId || fallbackSessionId,
				sub: privateIdUserId || fallbackTransactionId,
				email,
				emailVerified,
				name: fallbackName
		};
}

// Production email comes from IdentityContext; PRIVATEID_FALLBACK_EMAIL only backstops mock mode.
function resolveEmailFromIdentityContext(identityContext?: IdentityContext): { email: string; emailVerified: boolean } {
		if (identityContext?.email) {
				return { email: identityContext.email, emailVerified: Boolean(identityContext.emailVerified) };
		}

		if (configuration.getBoolean("PRIVATEID_MOCK_MODE", false)) {
				const fallbackEmail = configuration.get("PRIVATEID_FALLBACK_EMAIL", "privateid.user@bookwrm.local") ?? "privateid.user@bookwrm.local";
				return { email: fallbackEmail, emailVerified: true };
		}

		return { email: "", emailVerified: false };
}

export async function registerPrivateIdRoutes(app: FastifyInstance): Promise<void> {
		app.log.info({ method: "POST", path: "/privateid/webhook" }, "PrivateID webhook endpoint registered at POST /privateid/webhook");

		app.post("/privateid/webhook", async (request, reply) => {
				const timestamp = new Date().toISOString();
				const headers = request.headers;
				const body = (request.body ?? {}) as WebhookBody;
				const requestId = request.id;
				const correlationId = resolveCorrelationId(requestId, headers as unknown as Record<string, unknown>);
				const responseContext: {
						sharedSecretValidated?: boolean;
						parsedStatus?: string;
						sessionId?: string;
						transactionId?: string;
						resolvedUserId?: string;
						sessionCompleted?: boolean;
				} = {};

				const logWebhookResponse = (responseCode: number): void => {
						app.log.info(
								{
									event: "privateid_webhook",
									timestamp,
									requestId,
									correlationId,
									sessionId: responseContext.sessionId,
									transactionId: responseContext.transactionId,
									status: responseContext.parsedStatus,
									sharedSecretValidated: responseContext.sharedSecretValidated ?? false,
									resolvedUserId: responseContext.resolvedUserId,
									sessionCompleted: responseContext.sessionCompleted,
									responseCode
								},
								"PrivateID webhook processed"
						);
				};

				app.log.info(
						{
								event: "privateid_webhook_received",
								timestamp,
								requestId,
								correlationId,
								method: request.method,
								path: request.url,
								headers: sanitizeHeaders(headers as unknown as Record<string, unknown>)
						},
						"PrivateID webhook received"
				);

				const configuredSecret = secretProvider.getPrivateIdAuthConfiguration().webhookSharedSecret;
				if (!configuredSecret) {
						responseContext.sharedSecretValidated = false;
						responseContext.sessionCompleted = false;
					reply.code(500);
						logWebhookResponse(500);
					return {
							error: "server_configuration_error",
							error_description: "PRIVATEID_WEBHOOK_SHARED_SECRET is not configured"
					};
				}

				const receivedSecretHeader = headers["x-storythink-webhook-secret"];
				const receivedSecret = Array.isArray(receivedSecretHeader) ? receivedSecretHeader[0] : receivedSecretHeader;
				if (typeof receivedSecret !== "string" || receivedSecret !== configuredSecret) {
						responseContext.sharedSecretValidated = false;
						responseContext.sessionCompleted = false;
					reply.code(401);
						logWebhookResponse(401);
					return {
							error: "unauthorized",
							error_description: "Invalid webhook secret"
					};
				}
				responseContext.sharedSecretValidated = true;

				const status = pickObjectValue(body, ["status", "reason"]);
				responseContext.parsedStatus = status;
				if (!status || !PRIVATEID_WEBHOOK_STATUSES.has(status)) {
						responseContext.sessionCompleted = false;
					reply.code(400);
						logWebhookResponse(400);
					return {
							error: "invalid_request",
							error_description: "Webhook status must be one of SUCCESS, FAILURE, PENDING, REQUIRES_INPUT, EXPIRED"
					};
				}

				const sessionId = pickObjectValue(body, ["sessionId", "session_id", "sid"]);
				const transactionId = pickObjectValue(body, ["transactionId", "transaction_id", "txId", "txnId"]);
				responseContext.sessionId = sessionId;
				responseContext.transactionId = transactionId;
				const record = resolvePrivateIDSessionRecord(sessionId, transactionId);
				if (!record) {
						responseContext.sessionCompleted = false;
					reply.code(202);
						logWebhookResponse(202);
					return {
							status: "pending",
							message: "Webhook accepted but no active PrivateID session was found yet"
					};
				}
				responseContext.sessionId = record.session.sessionId;
				responseContext.transactionId = record.session.transactionId;
				responseContext.resolvedUserId = undefined;
				responseContext.sessionCompleted = Boolean(record.session.completed);

				if (status === "SUCCESS") {
						updatePrivateIDSessionStatus(record.session.sessionId, "ready", Date.now());
						const privateIdUserId = pickObjectValue(body, ["privateIdUserId", "privateiduserid", "userId", "subject"]) ?? record.session.transactionId;
						responseContext.resolvedUserId = privateIdUserId;
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

					// correlationId (Sprint 9.1) completes the PendingAuthorizationContext without relying on Bookwrm state.
					const correlationId = readMetadataCorrelationId(body);
					const correlatedContext = correlationId ? consumeByCorrelationId(correlationId) : undefined;
					if (correlatedContext) {
							storePendingAuthorizationRequest(record.session.sessionId, correlatedContext);
					}

					let authenticatedUser: AuthenticatedUser;
					if (correlationId) {
							// OIDC login: identity comes exclusively from IdentityRegistry, never Bookwrm/Base44.
							try {
									const candidate = extractIdentityCandidateFromRawResponse(body);
									authenticatedUser = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, candidate);
							} catch (error) {
									updatePrivateIDSessionStatus(record.session.sessionId, "failed", Date.now());
									responseContext.sessionCompleted = true;
									app.log.warn({ error, privateIdUserId }, "Identity Registry resolution failed during PrivateID webhook processing");
									reply.code(200);
									logWebhookResponse(200);
									return {
											status: "FAILURE",
											sessionId: record.session.sessionId,
											transactionId: record.session.transactionId,
											completed: true,
											error: error instanceof Error ? error.message : "Identity resolution failed"
									};
							}
					} else {
							// Legacy path only: Bookwrm-native BiometricIdentity flows outside OIDC Login are untouched.
							let resolvedIdentityContext: IdentityContext | undefined;
							try {
									const identityContext = await identityService.resolveIdentity(privateIdUserId);
									storePrivateIDIdentityContext(record.session.sessionId, identityContext);
									resolvedIdentityContext = identityContext.data;
							} catch (error) {
									app.log.warn({ error, privateIdUserId }, "Identity resolution failed during PrivateID webhook processing");
							}

							authenticatedUser = createBookwrmLegacyAuthenticatedUser(privateIdUserId, record.session.sessionId, record.session.transactionId, resolvedIdentityContext);
					}

						storePrivateIDAuthenticatedUser(record.session.sessionId, authenticatedUser);
						responseContext.sessionCompleted = true;
				} else if (status === "FAILURE") {
						updatePrivateIDSessionStatus(record.session.sessionId, "failed", Date.now());
						responseContext.sessionCompleted = true;
				} else if (status === "EXPIRED") {
						updatePrivateIDSessionStatus(record.session.sessionId, "expired", Date.now());
						responseContext.sessionCompleted = true;
				} else {
						updatePrivateIDSessionStatus(record.session.sessionId, "waiting");
						responseContext.sessionCompleted = false;
				}

				reply.code(200);
				logWebhookResponse(200);
				return {
						status,
						sessionId: record.session.sessionId,
						transactionId: record.session.transactionId,
						completed: Boolean(record.session.completed)
				};
		});

		app.get("/privateid/callback", async (request, reply) => {
				const query = (request.query ?? {}) as QueryRecord;
				const requestId = request.id;
				const correlationId = resolveCorrelationId(requestId, request.headers as unknown as Record<string, unknown>);

				const reason = pickQueryValue(query, ["reason", "status", "result"]);
				const sessionId = pickQueryValue(query, ["sessionId", "session_id", "sid"]);
				const transactionId = pickQueryValue(query, ["transactionId", "transaction_id", "txId", "txnId"]);
				let callbackSessionId = sessionId;
				let retry = false;

				if (!reason) {
						app.log.info({ requestId, correlationId, sessionId: callbackSessionId, reason, retry }, "PrivateID callback processed");
						reply.code(400);
						return {
							error: "invalid_request",
							error_description: "PrivateID callback must include reason"
						};
				}

				if (reason.trim().toLowerCase() !== "success") {
						app.log.info({ requestId, correlationId, sessionId: callbackSessionId, reason, retry }, "PrivateID callback processed");
					reply.code(200);
					reply.type("text/plain");
					return "authentication failed";
				}

				const resolvedRecord = resolvePrivateIDSessionRecord(sessionId, transactionId);

				if (!resolvedRecord) {
					retry = true;
						app.log.info({ requestId, correlationId, sessionId: callbackSessionId, reason, retry }, "PrivateID callback processed");
					reply.code(202);
					return {
							status: "pending",
							reason,
							message: "Authentication still processing...",
							retry: true
					};
				}

				const isComplete = resolvedRecord.session.status === "ready" && Boolean(resolvedRecord.session.completed);
				callbackSessionId = resolvedRecord.session.sessionId;
				if (!isComplete) {
					retry = true;
						app.log.info({ requestId, correlationId, sessionId: callbackSessionId, reason, retry }, "PrivateID callback processed");
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
				app.log.info({ requestId, correlationId, sessionId: callbackSessionId, reason, retry }, "PrivateID callback processed");

				const redirectUrl = await oidcService.resumePendingAuthorization(resolvedRecord.session.sessionId);
				if (redirectUrl) {
						reply.redirect(redirectUrl, 302);
						return;
				}

				return {
						status: resolvedRecord.session.status,
						reason,
						sessionId: resolvedRecord.session.sessionId,
						transactionId: resolvedRecord.session.transactionId,
						message: "Continue OIDC authorization"
				};
		});
}