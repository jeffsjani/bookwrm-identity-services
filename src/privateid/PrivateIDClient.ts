import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import { secretProvider } from "../config/SecretProvider.js";
import type { PrivateIDResult } from "./PrivateIDResult.js";
import type { PrivateIDSession, PrivateIDSessionStatus } from "./PrivateIDSession.js";
import { findPrivateIDSession, getCurrentPrivateIDSessionRecord, storePrivateIDResult, storePrivateIDSession } from "./PrivateIDSessionStore.js";

type PrivateIDSessionApiResponse = Record<string, unknown>;
const PRIVATEID_WEBHOOK_CALLBACK_URL = "https://identity.bookwrm.com/privateid/webhook";

export type PrivateIDCallbackPayload = {
		reason: string;
		sessionId?: string;
		transactionId?: string;
};

export class PrivateIDClient {
		private currentSessionId?: string;

		async createAuthenticationSession(correlationId?: string): Promise<PrivateIDSession> {
				const now = Date.now();
				const transactionId = randomUUID();
				const authBaseUrl = configuration.require("PRIVATEID_AUTH_BASE_URL");

				if (configuration.getBoolean("PRIVATEID_MOCK_MODE", false)) {
						const normalizedAuthBaseUrl = authBaseUrl.endsWith("/") ? authBaseUrl : `${authBaseUrl}/`;
						const session: PrivateIDSession = {
								sessionId: randomUUID(),
								transactionId,
								status: "created",
								launchUrl: `${normalizedAuthBaseUrl}launch`,
								expires: now + configuration.getNumber("PRIVATEID_SESSION_TTL_MS", 300_000),
								created: now
						};
						storePrivateIDSession(session, { oidcOrigin: Boolean(correlationId) });
						this.currentSessionId = session.sessionId;					console.info("[PrivateID] Created session (mock mode)", { sessionId: session.sessionId, transactionId });
						return session;
				}

				const authConfiguration = secretProvider.getPrivateIdAuthConfiguration();
				const missingCredentials: string[] = [];
				if (!authConfiguration.authApiKey) {
						missingCredentials.push("PRIVATEID_AUTH_API_KEY");
				}

				if (missingCredentials.length > 0) {
						throw new Error(`PrivateID session API configuration missing required credentials: ${missingCredentials.join(", ")}`);
				}

				const normalizedAuthBaseUrl = authBaseUrl.endsWith("/") ? authBaseUrl.slice(0, -1) : authBaseUrl;
				const endpoint = `${normalizedAuthBaseUrl}/v2/verification-session`;
				const redirectUrl = this.resolveRedirectUrl();
				const callbackUrl = this.resolveCallbackUrl();
				const callbackHeaders = this.resolveCallbackHeaders();
				const requestBody = {
					type: "VERIFY",
					requirements: ["face"],
					redirectURL: redirectUrl,
					enableDesktop: true,
					callback: {
							url: callbackUrl,
							headers: callbackHeaders
					},
					// No userId/email: identity is unknown at session creation, only correlationId is passed.
					...(correlationId ? { metadata: { correlationId } } : {})
				};

				const redactedCallbackHeaders = Object.fromEntries(
						Object.keys(callbackHeaders).map((key) => [key, "[REDACTED]"])
				);
				console.info(
						"[PrivateID] Session API request body",
						JSON.stringify({
								type: requestBody.type,
								requirements: requestBody.requirements,
								redirectURL: requestBody.redirectURL,
								callback: {
										url: requestBody.callback.url,
										headers: redactedCallbackHeaders
								}
						})
				);

				const response = await fetch(endpoint, {
						method: "POST",
						headers: {
								"content-type": "application/json",
								"x-api-key": authConfiguration.authApiKey as string
						},
						body: JSON.stringify(requestBody)
				});

				const rawBody = await response.text();
				let responsePayload: PrivateIDSessionApiResponse = {};
				if (rawBody.trim().length > 0) {
						try {
								responsePayload = JSON.parse(rawBody) as PrivateIDSessionApiResponse;
						} catch {
								throw new Error("PrivateID session API returned a non-JSON response");
						}
				}

				if (!response.ok) {
						throw new Error(`PrivateID session API request failed (${response.status}): ${rawBody || response.statusText}`);
				}

				const session = responsePayload as PrivateIDSession;
				if (!session.launchUrl) {
						throw new Error("PrivateID session API response missing launchUrl");
				}
				storePrivateIDSession(session, { oidcOrigin: Boolean(correlationId) });
				this.currentSessionId = session.sessionId;
				console.info("[PrivateID] Created session (PrivateID API)", { sessionId: session.sessionId, transactionId });

				return session;
		}

		async getSession(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();
				if (session.status !== "cancelled" && session.status !== "failed" && session.status !== "expired" && session.expires <= Date.now()) {
						session.status = "expired";
						session.completed = session.completed ?? Date.now();
				}

				return session;
		}

		async pollSession(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();

				if (session.status === "cancelled" || session.status === "failed" || session.status === "expired" || session.status === "ready") {
						return session;
				}

				if (session.expires <= Date.now()) {
						session.status = "expired";
						session.completed = session.completed ?? Date.now();
						return session;
				}

				if (!configuration.getBoolean("PRIVATEID_MOCK_MODE", false)) {
						session.status = "polling";
						return session;
				}

				session.status = "polling";
				const result = this.buildResult(session);
				storePrivateIDResult(session.sessionId, result);
				session.status = "ready";
				session.completed = Date.now();
				return session;
		}

		async handleCallback(payload: PrivateIDCallbackPayload): Promise<PrivateIDSession> {
				const reason = payload.reason.trim();
				const sessionId = payload.sessionId?.trim();
				const transactionId = payload.transactionId?.trim();

				if (!reason) {
						throw new Error("PrivateID callback is missing reason");
				}

				const record = (sessionId || transactionId)
						? findPrivateIDSession(sessionId, transactionId)
						: getCurrentPrivateIDSessionRecord();
				if (!record) {
						throw new Error("PrivateID callback session not found");
				}

				const normalizedReason = reason.toLowerCase();
				if (normalizedReason === "cancelled" || normalizedReason === "failed" || normalizedReason === "expired") {
						record.session.status = normalizedReason;
				} else {
						record.session.status = "ready";
						const result = this.buildResult(record.session);
						storePrivateIDResult(record.session.sessionId, result);
				}

				record.session.completed = Date.now();
				this.currentSessionId = record.session.sessionId;

				return record.session;
		}

		async cancelSession(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();
				session.status = "cancelled";
				session.completed = session.completed ?? Date.now();
				return session;
		}

		async getResult(): Promise<PrivateIDResult | undefined> {
				const session = await this.ensureSession();
				const record = findPrivateIDSession(session.sessionId);
				if (record?.result) {
						return record.result;
				}

				if (session.status !== "ready") {
						return undefined;
				}

				const result = this.buildResult(session);
				storePrivateIDResult(session.sessionId, result);
				return result;
		}

		async initialize(): Promise<PrivateIDSession> {
				return this.createAuthenticationSession();
		}

		async launch(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();
				if (session.status !== "cancelled" && session.status !== "failed" && session.status !== "expired") {
						session.status = "launching";
				}

				return session;
		}

		async identify(): Promise<PrivateIDSession> {
				return this.pollSession();
		}

		async cancel(): Promise<PrivateIDSession> {
				return this.cancelSession();
		}

		async getStatus(): Promise<PrivateIDSessionStatus> {
				const session = await this.ensureSession();
				if (session.expires <= Date.now()) {
						session.status = "expired";
						session.completed = session.completed ?? Date.now();
				}

				return session.status;
		}

		private async ensureSession(): Promise<PrivateIDSession> {
				if (!this.currentSessionId) {
						throw new Error("PrivateID session is not initialized");
				}

				const record = findPrivateIDSession(this.currentSessionId);
				if (!record) {
						throw new Error("PrivateID session not found");
				}

				return record.session;
		}

		private buildResult(session: PrivateIDSession): PrivateIDResult {
				const fallbackUserId = configuration.get("PRIVATEID_FALLBACK_USER_ID", session.transactionId) ?? session.transactionId;
				const confidence = configuration.getNumber("PRIVATEID_FALLBACK_CONFIDENCE", 0.99);
				const risk = configuration.getNumber("PRIVATEID_FALLBACK_RISK", 0.01);

				return {
						success: true,
						privateIdUserId: fallbackUserId,
						confidence,
						risk,
						liveness: true,
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						rawResponse: {
							status: session.status,
							sessionId: session.sessionId,
							transactionId: session.transactionId,
							launchUrl: session.launchUrl,
							expires: session.expires,
							created: session.created,
							completed: session.completed
						}
				};
		}

		private resolveRedirectUrl(): string {
				const redirectUrl = configuration.get("PRIVATEID_REDIRECT_URL")?.trim();
				if (!redirectUrl) {
						throw new Error("Missing required configuration: PRIVATEID_REDIRECT_URL");
				}

				return redirectUrl;
		}

		private resolveCallbackUrl(): string {
				return PRIVATEID_WEBHOOK_CALLBACK_URL;
		}

		private resolveCallbackHeaders(): Record<string, string> {
				const headers: Record<string, string> = {};
				const webhookSharedSecret = secretProvider.getPrivateIdAuthConfiguration().webhookSharedSecret;
				if (webhookSharedSecret) {
					headers["x-storythink-webhook-secret"] = webhookSharedSecret;
				}

				return headers;
		}

		private pickString(payload: PrivateIDSessionApiResponse, candidates: string[]): string | undefined {
				for (const key of candidates) {
						const value = payload[key];
						if (typeof value === "string" && value.trim().length > 0) {
								return value;
						}
				}

				return undefined;
		}

		private pickTimestamp(payload: PrivateIDSessionApiResponse, candidates: string[], fallback: number): number {
				for (const key of candidates) {
						const value = payload[key];
						if (typeof value === "number" && Number.isFinite(value)) {
								return value;
						}
						if (typeof value === "string" && value.trim().length > 0) {
								const asNumber = Number(value);
								if (Number.isFinite(asNumber)) {
										return asNumber;
								}
								const asDate = Date.parse(value);
								if (!Number.isNaN(asDate)) {
										return asDate;
								}
						}
				}

				return fallback;
		}

		private normalizeStatus(status: string): PrivateIDSessionStatus {
				const normalized = status.toLowerCase();
				if (
						normalized === "created"
						|| normalized === "initialized"
						|| normalized === "launching"
						|| normalized === "waiting"
						|| normalized === "polling"
						|| normalized === "ready"
						|| normalized === "cancelled"
						|| normalized === "failed"
						|| normalized === "expired"
				) {
						return normalized;
				}

				return "created";
		}
}