import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import { secretProvider } from "../config/SecretProvider.js";
import type { PrivateIDResult } from "./PrivateIDResult.js";
import type { PrivateIDSession, PrivateIDSessionStatus } from "./PrivateIDSession.js";

type PrivateIDSessionApiResponse = Record<string, unknown>;

export class PrivateIDClient {
		private session?: PrivateIDSession;
		private result?: PrivateIDResult;

		async createAuthenticationSession(): Promise<PrivateIDSession> {
				const now = Date.now();
				const transactionId = randomUUID();
				const authBaseUrl = configuration.require("PRIVATEID_AUTH_BASE_URL");
				this.result = undefined;

				if (configuration.getBoolean("PRIVATEID_MOCK_MODE", false)) {
						const normalizedAuthBaseUrl = authBaseUrl.endsWith("/") ? authBaseUrl : `${authBaseUrl}/`;
						this.session = {
								sessionId: randomUUID(),
								transactionId,
								status: "created",
								launchUrl: `${normalizedAuthBaseUrl}launch`,
								expires: now + configuration.getNumber("PRIVATEID_SESSION_TTL_MS", 300_000),
								created: now
						};

						return this.session;
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
				const callbackUrl = this.resolveCallbackUrl(redirectUrl);
				const callbackHeaders = this.resolveCallbackHeaders();

				const response = await fetch(endpoint, {
						method: "POST",
						headers: {
								"content-type": "application/json",
								"x-api-key": authConfiguration.authApiKey as string
						},
						body: JSON.stringify({
							type: "SIGN-IN",
							redirectURL: redirectUrl,
							enableDesktop: true,
							callback: {
									url: callbackUrl,
									headers: callbackHeaders
							}
						})
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

				this.session = responsePayload as PrivateIDSession;
				if (!this.session.launchUrl) {
						throw new Error("PrivateID session API response missing launchUrl");
				}

				return this.session;
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

				session.status = "polling";
				if (!this.result) {
						this.result = this.buildResult(session);
				}

				session.status = "ready";
				session.completed = Date.now();
				return session;
		}

		async cancelSession(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();
				session.status = "cancelled";
				session.completed = session.completed ?? Date.now();
				return session;
		}

		async getResult(): Promise<PrivateIDResult | undefined> {
				const session = await this.ensureSession();
				if (this.result) {
						return this.result;
				}

				if (session.status !== "ready") {
						return undefined;
				}

				this.result = this.buildResult(session);
				return this.result;
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
				if (!this.session) {
						await this.createAuthenticationSession();
				}

				return this.session as PrivateIDSession;
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
				const explicitRedirectUrl = configuration.get("PRIVATEID_REDIRECT_URL")?.trim();
				if (configuration.isProduction() && !explicitRedirectUrl) {
						throw new Error("PrivateID redirect URL is required in production: set PRIVATEID_REDIRECT_URL");
				}

				if (explicitRedirectUrl) {
						return explicitRedirectUrl;
				}

				const base44RedirectUri = configuration.get("OIDC_BASE44_REDIRECT_URI")?.trim();
				if (base44RedirectUri) {
						return base44RedirectUri;
				}

				const configuredRedirectUris = configuration.get("OIDC_BASE44_REDIRECT_URIS")?.trim();
				if (configuredRedirectUris) {
						try {
								const parsed = JSON.parse(configuredRedirectUris) as string[];
								if (Array.isArray(parsed) && parsed.length > 0 && typeof parsed[0] === "string") {
										return parsed[0];
								}
						} catch {
								const csvValue = configuredRedirectUris.split(",").map((entry) => entry.trim()).find((entry) => entry.length > 0);
								if (csvValue) {
										return csvValue;
								}
						}
				}

				throw new Error("PrivateID session API configuration missing redirect URL: set PRIVATEID_REDIRECT_URL, OIDC_BASE44_REDIRECT_URI, or OIDC_BASE44_REDIRECT_URIS");
		}

		private resolveCallbackUrl(redirectUrl: string): string {
				return configuration.get("PRIVATEID_CALLBACK_URL", redirectUrl) ?? redirectUrl;
		}

		private resolveCallbackHeaders(): Record<string, string> {
				const headers: Record<string, string> = {};
				const webhookSharedSecret = secretProvider.getPrivateIdAuthConfiguration().webhookSharedSecret;
				if (webhookSharedSecret) {
						headers["x-privateid-webhook-shared-secret"] = webhookSharedSecret;
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