import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import type { PrivateIDResult } from "./PrivateIDResult.js";
import type { PrivateIDSession, PrivateIDSessionStatus } from "./PrivateIDSession.js";

export class PrivateIDClient {
		private session?: PrivateIDSession;
		private result?: PrivateIDResult;

		async createAuthenticationSession(): Promise<PrivateIDSession> {
				const now = Date.now();
				this.result = undefined;
				this.session = {
						sessionId: randomUUID(),
						transactionId: randomUUID(),
						status: "created",
						launchUrl: configuration.get("PRIVATEID_LAUNCH_URL", "https://privateid.local/launch") ?? "https://privateid.local/launch",
						expires: now + configuration.getNumber("PRIVATEID_SESSION_TTL_MS", 300_000),
						created: now
				};

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
}