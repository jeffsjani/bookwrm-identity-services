import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import type { PrivateIDSession, PrivateIDSessionStatus } from "./PrivateIDSession.js";

export class PrivateIDClient {
		private session?: PrivateIDSession;
		private result?: unknown;

		async initialize(): Promise<PrivateIDSession> {
				const now = Date.now();
				this.session = {
						sessionId: randomUUID(),
						transactionId: randomUUID(),
						status: "initialized",
						launchUrl: configuration.get("PRIVATEID_LAUNCH_URL", "https://privateid.local/launch") ?? "https://privateid.local/launch",
						expires: now + configuration.getNumber("PRIVATEID_SESSION_TTL_MS", 300_000)
				};

				return this.session;
		}

		async launch(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();
				session.status = "launching";
				return session;
		}

		async identify(): Promise<PrivateIDSession> {
				const session = await this.ensureSession();
				session.status = "polling";
				if (!session.result) {
						session.result = this.buildResult(session);
				}
				return session;
		}

		async getStatus(): Promise<PrivateIDSessionStatus> {
				const session = await this.ensureSession();
				if (session.expires <= Date.now()) {
						session.status = "expired";
				}
				return session.status;
		}

		async cancel(): Promise<void> {
				const session = await this.ensureSession();
				session.status = "cancelled";
		}

		async getResult(): Promise<unknown> {
				const session = await this.ensureSession();
				return session.result ?? this.result;
		}

		private async ensureSession(): Promise<PrivateIDSession> {
				if (!this.session) {
						await this.initialize();
				}

				return this.session as PrivateIDSession;
		}

		private buildResult(session: PrivateIDSession): unknown {
				const fallbackEmail = configuration.get("PRIVATEID_FALLBACK_EMAIL", "privateid.user@bookwrm.local");
				const fallbackName = configuration.get("PRIVATEID_FALLBACK_NAME", "PrivateID User");

				return {
						id: session.sessionId,
						sub: session.transactionId,
						email: fallbackEmail,
						name: fallbackName
				};
		}
}