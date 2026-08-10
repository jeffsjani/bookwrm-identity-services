import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticationProvider, AuthenticatedUser, AuthenticationStatus } from "../authentication/AuthenticationProvider.js";
import { PrivateIDClient } from "./PrivateIDClient.js";

function sleep(ms: number): Promise<void> {
		return new Promise((resolve) => setTimeout(resolve, ms));
}

function toAuthenticatedUser(result: unknown, fallbackSessionId: string, fallbackTransactionId: string): AuthenticatedUser {
		if (result && typeof result === "object") {
				const candidate = result as Record<string, unknown>;
				const id = typeof candidate.id === "string" ? candidate.id : fallbackSessionId;
				const sub = typeof candidate.sub === "string" ? candidate.sub : fallbackTransactionId;
				const email = typeof candidate.email === "string" ? candidate.email : "privateid.user@bookwrm.local";
				const name = typeof candidate.name === "string" ? candidate.name : "PrivateID User";

				return { id, sub, email, name };
		}

		return {
				id: fallbackSessionId,
				sub: fallbackTransactionId,
				email: "privateid.user@bookwrm.local",
				name: "PrivateID User"
		};
}

export class PrivateIDAuthenticationProvider implements AuthenticationProvider {
		private readonly client = new PrivateIDClient();
		private statusSnapshot: AuthenticationStatus = { state: "idle" };

		async authenticate(): Promise<AuthenticatedUser> {
				this.statusSnapshot = { state: "initializing" };
				const session = await this.client.initialize();
				this.statusSnapshot = { state: "waiting", sessionId: session.sessionId };

				await this.client.launch();
				this.statusSnapshot = { state: "polling", sessionId: session.sessionId };

				const timeoutMs = configuration.getNumber("PRIVATEID_POLL_TIMEOUT_MS", 30_000);
				const pollIntervalMs = configuration.getNumber("PRIVATEID_POLL_INTERVAL_MS", 1000);
				const startedAt = Date.now();

				while (Date.now() - startedAt < timeoutMs) {
						await this.client.identify();
						const status = await this.client.getStatus();
						if (status === "ready") {
								const result = await this.client.getResult();
								this.statusSnapshot = { state: "ready", sessionId: session.sessionId };
								return toAuthenticatedUser(result, session.sessionId, session.transactionId);
						}

						if (status === "cancelled") {
								this.statusSnapshot = { state: "cancelled", sessionId: session.sessionId };
								throw new Error("PrivateID authentication was cancelled");
						}

						if (status === "failed" || status === "expired") {
								this.statusSnapshot = { state: "failed", sessionId: session.sessionId };
								throw new Error(`PrivateID authentication ended with status: ${status}`);
						}

						await sleep(pollIntervalMs);
				}

				this.statusSnapshot = { state: "failed", sessionId: session.sessionId, message: "PrivateID polling timed out" };
				throw new Error("PrivateID polling timed out");
		}

		async cancel(): Promise<void> {
				await this.client.cancel();
				this.statusSnapshot = { state: "cancelled" };
		}

		async status(): Promise<AuthenticationStatus> {
				const clientStatus = await this.client.getStatus();
				const mappedState: AuthenticationStatus["state"] =
						clientStatus === "created" || clientStatus === "initialized" || clientStatus === "launching"
								? "initializing"
								: clientStatus === "waiting"
									? "waiting"
									: clientStatus === "polling"
										? "polling"
										: clientStatus === "ready"
											? "ready"
											: clientStatus === "cancelled"
												? "cancelled"
												: "failed";
				return {
						state: mappedState,
						sessionId: this.statusSnapshot.sessionId,
						message: this.statusSnapshot.message
				};
		}

		async logout(): Promise<void> {
				await this.cancel();
		}
}