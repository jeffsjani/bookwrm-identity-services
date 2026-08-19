import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticationProvider, AuthenticatedUser, AuthenticationStatus, PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import { extractIdentityCandidateFromRawResponse, resolveAuthenticatedUserFromPrivateId } from "../identity/PrivateIdIdentityResolver.js";
import { PrivateIDClient, type PrivateIDCallbackPayload } from "./PrivateIDClient.js";
import type { PrivateIDResult } from "./PrivateIDResult.js";
import type { PrivateIDSession } from "./PrivateIDSession.js";
import { getPrivateIDAuthenticatedUser, storePendingAuthorizationRequest, storePrivateIDAuthenticatedUser } from "./PrivateIDSessionStore.js";
import { linkPrivateIdSession } from "../oidc/CorrelationStore.js";

function sleep(ms: number): Promise<void> {
		return new Promise((resolve) => setTimeout(resolve, ms));
}

export class PrivateIDAuthenticationProvider implements AuthenticationProvider {
		private readonly client = new PrivateIDClient();
		private statusSnapshot: AuthenticationStatus = { state: "idle" };
		private pendingAuthorizationContext?: PendingAuthorizationContext;

		setPendingAuthorizationContext(context: PendingAuthorizationContext): void {
				this.pendingAuthorizationContext = context;
		}

		// Used by the OIDC /authorize flow: creates the session and persists the pending context without polling for completion.
		async beginAsyncAuthentication(correlationId: string): Promise<{ launchUrl: string; sessionId: string }> {
				const session = await this.launchSession(correlationId);
				// Log the exact PrivateID sessionId to compare against incoming webhook sessionIds.
				console.info("[PrivateID] beginAsyncAuthentication sessionId", { sessionId: session.sessionId, transactionId: session.transactionId, correlationId });
				return { launchUrl: session.launchUrl, sessionId: session.sessionId };
		}

		async completeCallback(payload: PrivateIDCallbackPayload): Promise<{ session: PrivateIDSession; user: AuthenticatedUser; result?: PrivateIDResult; }> {
				const session = await this.client.handleCallback(payload);
				const result = await this.client.getResult();

				const user = await this.returnResult(result, session);
				this.statusSnapshot = { state: "ready", sessionId: session.sessionId };
				return { session, user, result: result ?? undefined };
		}

		async authenticate(): Promise<AuthenticatedUser> {
				const session = await this.launchSession();
				await this.waitForSession(session);

				const timeoutMs = configuration.getNumber("PRIVATEID_POLL_TIMEOUT_MS", 30_000);
				const pollIntervalMs = configuration.getNumber("PRIVATEID_POLL_INTERVAL_MS", 1000);
				const result = await this.pollForResult(session, timeoutMs, pollIntervalMs);
				return await this.returnResult(result, session);
		}

		private async launchSession(correlationId?: string): Promise<PrivateIDSession> {
				this.statusSnapshot = { state: "initializing" };
				const session = await this.client.createAuthenticationSession(correlationId);
				if (this.pendingAuthorizationContext) {
						storePendingAuthorizationRequest(session.sessionId, this.pendingAuthorizationContext);
						this.pendingAuthorizationContext = undefined;
				}
				if (correlationId) {
						linkPrivateIdSession(correlationId, session.sessionId);
				}
				this.statusSnapshot = { state: "waiting", sessionId: session.sessionId };
				return session;
		}

		private async waitForSession(session: PrivateIDSession): Promise<PrivateIDSession> {
				this.statusSnapshot = { state: "polling", sessionId: session.sessionId };
				return this.client.getSession();
		}

		private async pollForResult(session: PrivateIDSession, timeoutMs: number, pollIntervalMs: number): Promise<PrivateIDResult | undefined> {
				const startedAt = Date.now();

				while (Date.now() - startedAt < timeoutMs) {
						const sessionState = await this.client.pollSession();
						const status = sessionState.status;
						if (status === "ready") {
								this.statusSnapshot = { state: "ready", sessionId: session.sessionId };
								return this.client.getResult();
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

		private async returnResult(result: PrivateIDResult | undefined, session: PrivateIDSession): Promise<AuthenticatedUser> {
				const existingAuthenticatedUser = getPrivateIDAuthenticatedUser(session.sessionId);
				if (existingAuthenticatedUser) {
						return existingAuthenticatedUser;
				}

				const privateIdUserId = result?.privateIdUserId ?? session.sessionId;
				const candidate = extractIdentityCandidateFromRawResponse(result?.rawResponse);

				let authenticatedUser: AuthenticatedUser;
				try {
						authenticatedUser = await resolveAuthenticatedUserFromPrivateId(privateIdUserId, candidate);
				} catch (error) {
						this.statusSnapshot = {
								state: "failed",
								sessionId: session.sessionId,
								message: error instanceof Error ? error.message : "Identity resolution failed"
						};
						throw error;
				}

				storePrivateIDAuthenticatedUser(session.sessionId, authenticatedUser);
				return authenticatedUser;
		}

		async cancel(): Promise<void> {
				await this.client.cancelSession();
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