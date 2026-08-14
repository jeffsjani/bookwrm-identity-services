export type AuthenticatedUser = {
		id: string;
		sub: string;
		email: string;
		emailVerified: boolean;
		name: string;
};

export type AuthenticationStatus = {
		state: "idle" | "initializing" | "waiting" | "polling" | "ready" | "cancelled" | "failed";
		sessionId?: string;
		message?: string;
};

export type PendingAuthorizationContext = {
		clientId: string;
		redirectUri: string;
		scope: string;
		nonce: string;
		codeChallenge: string;
		state?: string;
};

export type AsyncAuthenticationSession = {
		launchUrl: string;
		sessionId: string;
};

export interface AuthenticationProvider {
		authenticate(): Promise<AuthenticatedUser>;
		cancel(): Promise<void>;
		status(): Promise<AuthenticationStatus>;
		logout(): Promise<void>;
		setPendingAuthorizationContext?(context: PendingAuthorizationContext): void;
		// Non-blocking session creation used by the OIDC /authorize flow to avoid synchronous polling.
		beginAsyncAuthentication?(): Promise<AsyncAuthenticationSession>;
}