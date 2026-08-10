export type AuthenticatedUser = {
		id: string;
		sub: string;
		email: string;
		name: string;
};

export type AuthenticationStatus = {
		state: "idle" | "initializing" | "waiting" | "polling" | "ready" | "cancelled" | "failed";
		sessionId?: string;
		message?: string;
};

export interface AuthenticationProvider {
		authenticate(): Promise<AuthenticatedUser>;
		cancel(): Promise<void>;
		status(): Promise<AuthenticationStatus>;
		logout(): Promise<void>;
}