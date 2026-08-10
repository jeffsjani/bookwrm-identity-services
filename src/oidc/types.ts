export type OIDCLogEntry = {
		requestId: string;
		clientId: string;
		flow: string;
		latency: number;
		success: boolean;
		error: string;
		user: string;
		pkce: string;
		correlationId: string;
};
