import type { AuthenticatedUser } from "../AuthenticationProvider.js";
import type { AuthorizedH1Client } from "../../identity/H1ClientAuthority.js";

export type EmailAuthenticationContext = AuthorizedH1Client;
export type EmailAuthenticationAuditType = "EMAIL_AUTHENTICATION_STARTED" |
	"EMAIL_AUTHENTICATION_VERIFIED" | "EMAIL_AUTHENTICATION_SUCCEEDED" |
	"EMAIL_AUTHENTICATION_FAILED" | "EMAIL_AUTHENTICATION_RATE_LIMITED";

export type EmailPrincipal = AuthenticatedUser & {
	authenticationMethod: "HAPI_EMAIL";
	authenticatedAt: string;
	assurance: "email_otp";
};

export interface EmailAuthenticationRepository {
	audit(context: EmailAuthenticationContext, type: EmailAuthenticationAuditType,
		challengeId: string | null, outcome: string): Promise<void>;
	establish(context: EmailAuthenticationContext, verificationId: string): Promise<{
		authenticated: true;
		subject: string;
		authenticationResult: string;
		expiresIn: number;
		authenticationMethod: "HAPI_EMAIL";
		authenticatedAt: string;
		assurance: "email_otp";
	}>;
	consumeResult(context: EmailAuthenticationContext, result: string): Promise<EmailPrincipal>;
}

export class EmailAuthenticationError extends Error {
	constructor(public readonly code = "AUTHENTICATION_FAILED", public readonly statusCode = 401) {
		super(code);
	}
}
