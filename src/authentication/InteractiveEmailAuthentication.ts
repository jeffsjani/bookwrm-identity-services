import type { AuthorizedH1Client } from "../identity/H1ClientAuthority.js";
import type { EmailPrincipal } from "./email/EmailAuthenticationTypes.js";

export type InteractiveEmailAuthority = AuthorizedH1Client & { tenantName: string };
export type InteractiveEmailMode = "AUTHENTICATION" | "REGISTRATION" | "INELIGIBLE";
export type InteractiveEmailVerification =
	| { mode: "AUTHENTICATION"; authenticationResult: string }
	| { mode: "REGISTRATION"; principal: EmailPrincipal };

// H6 Universal Login adapter over the certified H4 engine. All operations run server-side with the
// authority bound to the Authorization Interaction; the H4 authentication result never reaches the browser.
export interface InteractiveEmailAuthentication {
	authority(clientId: string): Promise<InteractiveEmailAuthority>;
	start(authority: InteractiveEmailAuthority, email: string): Promise<{
		challengeId: string; expiresIn: number; resendAfter: number; mode: InteractiveEmailMode
	}>;
	resend(authority: InteractiveEmailAuthority, challengeId: string, mode: InteractiveEmailMode): Promise<{
		challengeId: string; expiresIn: number; resendAfter: number
	}>;
	verify(authority: InteractiveEmailAuthority, challengeId: string, code: string, mode: InteractiveEmailMode): Promise<InteractiveEmailVerification>;
	consumeResult(authority: InteractiveEmailAuthority, authenticationResult: string): Promise<EmailPrincipal>;
}
