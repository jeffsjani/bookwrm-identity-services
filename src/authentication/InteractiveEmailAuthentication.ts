import type { AuthorizedH1Client } from "../identity/H1ClientAuthority.js";
import type { EmailPrincipal } from "./email/EmailAuthenticationTypes.js";

export type InteractiveEmailAuthority = AuthorizedH1Client & { tenantName: string };

// H6 Universal Login adapter over the certified H4 engine. All operations run server-side with the
// authority bound to the Authorization Interaction; the H4 authentication result never reaches the browser.
export interface InteractiveEmailAuthentication {
	authority(clientId: string): Promise<InteractiveEmailAuthority>;
	start(authority: InteractiveEmailAuthority, email: string): Promise<{ challengeId: string; expiresIn: number; resendAfter: number }>;
	resend(authority: InteractiveEmailAuthority, challengeId: string): Promise<{ challengeId: string; expiresIn: number; resendAfter: number }>;
	verify(authority: InteractiveEmailAuthority, challengeId: string, code: string): Promise<{ authenticationResult: string }>;
	consumeResult(authority: InteractiveEmailAuthority, authenticationResult: string): Promise<EmailPrincipal>;
}
