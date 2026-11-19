import type { ExternalIdentityProvider } from "../../models/ExternalIdentity.js";

// HAPI ID V2-D: the single server-side verification result shape shared by every upstream
// provider (Apple, Google). providerIssuer + providerSubject form the ONLY identity key ever
// handed to the federation layer; email is carried exclusively as display/contact metadata and
// can never link, merge, or resolve accounts.
export type VerifiedFederatedIdentity = {
		provider: ExternalIdentityProvider;
		providerIssuer: string;
		providerSubject: string;
		audience: string;
		email?: string;
		emailVerified?: boolean;
		// Apple private relay forwarding aliases; always false for providers without relay addresses.
		isPrivateRelayEmail: boolean;
		authTime?: number;
		expiresAt: number;
		// SHA-256 of the raw identity token: a non-reversible audit reference; the raw token is
		// never stored or logged.
		evidenceReference: string;
};

// Server-only verification of a provider id_token. Implementations MUST validate the JWKS
// signature, exact issuer, registered audience, expiration and the per-transaction nonce before
// returning any identity material. The browser can never supply a trusted provider subject.
export interface FederatedIdentityTokenVerifier {
		verify(identityToken: string, expectations: { nonce: string }): Promise<VerifiedFederatedIdentity>;
}
