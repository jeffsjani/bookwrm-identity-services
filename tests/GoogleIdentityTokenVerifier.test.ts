import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";
import { randomUUID } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

import {
		GOOGLE_ISSUER,
		GOOGLE_LEGACY_ISSUER,
		GoogleIdentityTokenVerifier,
		toGoogleLinkRequest
} from "../src/identity/federation/GoogleIdentityTokenVerifier.js";
import { IdentityFederationService } from "../src/identity/IdentityFederationService.js";
import { InMemoryExternalIdentityRepository } from "../src/identity/InMemoryExternalIdentityRepository.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";

// HAPI ID V2-D Phase 2/6: Google OIDC verification certification with SYNTHETIC keys and claims.
// No live Google credentials, endpoints, or provider identities are involved anywhere.

const AUDIENCE = "synthetic-client.apps.googleusercontent.com";
const NONCE = "per-transaction-nonce-456";

let signingKey: CryptoKey | import("node:crypto").KeyObject;
let jwks: JSONWebKeySet;
let rogueKey: CryptoKey | import("node:crypto").KeyObject;

beforeAll(async () => {
		const pair = await generateKeyPair("RS256");
		signingKey = pair.privateKey;
		jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "google-synthetic-1", alg: "RS256", use: "sig" }] };
		rogueKey = (await generateKeyPair("RS256")).privateKey;
});

type TokenOverrides = {
		issuer?: string;
		audience?: string;
		subject?: string | null;
		nonce?: string | null;
		expiresIn?: number;
		email?: string;
		emailVerified?: unknown;
		hostedDomain?: string;
		key?: typeof signingKey;
};

async function syntheticGoogleToken(overrides: TokenOverrides = {}): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
				...(overrides.subject !== null ? { sub: overrides.subject ?? "110123456789012345678" } : {}),
				...(overrides.nonce !== null ? { nonce: overrides.nonce ?? NONCE } : {}),
				...(overrides.email !== undefined ? { email: overrides.email } : {}),
				...(overrides.emailVerified !== undefined ? { email_verified: overrides.emailVerified } : {}),
				...(overrides.hostedDomain !== undefined ? { hd: overrides.hostedDomain } : {}),
				auth_time: now - 5
		};
		return new SignJWT(payload)
				.setProtectedHeader({ alg: "RS256", kid: "google-synthetic-1" })
				.setIssuer(overrides.issuer ?? GOOGLE_ISSUER)
				.setAudience(overrides.audience ?? AUDIENCE)
				.setIssuedAt(now)
				.setExpirationTime(now + (overrides.expiresIn ?? 600))
				.sign(overrides.key ?? signingKey);
}

function buildVerifier() {
		return new GoogleIdentityTokenVerifier({ expectedAudiences: [AUDIENCE], jwks });
}

describe("V2-D Google identity-token verification (synthetic keys)", () => {
		it("accepts a valid token and returns the exact verified provider identity", async () => {
				const verifier = buildVerifier();
				const token = await syntheticGoogleToken({ email: "user@example.com", emailVerified: true, hostedDomain: "example.com" });

				const verified = await verifier.verify(token, { nonce: NONCE });
				expect(verified.provider).toBe("GOOGLE");
				expect(verified.providerIssuer).toBe(GOOGLE_ISSUER);
				expect(verified.providerSubject).toBe("110123456789012345678");
				expect(verified.audience).toBe(AUDIENCE);
				expect(verified.email).toBe("user@example.com");
				expect(verified.emailVerified).toBe(true);
				expect(verified.isPrivateRelayEmail).toBe(false);
				expect(verified.hostedDomain).toBe("example.com");
				// Evidence reference is a hash, never the token.
				expect(verified.evidenceReference).not.toContain(token.slice(0, 20));
		});

		it("accepts the legacy issuer form but always canonicalizes the identity key", async () => {
				const verifier = buildVerifier();
				const verified = await verifier.verify(
						await syntheticGoogleToken({ issuer: GOOGLE_LEGACY_ISSUER }), { nonce: NONCE });
				expect(verified.providerIssuer).toBe(GOOGLE_ISSUER);
		});

		it("never surfaces an unverified email, including string-typed claims", async () => {
				const verifier = buildVerifier();
				const unverified = await verifier.verify(
						await syntheticGoogleToken({ email: "spoof@example.com", emailVerified: false }), { nonce: NONCE });
				expect(unverified.email).toBeUndefined();
				expect(unverified.emailVerified).toBe(false);

				const missing = await verifier.verify(
						await syntheticGoogleToken({ email: "spoof@example.com" }), { nonce: NONCE });
				expect(missing.email).toBeUndefined();

				const stringTyped = await verifier.verify(
						await syntheticGoogleToken({ email: "ok@example.com", emailVerified: "true" }), { nonce: NONCE });
				expect(stringTyped.email).toBe("ok@example.com");
				expect(stringTyped.emailVerified).toBe(true);
		});

		it("rejects a token from any other issuer", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(
						await syntheticGoogleToken({ issuer: "https://accounts.google.com.evil.example" }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "wrong_issuer" });
		});

		it("rejects a token for a different audience", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(
						await syntheticGoogleToken({ audience: "other-client.apps.googleusercontent.com" }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "wrong_audience" });
		});

		it("rejects an expired token", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(await syntheticGoogleToken({ expiresIn: -60 }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "token_expired" });
		});

		it("rejects nonce mismatches, missing nonces, and transactions without an expected nonce", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(await syntheticGoogleToken({ nonce: "different-nonce" }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "nonce_mismatch" });
				await expect(verifier.verify(await syntheticGoogleToken({ nonce: null }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "nonce_mismatch" });
				await expect(verifier.verify(await syntheticGoogleToken(), { nonce: "" }))
						.rejects.toMatchObject({ code: "nonce_mismatch" });
		});

		it("rejects a token signed by a key outside Google's JWKS", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(await syntheticGoogleToken({ key: rogueKey }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "invalid_signature" });
		});

		it("rejects a token without a subject, garbage, and empty tokens", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(await syntheticGoogleToken({ subject: null }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "missing_subject" });
				await expect(verifier.verify("", { nonce: NONCE })).rejects.toMatchObject({ code: "invalid_token" });
				await expect(verifier.verify("not.a.jwt", { nonce: NONCE })).rejects.toMatchObject({ code: "invalid_token" });
		});
});

describe("V2-D verified Google identities feeding the federation layer", () => {
		function buildFederation() {
				const subjects = new Map<string, IdentitySubject>();
				const repository = new InMemoryExternalIdentityRepository(async (id) => subjects.get(id));
				const service = new IdentityFederationService(repository);
				const createSubject = (): IdentitySubject => {
						const id = randomUUID();
						const subject: IdentitySubject = {
								id,
								oidcSubject: randomUUID(),
								primaryProvider: "HAPI_EMAIL",
								primaryProviderSubject: `${id}@example.com`,
								email: `${id}@example.com`,
								emailVerified: true,
								status: "ACTIVE",
								createdAt: new Date().toISOString(),
								updatedAt: new Date().toISOString()
						};
						subjects.set(id, subject);
						return subject;
				};
				return { service, createSubject };
		}

		it("links a server-verified Google identity and enforces provider-identity uniqueness", async () => {
				const verifier = buildVerifier();
				const { service, createSubject } = buildFederation();
				const owner = createSubject();
				const attacker = createSubject();

				const verified = await verifier.verify(await syntheticGoogleToken(), { nonce: NONCE });
				expect((await service.linkExternalIdentity(toGoogleLinkRequest(owner.id, verified))).status).toBe("linked");
				expect((await service.linkExternalIdentity(toGoogleLinkRequest(attacker.id, verified))).status).toBe("conflict");
				expect((await service.linkExternalIdentity(toGoogleLinkRequest(owner.id, verified))).status).toBe("already_linked");
		});

		it("resolves Apple and Google through the same registry without ever matching by email", async () => {
				const verifier = buildVerifier();
				const { service, createSubject } = buildFederation();
				const subjectA = createSubject();
				const subjectB = createSubject();

				// Two DIFFERENT Google subjects carrying the same verified email address.
				const verifiedA = await verifier.verify(
						await syntheticGoogleToken({ subject: "110000000000000000001", email: "shared@example.com", emailVerified: true }),
						{ nonce: NONCE });
				const verifiedB = await verifier.verify(
						await syntheticGoogleToken({ subject: "110000000000000000002", email: "shared@example.com", emailVerified: true }),
						{ nonce: NONCE });

				expect((await service.linkExternalIdentity(toGoogleLinkRequest(subjectA.id, verifiedA))).status).toBe("linked");
				expect((await service.linkExternalIdentity(toGoogleLinkRequest(subjectB.id, verifiedB))).status).toBe("linked");

				expect((await service.listExternalIdentities(subjectA.id))[0].providerSubject).toBe("110000000000000000001");
				expect((await service.listExternalIdentities(subjectB.id))[0].providerSubject).toBe("110000000000000000002");
		});
});
