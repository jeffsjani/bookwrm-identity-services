import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";
import { randomUUID } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

import {
		APPLE_ISSUER,
		AppleIdentityTokenVerifier,
		toAppleLinkRequest
} from "../src/identity/federation/AppleIdentityTokenVerifier.js";
import { IdentityFederationService } from "../src/identity/IdentityFederationService.js";
import { InMemoryExternalIdentityRepository } from "../src/identity/InMemoryExternalIdentityRepository.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";

// HAPI ID V2-C Phase 3/5: Apple OIDC verification certification with SYNTHETIC keys and claims.
// No live Apple credentials, endpoints, or provider identities are involved anywhere.

const AUDIENCE = "com.hapi.id.dev-services";
const NONCE = "per-transaction-nonce-123";

let signingKey: CryptoKey | import("node:crypto").KeyObject;
let jwks: JSONWebKeySet;
let rogueKey: CryptoKey | import("node:crypto").KeyObject;

beforeAll(async () => {
		const pair = await generateKeyPair("RS256");
		signingKey = pair.privateKey;
		jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "apple-synthetic-1", alg: "RS256", use: "sig" }] };
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
		isPrivateEmail?: unknown;
		key?: typeof signingKey;
		alg?: string;
};

async function syntheticAppleToken(overrides: TokenOverrides = {}): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
				...(overrides.subject !== null ? { sub: overrides.subject ?? "001234.synthetic-apple-subject.5678" } : {}),
				...(overrides.nonce !== null ? { nonce: overrides.nonce ?? NONCE } : {}),
				...(overrides.email !== undefined ? { email: overrides.email } : {}),
				...(overrides.emailVerified !== undefined ? { email_verified: overrides.emailVerified } : {}),
				...(overrides.isPrivateEmail !== undefined ? { is_private_email: overrides.isPrivateEmail } : {}),
				auth_time: now - 5
		};
		return new SignJWT(payload)
				.setProtectedHeader({ alg: overrides.alg ?? "RS256", kid: "apple-synthetic-1" })
				.setIssuer(overrides.issuer ?? APPLE_ISSUER)
				.setAudience(overrides.audience ?? AUDIENCE)
				.setIssuedAt(now)
				.setExpirationTime(now + (overrides.expiresIn ?? 600))
				.sign(overrides.key ?? signingKey);
}

function buildVerifier() {
		return new AppleIdentityTokenVerifier({ expectedAudiences: [AUDIENCE], jwks });
}

describe("V2-C Apple identity-token verification (synthetic keys)", () => {
		it("accepts a valid token and returns the exact verified provider identity", async () => {
				const verifier = buildVerifier();
				const token = await syntheticAppleToken({ email: "user@example.com", emailVerified: "true" });

				const verified = await verifier.verify(token, { nonce: NONCE });
				expect(verified.provider).toBe("APPLE");
				expect(verified.providerIssuer).toBe(APPLE_ISSUER);
				expect(verified.providerSubject).toBe("001234.synthetic-apple-subject.5678");
				expect(verified.audience).toBe(AUDIENCE);
				expect(verified.email).toBe("user@example.com");
				// Apple's string-typed boolean claims are normalized.
				expect(verified.emailVerified).toBe(true);
				expect(verified.isPrivateRelayEmail).toBe(false);
				expect(verified.authTime).toBeDefined();
				// Evidence reference is a hash, never the token.
				expect(verified.evidenceReference).not.toContain(token.slice(0, 20));
		});

		it("flags Apple private relay addresses via claim and via relay domain", async () => {
				const verifier = buildVerifier();
				const byClaim = await verifier.verify(
						await syntheticAppleToken({ email: "abc123@example.com", isPrivateEmail: "true" }),
						{ nonce: NONCE });
				expect(byClaim.isPrivateRelayEmail).toBe(true);

				const byDomain = await verifier.verify(
						await syntheticAppleToken({ email: "xyz789@privaterelay.appleid.com" }),
						{ nonce: NONCE });
				expect(byDomain.isPrivateRelayEmail).toBe(true);
		});

		it("rejects a token from any other issuer", async () => {
				const verifier = buildVerifier();
				const token = await syntheticAppleToken({ issuer: "https://appleid.apple.com.evil.example" });
				await expect(verifier.verify(token, { nonce: NONCE }))
						.rejects.toMatchObject({ code: "wrong_issuer" });
		});

		it("rejects a token for a different audience", async () => {
				const verifier = buildVerifier();
				const token = await syntheticAppleToken({ audience: "com.other.app" });
				await expect(verifier.verify(token, { nonce: NONCE }))
						.rejects.toMatchObject({ code: "wrong_audience" });
		});

		it("rejects an expired token", async () => {
				const verifier = buildVerifier();
				const token = await syntheticAppleToken({ expiresIn: -60 });
				await expect(verifier.verify(token, { nonce: NONCE }))
						.rejects.toMatchObject({ code: "token_expired" });
		});

		it("rejects nonce mismatches, missing nonces, and transactions without an expected nonce", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify(await syntheticAppleToken({ nonce: "different-nonce" }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "nonce_mismatch" });
				await expect(verifier.verify(await syntheticAppleToken({ nonce: null }), { nonce: NONCE }))
						.rejects.toMatchObject({ code: "nonce_mismatch" });
				await expect(verifier.verify(await syntheticAppleToken(), { nonce: "" }))
						.rejects.toMatchObject({ code: "nonce_mismatch" });
		});

		it("rejects a token signed by a key outside Apple's JWKS", async () => {
				const verifier = buildVerifier();
				const token = await syntheticAppleToken({ key: rogueKey });
				await expect(verifier.verify(token, { nonce: NONCE }))
						.rejects.toMatchObject({ code: "invalid_signature" });
		});

		it("rejects a token without a subject", async () => {
				const verifier = buildVerifier();
				const token = await syntheticAppleToken({ subject: null });
				await expect(verifier.verify(token, { nonce: NONCE }))
						.rejects.toMatchObject({ code: "missing_subject" });
		});

		it("rejects garbage and empty tokens", async () => {
				const verifier = buildVerifier();
				await expect(verifier.verify("", { nonce: NONCE })).rejects.toMatchObject({ code: "invalid_token" });
				await expect(verifier.verify("not.a.jwt", { nonce: NONCE })).rejects.toMatchObject({ code: "invalid_token" });
		});
});

describe("V2-C verified Apple identities feeding the federation layer", () => {
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

		it("links a server-verified Apple identity and enforces provider-identity uniqueness", async () => {
				const verifier = buildVerifier();
				const { service, createSubject } = buildFederation();
				const owner = createSubject();
				const attacker = createSubject();

				const verified = await verifier.verify(await syntheticAppleToken(), { nonce: NONCE });
				const linked = await service.linkExternalIdentity(toAppleLinkRequest(owner.id, verified));
				expect(linked.status).toBe("linked");

				// Duplicate external identity: the same verified Apple subject can never link to a
				// second HAPI subject.
				const duplicate = await service.linkExternalIdentity(toAppleLinkRequest(attacker.id, verified));
				expect(duplicate.status).toBe("conflict");

				// Idempotent for the rightful owner.
				const again = await service.linkExternalIdentity(toAppleLinkRequest(owner.id, verified));
				expect(again.status).toBe("already_linked");
		});

		it("supports the revocation/relinking policy: unlink frees the provider identity for explicit relinking", async () => {
				const verifier = buildVerifier();
				const { service, createSubject } = buildFederation();
				const first = createSubject();
				const second = createSubject();

				const verified = await verifier.verify(await syntheticAppleToken(), { nonce: NONCE });
				const linked = await service.linkExternalIdentity(toAppleLinkRequest(first.id, verified));
				if (linked.status !== "linked") throw new Error("expected linked");

				const unlinked = await service.unlinkExternalIdentity({
						identitySubjectId: first.id,
						externalIdentityId: linked.externalIdentity.id
				});
				expect(unlinked.status).toBe("unlinked");

				// Relink the same (revoked) provider identity to a different subject -- explicit only.
				const relinked = await service.linkExternalIdentity(toAppleLinkRequest(second.id, verified));
				expect(relinked.status).toBe("linked");
		});

		it("never derives linking from email: two subjects sharing the Apple email never auto-link", async () => {
				const verifier = buildVerifier();
				const { service, createSubject } = buildFederation();
				const subjectA = createSubject();
				const subjectB = createSubject();

				// Two DIFFERENT Apple subjects carrying the same email address.
				const tokenA = await syntheticAppleToken({ subject: "001234.apple-subject-A", email: "shared@example.com" });
				const tokenB = await syntheticAppleToken({ subject: "001234.apple-subject-B", email: "shared@example.com" });
				const verifiedA = await verifier.verify(tokenA, { nonce: NONCE });
				const verifiedB = await verifier.verify(tokenB, { nonce: NONCE });

				expect((await service.linkExternalIdentity(toAppleLinkRequest(subjectA.id, verifiedA))).status).toBe("linked");
				// Both links succeed independently: the email overlap is invisible to the identity key.
				expect((await service.linkExternalIdentity(toAppleLinkRequest(subjectB.id, verifiedB))).status).toBe("linked");

				const aIdentities = await service.listExternalIdentities(subjectA.id);
				const bIdentities = await service.listExternalIdentities(subjectB.id);
				expect(aIdentities[0].providerSubject).toBe("001234.apple-subject-A");
				expect(bIdentities[0].providerSubject).toBe("001234.apple-subject-B");
		});
});
