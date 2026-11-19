import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";
import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { configuration } from "../src/config/ConfigurationService.js";
import { AppleIdentityTokenVerifier, APPLE_ISSUER } from "../src/identity/federation/AppleIdentityTokenVerifier.js";
import { GoogleIdentityTokenVerifier, GOOGLE_ISSUER } from "../src/identity/federation/GoogleIdentityTokenVerifier.js";
import { FederationTransactionStore } from "../src/identity/federation/FederationTransactionStore.js";
import { IdentityFederationService } from "../src/identity/IdentityFederationService.js";
import { InMemoryExternalIdentityRepository } from "../src/identity/InMemoryExternalIdentityRepository.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { HapiSessionService, HAPI_SESSION_COOKIE } from "../src/identity/sessions/HapiSessionService.js";
import { InMemoryHapiSessionRepository } from "../src/identity/sessions/InMemoryHapiSessionRepository.js";
import { InMemoryRefreshTokenFamilyRepository } from "../src/oidc/refresh/InMemoryRefreshTokenFamilyRepository.js";
import { RefreshTokenRotationService } from "../src/oidc/refresh/RefreshTokenRotationService.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";
import {
		HAPI_CSRF_HEADER,
		RECENT_AUTHENTICATION_MAX_AGE_MS,
		registerAccountAuthenticationMethodRoutes
} from "../src/routes/accountAuthenticationMethods.js";
import { ensureOidcTestEnvironment } from "./oidcTestHarness.js";

// HAPI ID V2-D Phases 3/6: authenticated account-linking API certification (V2-C Phase 4 design).
// All provider tokens, keys, sessions, and subjects are synthetic.

const APPLE_CLIENT = "com.hapi.id.synthetic";
const GOOGLE_CLIENT = "synthetic.apps.googleusercontent.com";

let appleKey: CryptoKey | import("node:crypto").KeyObject;
let appleJwks: JSONWebKeySet;
let googleKey: CryptoKey | import("node:crypto").KeyObject;
let googleJwks: JSONWebKeySet;

beforeAll(async () => {
		ensureOidcTestEnvironment();
		const apple = await generateKeyPair("RS256");
		appleKey = apple.privateKey;
		appleJwks = { keys: [{ ...(await exportJWK(apple.publicKey)), kid: "a1", alg: "RS256", use: "sig" }] };
		const google = await generateKeyPair("RS256");
		googleKey = google.privateKey;
		googleJwks = { keys: [{ ...(await exportJWK(google.publicKey)), kid: "g1", alg: "RS256", use: "sig" }] };
});

function setFlag(value: boolean | undefined): void {
		if (value === undefined) delete process.env.HAPI_ACCOUNT_LINKING_API_ENABLED;
		else process.env.HAPI_ACCOUNT_LINKING_API_ENABLED = String(value);
		configuration.reload();
}

async function appleToken(nonce: string, subject = "001234.linked.5678", email?: string): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({ sub: subject, nonce, ...(email ? { email, email_verified: "true" } : {}) })
				.setProtectedHeader({ alg: "RS256", kid: "a1" })
				.setIssuer(APPLE_ISSUER).setAudience(APPLE_CLIENT)
				.setIssuedAt(now).setExpirationTime(now + 600).sign(appleKey);
}

async function googleToken(nonce: string, subject = "110000000000000000009"): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({ sub: subject, nonce })
				.setProtectedHeader({ alg: "RS256", kid: "g1" })
				.setIssuer(GOOGLE_ISSUER).setAudience(GOOGLE_CLIENT)
				.setIssuedAt(now).setExpirationTime(now + 600).sign(googleKey);
}

async function linkingFixture() {
		ensureOidcTestEnvironment();
		setFlag(true);
		let now = Date.now();
		const clock = () => new Date(now);
		const subjects = new InMemoryIdentitySubjectRepository();
		const externalRepository = new InMemoryExternalIdentityRepository(async (id) => subjects.findById(id));
		const federation = new IdentityFederationService(externalRepository);
		const sessionRepository = new InMemoryHapiSessionRepository();
		const sessions = new HapiSessionService(sessionRepository, undefined, clock);
		const transactions = new FederationTransactionStore();
		const refreshRepository = new InMemoryRefreshTokenFamilyRepository();
		const refreshRotation = new RefreshTokenRotationService(refreshRepository, undefined, clock);

		const app: FastifyInstance = Fastify();
		await registerAccountAuthenticationMethodRoutes(app, {
				sessions,
				federation,
				transactions,
				refreshRotation,
				verifiers: {
						APPLE: new AppleIdentityTokenVerifier({ expectedAudiences: [APPLE_CLIENT], jwks: appleJwks }),
						GOOGLE: new GoogleIdentityTokenVerifier({ expectedAudiences: [GOOGLE_CLIENT], jwks: googleJwks })
				}
		});
		await app.ready();

		const createSubject = (overrides: Partial<IdentitySubject> = {}) => subjects.create({
				id: randomUUID(), oidcSubject: randomUUID(), primaryProvider: "HAPI_EMAIL",
				primaryProviderSubject: "member@example.com", email: "member@example.com",
				emailVerified: true, status: "ACTIVE", ...overrides });

		const authenticatedSession = async (identitySubjectId: string) => {
				const established = await sessions.establishSession({ identitySubjectId, authenticationMethod: "HAPI_EMAIL" });
				return {
						session: established.session,
						headers: {
								cookie: `${HAPI_SESSION_COOKIE}=${established.sessionToken}`,
								[HAPI_CSRF_HEADER]: established.csrfToken
						}
				};
		};

		return { app, subjects, federation, externalRepository, sessions, sessionRepository, transactions,
				refreshRotation, refreshRepository, createSubject, authenticatedSession,
				advance: (ms: number) => { now += ms; } };
}

type Fixture = Awaited<ReturnType<typeof linkingFixture>>;

async function startLink(f: Fixture, headers: Record<string, string>, provider = "APPLE") {
		const response = await f.app.inject({ method: "POST", url: "/account/authentication-methods/link",
				headers, payload: { provider } });
		return response;
}

async function completeLink(f: Fixture, headers: Record<string, string>, transactionId: string, identityToken: string) {
		return f.app.inject({ method: "POST", url: "/account/authentication-methods/link/complete",
				headers, payload: { transactionId, identityToken } });
}

afterEach(() => setFlag(undefined));

describe("V2-D authenticated account-linking API", () => {
		it("is entirely absent behind the default-off flag", async () => {
				const f = await linkingFixture();
				setFlag(undefined);
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				for (const [method, url] of [["GET", "/account/authentication-methods"],
						["POST", "/account/authentication-methods/link"],
						["POST", "/account/authentication-methods/link/complete"],
						["DELETE", `/account/authentication-methods/${randomUUID()}`]] as const) {
						const response = await f.app.inject({ method, url, headers,
								...(method === "POST" ? { payload: {} } : {}) });
						expect(response.statusCode, `${method} ${url}`).toBe(404);
				}
		});

		it("rejects unauthenticated, unknown, and stale sessions before anything else", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();

				const anonymous = await f.app.inject({ method: "GET", url: "/account/authentication-methods" });
				expect(anonymous.statusCode).toBe(401);
				expect(JSON.parse(anonymous.body).error).toBe("authentication_required");

				const unknown = await f.app.inject({ method: "GET", url: "/account/authentication-methods",
						headers: { cookie: `${HAPI_SESSION_COOKIE}=hsid_forged` } });
				expect(unknown.statusCode).toBe(401);

				// Revoked (stale) session.
				const { session, headers } = await f.authenticatedSession(subject.id);
				await f.sessions.revokeSession(subject.id, session.id);
				const stale = await f.app.inject({ method: "GET", url: "/account/authentication-methods", headers });
				expect(stale.statusCode).toBe(401);
				expect(JSON.parse(stale.body).error).toBe("stale_session");

				// Expired session.
				const second = await f.authenticatedSession(subject.id);
				f.advance(91 * 24 * 60 * 60 * 1000);
				const expired = await f.app.inject({ method: "GET", url: "/account/authentication-methods", headers: second.headers });
				expect(expired.statusCode).toBe(401);
				expect(JSON.parse(expired.body).error).toBe("stale_session");
		});

		it("lists methods including the derived HAPI_EMAIL method with recent-authentication context", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				const response = await f.app.inject({ method: "GET", url: "/account/authentication-methods", headers });
				expect(response.statusCode).toBe(200);
				const body = JSON.parse(response.body);
				expect(body.methods).toHaveLength(1);
				expect(body.methods[0]).toMatchObject({ type: "HAPI_EMAIL", status: "verified", derived: true });
				expect(body.canUnlink[body.methods[0].id]).toBe(false);
				expect(body.recentAuthentication).toMatchObject({ satisfied: true, maxAgeSeconds: 600 });
		});

		it("enforces the double-submit CSRF header on every mutation", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				const noCsrf = { cookie: headers.cookie };
				const wrongCsrf = { cookie: headers.cookie, [HAPI_CSRF_HEADER]: "hcsrf_forged" };
				for (const candidate of [noCsrf, wrongCsrf]) {
						const started = await startLink(f, candidate as Record<string, string>);
						expect(started.statusCode).toBe(403);
						expect(JSON.parse(started.body).error).toBe("csrf_invalid");
						const unlinked = await f.app.inject({ method: "DELETE",
								url: `/account/authentication-methods/${randomUUID()}`, headers: candidate as Record<string, string> });
						expect(unlinked.statusCode).toBe(403);
				}
		});

		it("requires recent authentication (step-up) for start, complete, and unlink", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				f.advance(RECENT_AUTHENTICATION_MAX_AGE_MS + 1_000);
				for (const response of [
						await startLink(f, headers),
						await completeLink(f, headers, randomUUID(), "x"),
						await f.app.inject({ method: "DELETE", url: `/account/authentication-methods/${randomUUID()}`, headers })
				]) {
						expect(response.statusCode).toBe(428);
						expect(JSON.parse(response.body)).toMatchObject({ error: "step_up_required", maxAgeSeconds: 600 });
				}
				// Listing still works without step-up, and reports the stale auth honestly.
				const listed = await f.app.inject({ method: "GET", url: "/account/authentication-methods", headers });
				expect(listed.statusCode).toBe(200);
				expect(JSON.parse(listed.body).recentAuthentication.satisfied).toBe(false);
		});

		it("links Apple end-to-end: single-use nonce-bound transaction, server-side verification, audit", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);

				const started = await startLink(f, headers);
				expect(started.statusCode, started.body).toBe(200);
				const transaction = JSON.parse(started.body);
				expect(transaction.transactionId).toBeDefined();
				expect(transaction.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
				expect(transaction.authorizationParameters.provider).toBe("APPLE");

				const completed = await completeLink(f, headers, transaction.transactionId,
						await appleToken(transaction.nonce, "001234.linked.5678", "user@privaterelay.appleid.com"));
				expect(completed.statusCode, completed.body).toBe(200);
				const body = JSON.parse(completed.body);
				const appleMethod = body.methods.find((method: { type: string }) => method.type === "APPLE");
				expect(appleMethod).toMatchObject({ status: "linked" });
				expect(body.canUnlink[appleMethod.id]).toBe(true);

				// Transactionally audited by the V2-B repository.
				const audit = await f.federation.listLinkAudit(subject.id);
				expect(audit).toHaveLength(1);
				expect(audit[0]).toMatchObject({ action: "LINK", outcome: "SUCCEEDED", provider: "APPLE" });
				// Raw token material never persisted: evidence is a 43-char hash reference.
				expect(audit[0].evidenceReference).toMatch(/^[A-Za-z0-9_-]{43}$/);

				// The transaction is single-use: replaying the completion fails.
				const replayed = await completeLink(f, headers, transaction.transactionId,
						await appleToken(transaction.nonce));
				expect(replayed.statusCode).toBe(400);
				expect(JSON.parse(replayed.body).error).toBe("invalid_transaction");
		});

		it("rejects provider tokens that fail verification, without echoing claim details", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				for (const forgedToken of [
						await appleToken("some-other-nonce"),
						"not.a.jwt",
						await googleToken("irrelevant")
				]) {
						const started = await startLink(f, headers);
						const { transactionId, nonce } = JSON.parse(started.body);
						void nonce;
						const completed = await completeLink(f, headers, transactionId, forgedToken);
						expect(completed.statusCode).toBe(400);
						const body = JSON.parse(completed.body);
						expect(body.error).toBe("provider_verification_failed");
						expect(JSON.stringify(body)).not.toContain("nonce");
						// Each failure consumed its transaction (single-use even on failure).
						const retried = await completeLink(f, headers, transactionId, await appleToken("x"));
						expect(JSON.parse(retried.body).error).toBe("invalid_transaction");
				}
		});

		it("never accepts browser-supplied issuer/subject fields as evidence", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				const started = await startLink(f, headers);
				const { transactionId } = JSON.parse(started.body);
				// A client claiming a provider identity directly -- no identityToken -- is rejected
				// outright; the only accepted evidence is a verifiable provider token.
				const asserted = await f.app.inject({ method: "POST", url: "/account/authentication-methods/link/complete",
						headers, payload: { transactionId, issuer: APPLE_ISSUER, subject: "001234.victim.9999",
								providerSubject: "001234.victim.9999" } });
				expect(asserted.statusCode).toBe(400);
				expect(JSON.parse(asserted.body).error).toBe("invalid_request");
				expect(await f.federation.listExternalIdentities(subject.id)).toHaveLength(0);
		});

		it("binds linking transactions to the exact subject AND session (cross-user/cross-session rejection)", async () => {
				const f = await linkingFixture();
				const alice = await f.createSubject({ primaryProviderSubject: "alice@example.com", email: "alice@example.com" });
				const bob = await f.createSubject({ primaryProviderSubject: "bob@example.com", email: "bob@example.com" });
				const aliceAuth = await f.authenticatedSession(alice.id);
				const bobAuth = await f.authenticatedSession(bob.id);

				// Bob cannot complete Alice's transaction, even with a perfectly valid provider token.
				const started = await startLink(f, aliceAuth.headers);
				const { transactionId, nonce } = JSON.parse(started.body);
				const hijacked = await completeLink(f, bobAuth.headers, transactionId, await appleToken(nonce));
				expect(hijacked.statusCode).toBe(400);
				expect(JSON.parse(hijacked.body).error).toBe("invalid_transaction");
				expect(await f.federation.listExternalIdentities(bob.id)).toHaveLength(0);
				expect(await f.federation.listExternalIdentities(alice.id)).toHaveLength(0);

				// A transaction minted under a different session of the SAME subject is also unusable.
				const secondSession = await f.authenticatedSession(alice.id);
				const other = await startLink(f, secondSession.headers);
				const otherTransaction = JSON.parse(other.body);
				const crossSession = await completeLink(f, aliceAuth.headers, otherTransaction.transactionId,
						await appleToken(otherTransaction.nonce));
				expect(crossSession.statusCode).toBe(400);
		});

		it("detects already-linked providers and cross-account conflicts without revealing the owner", async () => {
				const f = await linkingFixture();
				const owner = await f.createSubject({ primaryProviderSubject: "owner@example.com", email: "owner@example.com" });
				const intruder = await f.createSubject({ primaryProviderSubject: "intruder@example.com", email: "intruder@example.com" });
				const ownerAuth = await f.authenticatedSession(owner.id);
				const intruderAuth = await f.authenticatedSession(intruder.id);

				// Owner links the Apple identity.
				const started = await startLink(f, ownerAuth.headers);
				const { transactionId, nonce } = JSON.parse(started.body);
				expect((await completeLink(f, ownerAuth.headers, transactionId, await appleToken(nonce))).statusCode).toBe(200);

				// Owner cannot start a second APPLE link.
				const again = await startLink(f, ownerAuth.headers);
				expect(again.statusCode).toBe(409);
				expect(JSON.parse(again.body).error).toBe("provider_already_linked");

				// The intruder's attempt to link the SAME Apple identity conflicts; the response body
				// never identifies the owning account.
				const intruderStart = await startLink(f, intruderAuth.headers);
				const intruderTransaction = JSON.parse(intruderStart.body);
				const conflicted = await completeLink(f, intruderAuth.headers, intruderTransaction.transactionId,
						await appleToken(intruderTransaction.nonce));
				expect(conflicted.statusCode).toBe(409);
				const body = JSON.parse(conflicted.body);
				expect(body.error).toBe("provider_identity_in_use");
				expect(JSON.stringify(body)).not.toContain(owner.id);
				expect(JSON.stringify(body)).not.toContain(owner.oidcSubject);
		});

		it("handles concurrent completions of one transaction with exactly one winner", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				const started = await startLink(f, headers);
				const { transactionId, nonce } = JSON.parse(started.body);
				const token = await appleToken(nonce);
				const results = await Promise.all(Array.from({ length: 6 },
						() => completeLink(f, headers, transactionId, token)));
				expect(results.filter((response) => response.statusCode === 200)).toHaveLength(1);
				expect((await f.federation.listExternalIdentities(subject.id))
						.filter((identity) => identity.status === "linked")).toHaveLength(1);
		});

		it("unlinks safely: last-method protection, no existence oracle, session/token revocation", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { session, headers } = await f.authenticatedSession(subject.id);

				const started = await startLink(f, headers);
				const { transactionId, nonce } = JSON.parse(started.body);
				await completeLink(f, headers, transactionId, await appleToken(nonce));
				const identities = await f.federation.listExternalIdentities(subject.id);
				const externalIdentityId = identities[0].id;

				// Sessions and refresh families established through APPLE are revoked on unlink.
				const appleSession = await f.sessions.establishSession({
						identitySubjectId: subject.id, authenticationMethod: "APPLE" });
				const family = await f.refreshRotation.issueFamily({
						identitySubjectId: subject.id, clientId: "client", scope: "openid",
						clientProfile: "confidential_web", sessionId: appleSession.session.id });

				// Another subject's identity id (or garbage) is a plain 404: no existence oracle.
				const foreign = await f.app.inject({ method: "DELETE",
						url: `/account/authentication-methods/${randomUUID()}`, headers });
				expect(foreign.statusCode).toBe(404);

				const unlinked = await f.app.inject({ method: "DELETE",
						url: `/account/authentication-methods/${externalIdentityId}`, headers });
				expect(unlinked.statusCode, unlinked.body).toBe(200);
				expect(JSON.parse(unlinked.body).methods.find((method: { type: string }) => method.type === "APPLE")).toBeUndefined();
				const revokedSession = await f.sessionRepository.findById?.(appleSession.session.id)
						?? (await f.sessions.listSessions(subject.id)).find((candidate) => candidate.id === appleSession.session.id);
				expect(revokedSession?.status).toBe("revoked");
				expect((await f.refreshRotation.getFamily(family.family.id))?.status).toBe("revoked");
				// The current (email) session survives.
				expect((await f.sessions.listSessions(subject.id)).find((candidate) => candidate.id === session.id)?.status).toBe("active");
		});

		it("refuses to unlink the last usable sign-in method", async () => {
				const f = await linkingFixture();
				// A federated-only subject: no verified HAPI email fallback.
				const subject = await f.createSubject({ primaryProvider: "Apple",
						primaryProviderSubject: "001234.only.0001", email: undefined, emailVerified: undefined });
				const { headers } = await f.authenticatedSession(subject.id);
				const started = await startLink(f, headers);
				const { transactionId, nonce } = JSON.parse(started.body);
				await completeLink(f, headers, transactionId, await appleToken(nonce, "001234.only.0001"));
				const [identity] = await f.federation.listExternalIdentities(subject.id);

				const refused = await f.app.inject({ method: "DELETE",
						url: `/account/authentication-methods/${identity.id}`, headers });
				expect(refused.statusCode).toBe(409);
				expect(JSON.parse(refused.body).error).toBe("last_method");
				expect((await f.federation.listExternalIdentities(subject.id))[0].status).toBe("linked");
				const audit = await f.federation.listLinkAudit(subject.id);
				expect(audit.at(-1)).toMatchObject({ action: "UNLINK", outcome: "REJECTED_LAST_METHOD" });
		});

		it("links Google through the same registry with the same guarantees", async () => {
				const f = await linkingFixture();
				const subject = await f.createSubject();
				const { headers } = await f.authenticatedSession(subject.id);
				const started = await startLink(f, headers, "GOOGLE");
				expect(started.statusCode).toBe(200);
				const { transactionId, nonce } = JSON.parse(started.body);
				const completed = await completeLink(f, headers, transactionId, await googleToken(nonce));
				expect(completed.statusCode, completed.body).toBe(200);
				const body = JSON.parse(completed.body);
				expect(body.methods.map((method: { type: string }) => method.type).sort())
						.toEqual(["GOOGLE", "HAPI_EMAIL"]);
		});
});
