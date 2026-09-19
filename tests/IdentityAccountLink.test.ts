import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { storeCorrelation } from "../src/oidc/CorrelationStore.js";
import { PrivateIDAuthenticationProvider } from "../src/privateid/PrivateIDAuthenticationProvider.js";
import { resolvePrivateIDSessionRecord } from "../src/privateid/PrivateIDSessionStore.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import { inMemoryUserAuthenticatorRepository } from "../src/identity/InMemoryUserAuthenticatorRepository.js";
import type { PendingAuthorizationContext } from "../src/authentication/AuthenticationProvider.js";
import { buildOidcTestApp, exchangeAuthorizationCode, pkceChallengeFromVerifier } from "./oidcTestHarness.js";

const SERVICE_KEY = "hapi-platform-service-key";
const WEBHOOK_SECRET = "privateid-webhook-secret";

function decodeIdTokenPayload(idToken: string): Record<string, unknown> {
		const [, payloadB64] = idToken.split(".");
		return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
}

// Seeds an IdentitySubject the way PrivateIDEnrollmentService.completeEnrollment() currently does:
// no email/emailVerified at all -- reproducing the Release C5.1 investigation findings.
async function seedFaceLoginUserWithoutEmail() {
		const providerSubject = `puid-${randomUUID()}`;
		const subject = await identityRegistry.resolveOrCreate({
				provider: "PrivateID",
				providerSubject
		});
		await inMemoryUserAuthenticatorRepository.create({
				id: randomUUID(),
				userId: subject.id,
				provider: "privateid",
				providerSubject,
				authenticatorType: "face",
				status: "active"
		});
		return { subject, providerSubject };
}

async function driveOidcLoginToCode(app: Awaited<ReturnType<typeof buildOidcTestApp>>["app"], verifier: string, providerSubject: string) {
		const challenge = pkceChallengeFromVerifier(verifier);
		const pendingContext: PendingAuthorizationContext = {
				clientId: "base44-web",
				redirectUri: "https://example.com/callback",
				scope: "openid profile email",
				nonce: "account-link-nonce",
				codeChallenge: challenge
		};
		const correlationId = randomUUID();
		storeCorrelation(correlationId, pendingContext);

		const provider = new PrivateIDAuthenticationProvider();
		const { sessionId } = await provider.beginAsyncAuthentication(correlationId);
		const record = resolvePrivateIDSessionRecord(sessionId);
		if (!record) {
				throw new Error("Expected PrivateID session to be recorded after beginAsyncAuthentication");
		}

		const webhookResponse = await app.inject({
				method: "POST",
				url: "/privateid/webhook",
				headers: { "x-storythink-webhook-secret": WEBHOOK_SECRET },
				payload: {
						status: "SUCCESS",
						sessionId,
						transactionId: record.session.transactionId,
						puid: providerSubject
				}
		});
		if (webhookResponse.statusCode !== 200) {
				throw new Error(`Webhook failed: ${webhookResponse.statusCode} ${webhookResponse.body}`);
		}

		const callbackResponse = await app.inject({
				method: "GET",
				url: `/privateid/callback?reason=success&sessionId=${encodeURIComponent(sessionId)}&transactionId=${encodeURIComponent(record.session.transactionId)}`
		});
		if (callbackResponse.statusCode !== 302 || !callbackResponse.headers.location) {
				throw new Error(`Callback failed: ${callbackResponse.statusCode} ${callbackResponse.body}`);
		}

		const code = new URL(callbackResponse.headers.location as string).searchParams.get("code");
		if (!code) {
				throw new Error("Callback redirect missing code parameter");
		}

		return code;
}

describe("Release C5.1: Bookwrm account -> IdentitySubject link", () => {
		it("populates email/emailVerified and flows through to the ID Token and /userinfo", async () => {
				const { app } = await buildOidcTestApp();
				const { subject, providerSubject } = await seedFaceLoginUserWithoutEmail();
				const externalUserId = "6a1f25b6f6771ce75374f8ad";
				const verifier = "account-link-verifier-123456789";

				const code = await driveOidcLoginToCode(app, verifier, providerSubject);

				const linkResponse = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload: {
								source: "bookwrm",
								oidcSubject: subject.oidcSubject,
								email: "jeff@bookwrm.local",
								emailVerified: true
						}
				});
				expect(linkResponse.statusCode).toBe(201);
				const linkPayload = linkResponse.json() as Record<string, unknown>;
				expect(linkPayload.created).toBe(true);

				// IdentitySubject.id / oidcSubject / primaryProviderSubject / status are all preserved.
				const reloaded = await identityRegistry.findByOidcSubject(subject.oidcSubject);
				expect(reloaded?.id).toBe(subject.id);
				expect(reloaded?.oidcSubject).toBe(subject.oidcSubject);
				expect(reloaded?.primaryProviderSubject).toBe(providerSubject);
				expect(reloaded?.status).toBe("ACTIVE");
				expect(reloaded?.email).toBe("jeff@bookwrm.local");
				expect(reloaded?.emailVerified).toBe(true);

				const tokenResponse = await exchangeAuthorizationCode(app, code, verifier);
				expect(tokenResponse.statusCode).toBe(200);
				const tokens = tokenResponse.json() as Record<string, unknown>;
				const idTokenPayload = decodeIdTokenPayload(String(tokens.id_token));

				expect(idTokenPayload.sub).toBe(subject.oidcSubject);
				expect(idTokenPayload.email).toBe("jeff@bookwrm.local");
				expect(idTokenPayload.email_verified).toBe(true);

				const userInfoResponse = await app.inject({
						method: "GET",
						url: "/userinfo",
						headers: { authorization: `Bearer ${String(tokens.access_token)}` }
				});
				expect(userInfoResponse.statusCode).toBe(200);
				const userInfoPayload = userInfoResponse.json() as Record<string, unknown>;
				expect(userInfoPayload.sub).toBe(subject.oidcSubject);
				expect(userInfoPayload.email).toBe("jeff@bookwrm.local");
				expect(userInfoPayload.email_verified).toBe(true);

				await app.close();
		});

		it("is idempotent on repeat synchronization", async () => {
				const { app } = await buildOidcTestApp();
				const { subject } = await seedFaceLoginUserWithoutEmail();
				const externalUserId = `bookwrm-${randomUUID()}`;

				const payload = {
						source: "bookwrm",
						oidcSubject: subject.oidcSubject,
						email: "repeat@bookwrm.local",
						emailVerified: true
				};

				const first = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload
				});
				expect(first.statusCode).toBe(201);
				const firstLink = (first.json() as Record<string, unknown>).link as Record<string, unknown>;

				const second = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload
				});
				expect(second.statusCode).toBe(200);
				const secondPayload = second.json() as Record<string, unknown>;
				expect(secondPayload.created).toBe(false);
				const secondLink = secondPayload.link as Record<string, unknown>;
				expect(secondLink.id).toBe(firstLink.id);

				// No duplicate IdentitySubject / oidcSubject / authenticator was created by the repeat call.
				const subjects = await identityRegistry.listSubjects();
				const matchingOidcSubjects = subjects.filter((candidate) => candidate.oidcSubject === subject.oidcSubject);
				expect(matchingOidcSubjects).toHaveLength(1);

				await app.close();
		});

		it("rejects a conflicting link to a different IdentitySubject", async () => {
				const { app } = await buildOidcTestApp();
				const { subject: subjectA } = await seedFaceLoginUserWithoutEmail();
				const { subject: subjectB } = await seedFaceLoginUserWithoutEmail();
				const externalUserId = `bookwrm-${randomUUID()}`;

				const first = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload: { source: "bookwrm", oidcSubject: subjectA.oidcSubject, email: "conflict@bookwrm.local", emailVerified: true }
				});
				expect(first.statusCode).toBe(201);

				const conflicting = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload: { source: "bookwrm", oidcSubject: subjectB.oidcSubject, email: "conflict@bookwrm.local", emailVerified: true }
				});
				expect(conflicting.statusCode).toBe(409);

				// subjectB must not have been silently linked/merged.
				const reloadedB = await identityRegistry.findByOidcSubject(subjectB.oidcSubject);
				expect(reloadedB?.email).toBeUndefined();

				await app.close();
		});

		it("does not accept a PrivateID PUID as the account identifier and leaves the PUID unchanged", async () => {
				const { app } = await buildOidcTestApp();
				const { subject, providerSubject } = await seedFaceLoginUserWithoutEmail();

				// Attempting to smuggle the PrivateID PUID in as externalUserId is rejected: it must match the
				// trusted x-bookwrm-user-id header, and the header here is a genuine Bookwrm identifier, not the PUID.
				const response = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": "6a1f25b6f6771ce75374f8ad" },
						payload: {
								source: "bookwrm",
								externalUserId: providerSubject,
								oidcSubject: subject.oidcSubject,
								email: "puid-mismatch@bookwrm.local",
								emailVerified: true
						}
				});
				expect(response.statusCode).toBe(400);

				const reloaded = await identityRegistry.findByOidcSubject(subject.oidcSubject);
				expect(reloaded?.primaryProviderSubject).toBe(providerSubject);
				expect(reloaded?.email).toBeUndefined();

				await app.close();
		});

		it("does not set emailVerified=true unless the trusted caller explicitly asserts it", async () => {
				const { app } = await buildOidcTestApp();
				const { subject } = await seedFaceLoginUserWithoutEmail();
				const externalUserId = `bookwrm-${randomUUID()}`;

				const response = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { authorization: `Bearer ${SERVICE_KEY}`, "x-bookwrm-user-id": externalUserId },
						payload: { source: "bookwrm", oidcSubject: subject.oidcSubject, email: "unverified@bookwrm.local" }
				});
				expect(response.statusCode).toBe(201);

				const reloaded = await identityRegistry.findByOidcSubject(subject.oidcSubject);
				expect(reloaded?.email).toBe("unverified@bookwrm.local");
				expect(reloaded?.emailVerified).toBeFalsy();

				await app.close();
		});

		it("rejects requests without a valid service credential", async () => {
				const { app } = await buildOidcTestApp();
				const { subject } = await seedFaceLoginUserWithoutEmail();

				const response = await app.inject({
						method: "POST",
						url: "/internal/identity/account-link",
						headers: { "x-bookwrm-user-id": "bookwrm-123" },
						payload: { source: "bookwrm", oidcSubject: subject.oidcSubject, email: "no-auth@bookwrm.local", emailVerified: true }
				});
				expect(response.statusCode).toBe(401);

				await app.close();
		});
});
