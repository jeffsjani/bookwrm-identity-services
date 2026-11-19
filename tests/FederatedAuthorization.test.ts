import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { AppleIdentityTokenVerifier, APPLE_ISSUER } from "../src/identity/federation/AppleIdentityTokenVerifier.js";
import {
		APPLE_AUTHORIZATION_ENDPOINT,
		APPLE_TOKEN_ENDPOINT,
		FederatedAuthorizationError,
		FederatedAuthorizationService,
		type AuthorizationCodeExchanger
} from "../src/identity/federation/FederatedAuthorizationService.js";
import {
		FEDERATION_TRANSACTION_TTL_MS,
		FederationTransactionStore
} from "../src/identity/federation/FederationTransactionStore.js";
import { getRedisClient } from "../src/oidc/infrastructure/RedisInfrastructure.js";
import { ensureOidcTestEnvironment } from "./oidcTestHarness.js";

// HAPI ID V2-D Phase 1/6: upstream authorization round-trip certification with synthetic
// transactions, codes, keys, and exchanger. No provider endpoint is ever contacted.

const AUDIENCE = "com.hapi.id.synthetic-services";
const REDIRECT_URI = "https://id.example.test/federation/apple/callback";

let signingKey: CryptoKey | import("node:crypto").KeyObject;
let jwks: JSONWebKeySet;

beforeAll(async () => {
		ensureOidcTestEnvironment();
		const pair = await generateKeyPair("RS256");
		signingKey = pair.privateKey;
		jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "apple-synthetic-1", alg: "RS256", use: "sig" }] };
});

async function appleToken(nonce: string, subject = "001234.synthetic.5678"): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({ sub: subject, nonce })
				.setProtectedHeader({ alg: "RS256", kid: "apple-synthetic-1" })
				.setIssuer(APPLE_ISSUER)
				.setAudience(AUDIENCE)
				.setIssuedAt(now)
				.setExpirationTime(now + 600)
				.sign(signingKey);
}

// Synthetic provider: redeems exactly one known code and mints an id_token bound to the nonce the
// test placed in the "provider session".
function syntheticExchanger(validCode: string, nonceForToken: () => string): AuthorizationCodeExchanger & { seen: URLSearchParams[] } {
		const seen: URLSearchParams[] = [];
		return {
				seen,
				async exchange(_endpoint: string, params: URLSearchParams) {
						seen.push(params);
						if (params.get("code") !== validCode) throw new Error("invalid_grant");
						return { idToken: await appleToken(nonceForToken()) };
				}
		};
}

function buildService(exchanger: AuthorizationCodeExchanger, store = new FederationTransactionStore()) {
		return {
				store,
				service: new FederatedAuthorizationService(
						{
								provider: "APPLE",
								clientId: AUDIENCE,
								redirectUri: REDIRECT_URI,
								scope: "name email",
								authorizationEndpoint: APPLE_AUTHORIZATION_ENDPOINT,
								tokenEndpoint: APPLE_TOKEN_ENDPOINT,
								responseMode: "form_post",
								clientSecret: async () => "synthetic-client-secret"
						},
						new AppleIdentityTokenVerifier({ expectedAudiences: [AUDIENCE], jwks }),
						store,
						exchanger
				)
		};
}

describe("V2-D federation transaction store", () => {
		it("creates single-use transactions with independent 256-bit state and nonce", async () => {
				const store = new FederationTransactionStore();
				const transaction = await store.create({ purpose: "login", provider: "APPLE", interactionHandle: "h1" });
				expect(transaction.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
				expect(transaction.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
				expect(transaction.state).not.toBe(transaction.nonce);
				expect(transaction.expiresAt - transaction.createdAt).toBe(FEDERATION_TRANSACTION_TTL_MS);

				// Raw state/id never appear as storage keys.
				const keys = await getRedisClient().keys("*federation_txn*");
				expect(keys.some((key) => key.includes(transaction.state) || key.includes(transaction.id))).toBe(false);
		});

		it("is single-use under concurrent consumption by state and never revives", async () => {
				const store = new FederationTransactionStore();
				const transaction = await store.create({ purpose: "login", provider: "APPLE" });
				const results = await Promise.all(Array.from({ length: 8 }, () => store.consumeByState(transaction.state)));
				expect(results.filter(Boolean)).toHaveLength(1);
				expect(await store.consumeByState(transaction.state)).toBeNull();
				expect(await store.consumeById(transaction.id)).toBeNull();
		});

		it("rejects forged, malformed, and expired states", async () => {
				let now = 1_000_000;
				const store = new FederationTransactionStore(getRedisClient(), 1_000, () => now);
				const transaction = await store.create({ purpose: "link", provider: "GOOGLE", identitySubjectId: "s1", sessionId: "sess1" });
				expect(await store.consumeByState("A".repeat(43))).toBeNull();
				expect(await store.consumeByState("not-a-state")).toBeNull();
				expect(await store.consumeByState(undefined)).toBeNull();
				now += 1_500;
				expect(await store.consumeByState(transaction.state)).toBeNull();
		});

		it("preserves the login/link binding fields verbatim", async () => {
				const store = new FederationTransactionStore();
				const login = await store.create({ purpose: "login", provider: "APPLE", interactionHandle: "handle-1" });
				const link = await store.create({ purpose: "link", provider: "GOOGLE", identitySubjectId: "subject-1", sessionId: "session-1" });
				expect(await store.consumeByState(login.state)).toMatchObject({ purpose: "login", interactionHandle: "handle-1" });
				expect(await store.consumeById(link.id)).toMatchObject({
						purpose: "link", identitySubjectId: "subject-1", sessionId: "session-1" });
		});
});

describe("V2-D upstream authorization round-trip (synthetic provider)", () => {
		it("builds the provider authorization URL with exact registered values and server-generated state/nonce", async () => {
				const { service, store } = buildService(syntheticExchanger("unused", () => ""));
				const transaction = await store.create({ purpose: "login", provider: "APPLE", interactionHandle: "h" });
				const url = new URL(service.buildAuthorizationUrl(transaction));
				expect(`${url.origin}${url.pathname}`).toBe(APPLE_AUTHORIZATION_ENDPOINT);
				expect(url.searchParams.get("response_type")).toBe("code");
				expect(url.searchParams.get("client_id")).toBe(AUDIENCE);
				expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
				expect(url.searchParams.get("state")).toBe(transaction.state);
				expect(url.searchParams.get("nonce")).toBe(transaction.nonce);
				expect(url.searchParams.get("response_mode")).toBe("form_post");
		});

		it("completes a valid callback: consumes the state, exchanges the code server-side, verifies the nonce-bound token", async () => {
				let providerNonce = "";
				const exchanger = syntheticExchanger("code-1", () => providerNonce);
				const { service, store } = buildService(exchanger);
				const transaction = await store.create({ purpose: "login", provider: "APPLE", interactionHandle: "h" });
				providerNonce = transaction.nonce;

				const result = await service.handleCallback({ state: transaction.state, code: "code-1" });
				expect(result.verified.providerSubject).toBe("001234.synthetic.5678");
				expect(result.transaction.id).toBe(transaction.id);
				// The exchange carried the registered redirect_uri and the (synthetic) client secret.
				expect(exchanger.seen[0].get("redirect_uri")).toBe(REDIRECT_URI);
				expect(exchanger.seen[0].get("client_secret")).toBe("synthetic-client-secret");
				expect(exchanger.seen[0].get("grant_type")).toBe("authorization_code");

				// The state is burned: replaying the captured callback fails closed.
				await expect(service.handleCallback({ state: transaction.state, code: "code-1" }))
						.rejects.toMatchObject({ code: "invalid_state" });
		});

		it("rejects unknown and cross-provider states", async () => {
				const { service, store } = buildService(syntheticExchanger("c", () => ""));
				await expect(service.handleCallback({ state: "F".repeat(43), code: "c" }))
						.rejects.toMatchObject({ code: "invalid_state" });
				const google = await store.create({ purpose: "login", provider: "GOOGLE" });
				await expect(service.handleCallback({ state: google.state, code: "c" }))
						.rejects.toMatchObject({ code: "invalid_state" });
		});

		it("maps provider denial and errors to typed outcomes and still burns the transaction", async () => {
				const { service, store } = buildService(syntheticExchanger("c", () => ""));
				const denied = await store.create({ purpose: "login", provider: "APPLE" });
				await expect(service.handleCallback({ state: denied.state, error: "user_cancelled_authorize" }))
						.rejects.toMatchObject({ code: "provider_denied" });
				expect(await store.consumeByState(denied.state)).toBeNull();

				const failed = await store.create({ purpose: "login", provider: "APPLE" });
				await expect(service.handleCallback({ state: failed.state, error: "temporarily_unavailable" }))
						.rejects.toMatchObject({ code: "provider_error" });

				const missingCode = await store.create({ purpose: "login", provider: "APPLE" });
				await expect(service.handleCallback({ state: missingCode.state }))
						.rejects.toMatchObject({ code: "provider_error" });
		});

		it("fails closed on authorization-code replay/injection at the provider exchange", async () => {
				let providerNonce = "";
				const { service, store } = buildService(syntheticExchanger("real-code", () => providerNonce));
				const transaction = await store.create({ purpose: "login", provider: "APPLE" });
				providerNonce = transaction.nonce;
				// An attacker-injected (stolen or already-redeemed) code fails the server-side exchange.
				await expect(service.handleCallback({ state: transaction.state, code: "stolen-code" }))
						.rejects.toMatchObject({ code: "code_exchange_failed" });
		});

		it("rejects an exchanged token bound to a different transaction's nonce (callback injection)", async () => {
				const fixedNonce = "attacker-controlled-nonce";
				const { service, store } = buildService(syntheticExchanger("code-x", () => fixedNonce));
				const transaction = await store.create({ purpose: "login", provider: "APPLE" });
				await expect(service.handleCallback({ state: transaction.state, code: "code-x" }))
						.rejects.toMatchObject({ code: "verification_failed" });
		});

		it("never includes token or secret material in thrown errors", async () => {
				let providerNonce = "";
				const { service, store } = buildService(syntheticExchanger("code-1", () => providerNonce));
				const transaction = await store.create({ purpose: "login", provider: "APPLE" });
				const error = await service.handleCallback({ state: transaction.state, code: "wrong" })
						.then(() => undefined, (caught: unknown) => caught as Error);
				expect(error).toBeInstanceOf(FederatedAuthorizationError);
				expect(error!.message).not.toContain("wrong");
				expect(error!.message).not.toContain("synthetic-client-secret");
		});
});
