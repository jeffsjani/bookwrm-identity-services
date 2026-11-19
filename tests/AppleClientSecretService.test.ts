import { generateKeyPairSync } from "node:crypto";
import { exportJWK, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";

import {
		APPLE_CLIENT_SECRET_AUDIENCE,
		AppleClientSecretService
} from "../src/identity/federation/AppleClientSecretService.js";

// HAPI ID V2-D Phase 1: Apple client-secret JWT generation with a SYNTHETIC ES256 key.
// No live Apple credentials exist anywhere in this suite.

const TEAM_ID = "SYNTHTEAM1";
const CLIENT_ID = "com.hapi.id.synthetic-services";
const KEY_ID = "SYNTHKEY01";

function syntheticKeyPair() {
		const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
		return {
				privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
				publicKey
		};
}

describe("V2-D Apple client-secret JWT generation (synthetic ES256 key)", () => {
		it("mints a valid ES256 JWT with Apple's exact required claims and header", async () => {
				const { privateKeyPem, publicKey } = syntheticKeyPair();
				const now = new Date("2026-11-19T12:00:00Z");
				const service = new AppleClientSecretService({
						teamId: TEAM_ID, clientId: CLIENT_ID, keyId: KEY_ID, privateKeyPem, now: () => now });

				const secret = await service.generate();
				const { payload, protectedHeader } = await jwtVerify(secret, publicKey, {
						issuer: TEAM_ID,
						audience: APPLE_CLIENT_SECRET_AUDIENCE,
						currentDate: now
				});
				expect(protectedHeader.alg).toBe("ES256");
				expect(protectedHeader.kid).toBe(KEY_ID);
				expect(payload.sub).toBe(CLIENT_ID);
				expect(payload.iat).toBe(Math.floor(now.getTime() / 1000));
				// Short-lived by default: a fresh secret per exchange, never a long-lived artifact.
				expect((payload.exp as number) - (payload.iat as number)).toBe(300);
		});

		it("caps the lifetime at Apple's 6-month maximum", async () => {
				const { privateKeyPem, publicKey } = syntheticKeyPair();
				const now = new Date();
				const service = new AppleClientSecretService({
						teamId: TEAM_ID, clientId: CLIENT_ID, keyId: KEY_ID, privateKeyPem,
						ttlSeconds: 99_999_999, now: () => now });
				const { payload } = await jwtVerify(await service.generate(), publicKey, { currentDate: now });
				expect((payload.exp as number) - (payload.iat as number)).toBe(15_777_000);
		});

		it("requires every credential field and rejects invalid key material without echoing it", async () => {
				const { privateKeyPem } = syntheticKeyPair();
				expect(() => new AppleClientSecretService({ teamId: "", clientId: CLIENT_ID, keyId: KEY_ID, privateKeyPem }))
						.toThrow(/teamId/);
				expect(() => new AppleClientSecretService({ teamId: TEAM_ID, clientId: " ", keyId: KEY_ID, privateKeyPem }))
						.toThrow(/clientId/);
				expect(() => new AppleClientSecretService({ teamId: TEAM_ID, clientId: CLIENT_ID, keyId: "", privateKeyPem }))
						.toThrow(/keyId/);

				const secretText = "-----BEGIN PRIVATE KEY-----\nNOTAKEY\n-----END PRIVATE KEY-----";
				const broken = new AppleClientSecretService({
						teamId: TEAM_ID, clientId: CLIENT_ID, keyId: KEY_ID, privateKeyPem: secretText });
				const error = await broken.generate().then(() => undefined, (caught: unknown) => caught);
				expect(error).toBeInstanceOf(Error);
				expect((error as Error).message).not.toContain("NOTAKEY");
		});

		it("never embeds key material in the generated token", async () => {
				const { privateKeyPem } = syntheticKeyPair();
				const service = new AppleClientSecretService({
						teamId: TEAM_ID, clientId: CLIENT_ID, keyId: KEY_ID, privateKeyPem });
				const secret = await service.generate();
				const keyBody = privateKeyPem.replace(/-----[^-]+-----|\s/g, "").slice(0, 32);
				expect(secret).not.toContain(keyBody);
				// Header/payload are inspectable; only signature + public claims are present.
				const payload = JSON.parse(Buffer.from(secret.split(".")[1], "base64url").toString("utf8"));
				expect(Object.keys(payload).sort()).toEqual(["aud", "exp", "iat", "iss", "sub"]);
		});
});
