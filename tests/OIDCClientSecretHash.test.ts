import { describe, expect, it } from "vitest";
import { hashOIDCClientSecret, isHashedOIDCClientSecret, verifyOIDCClientSecret } from "../src/security/OIDCClientSecret.js";

describe("OIDC client secret hashing", () => {
	it("issues salted non-reversible secrets and verifies the correct value", async () => {
		const secret = "high-entropy-pilot-secret-" + "x".repeat(32);
		const first = await hashOIDCClientSecret(secret);
		const second = await hashOIDCClientSecret(secret);
		expect(isHashedOIDCClientSecret(first)).toBe(true);
		expect(first).not.toBe(secret);
		expect(first).not.toBe(second);
		expect(await verifyOIDCClientSecret(first, secret)).toBe(true);
	});

	it("rejects wrong, missing and malformed supplied secrets", async () => {
		const secret = await hashOIDCClientSecret("correct-high-entropy-secret-123456789");
		expect(await verifyOIDCClientSecret(secret, "wrong-secret")).toBe(false);
		expect(await verifyOIDCClientSecret(secret, "")).toBe(false);
		expect(await verifyOIDCClientSecret(secret, "bad\0secret")).toBe(false);
		expect(await verifyOIDCClientSecret(secret.replace("scrypt$16384$", "scrypt$65536$"), "correct-high-entropy-secret-123456789")).toBe(false);
		expect(await verifyOIDCClientSecret(`${secret}!`, "correct-high-entropy-secret-123456789")).toBe(false);
		expect(await verifyOIDCClientSecret("malformed$hash", "correct-high-entropy-secret-123456789")).toBe(false);
	});

	it("preserves compatibility with existing plaintext credentials", async () => {
		expect(await verifyOIDCClientSecret("legacy-client-secret", "legacy-client-secret")).toBe(true);
		expect(await verifyOIDCClientSecret("legacy-client-secret", "wrong-secret")).toBe(false);
		expect(isHashedOIDCClientSecret("legacy-client-secret")).toBe(false);
	});
});
