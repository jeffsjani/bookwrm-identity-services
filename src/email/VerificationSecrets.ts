import { createHmac, randomInt, timingSafeEqual } from "node:crypto";

export class VerificationSecrets {
	constructor(private readonly secret: string) {
		if (Buffer.byteLength(secret) < 32) throw new Error("HAPI_EMAIL_VERIFICATION_SECRET must be at least 32 bytes");
	}
	generate(length: number): string {
		return randomInt(0, 10 ** length).toString().padStart(length, "0");
	}
	destination(email: string): string {
		return this.hash(["destination", email]);
	}
	code(challengeId: string, code: string): string {
		return this.hash(["otp", challengeId, code]);
	}
	matches(challengeId: string, code: string, expected: string): boolean {
		const actual = Buffer.from(this.code(challengeId, code), "hex");
		const stored = Buffer.from(expected, "hex");
		return stored.length === actual.length && timingSafeEqual(actual, stored);
	}
	private hash(parts: string[]): string {
		return createHmac("sha256", this.secret).update(JSON.stringify(parts)).digest("hex");
	}
}