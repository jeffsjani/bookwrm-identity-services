import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "@babel/parser";

describe("H4 architecture isolation", () => {
	it("has no downstream product, face, linking, registration, or credential-hash dependencies", () => {
		const directory = resolve("src/authentication/email");
		const files = readdirSync(directory).filter(file => file.endsWith(".ts"))
			.map(file => resolve(directory, file));
		files.push(resolve("src/routes/emailAuthentication.ts"), resolve("src/authentication/EmailOIDCHandoff.ts"));
		for (const file of files) {
			const source = readFileSync(file, "utf8");
			expect(source).not.toMatch(/Base44|Bookwrm|PrivateID|C5\.1|C5\.2|IdentityAccountLink|UserAuthenticator|\bpassword\b/i);
			expect(source).not.toMatch(/resolveOrCreate|createIdentitySubject|import\s*\(/);
			for (const statement of parse(source, { sourceType: "module", plugins: ["typescript"] }).program.body) {
				if (statement.type === "ImportDeclaration") {
					expect(statement.source.value).not.toMatch(/base44|bookwrm|privateid|registration|accountlink/i);
				}
			}
		}
	});
	it("does not add another OTP generator, hash, rate limiter, or delivery provider", () => {
		const service = readFileSync(resolve("src/authentication/email/EmailAuthenticationService.ts"), "utf8");
		expect(service).toContain("this.verification.start");
		expect(service).toContain("this.verification.resend");
		expect(service).toContain("this.verification.verify");
		expect(service).not.toMatch(/randomInt|VerificationSecrets|sendVerificationEmail|fetch\(/);
	});
});
