import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "@babel/parser";

// Task 15: H3 Core must have zero dependencies on Base44, Bookwrm User, x-bookwrm-user-id,
// BiometricIdentity, PendingIdentityActivation, or PrivateID. H1 Tenant/Application and H2
// Verification are expected (and necessary) dependencies -- e.g. identity/IdentityRegistry.js and
// email/VerificationChallenge.js -- so only src/registration's own files are scanned for forbidden
// content; files it legitimately imports from identity/email are only checked by import path, not
// recursively opened (those modules may harmlessly mention Bookwrm/Base44 in comments describing
// their *own*, unrelated, non-H3 callers).
describe("H3 Core architecture isolation", () => {
	it("src/registration contains no Base44/Bookwrm/PrivateID/password coupling and imports no forbidden module", () => {
		const core = resolve("src/registration");
		const files = readdirSync(core).filter(file => file.endsWith(".ts")).map(file => resolve(core, file));
		expect(files.length).toBeGreaterThan(3);
		for (const file of files) {
			const source = readFileSync(file, "utf8");
			expect(source).not.toMatch(/Base44|x-bookwrm-user-id|BiometricIdentity|PendingIdentityActivation|PrivateID/i);
			expect(source).not.toMatch(/\bpassword\b/i);
			expect(source).not.toMatch(/import\s*\(/);
			for (const imported of parse(source, { sourceType: "module", plugins: ["typescript"] }).program.body) {
				if (imported.type !== "ImportDeclaration" && imported.type !== "ExportNamedDeclaration" && imported.type !== "ExportAllDeclaration") continue;
				const moduleName = imported.source?.value;
				if (!moduleName) continue;
				expect(moduleName).not.toMatch(/base44|bookwrm|biometric|pendingidentityactivation|privateid/i);
			}
		}
	});

	it("src/routes/registration.ts never references Base44/Bookwrm/PrivateID identifiers", () => {
		const source = readFileSync(resolve("src/routes/registration.ts"), "utf8");
		expect(source).not.toMatch(/Base44|x-bookwrm-user-id|BiometricIdentity|PendingIdentityActivation|PrivateID/i);
		expect(source).not.toMatch(/\bpassword\b/i);
	});
});
