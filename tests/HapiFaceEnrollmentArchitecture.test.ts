import { readFileSync, readdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { parse } from "@babel/parser";
import { describe, expect, it } from "vitest";

describe("H5 architecture isolation", () => {
	it("has no transitive runtime product/account-link/claim-governance dependency", () => {
		const queue = readdirSync("src/authenticators").filter(file => file.endsWith(".ts"))
			.map(file => resolve("src/authenticators", file));
		queue.push(resolve("src/routes/hapiFaceEnrollment.ts"));
		const visited = new Set<string>();
		while (queue.length) {
			const file = queue.pop()!;
			if (visited.has(file)) continue;
			visited.add(file);
			expect(relative(resolve("src"), file)).not.toMatch(/base44|bookwrm|IdentityAccountLink|IdentityService\.ts|IdentityClaimGovernance|PlatformSeed|IdentityPlatformClient/i);
			const source = readFileSync(file, "utf8");
			expect(source).not.toMatch(/x-bookwrm-user-id|C5\.1|C5\.2|import\s*\(/i);
			for (const statement of parse(source, { sourceType: "module", plugins: ["typescript"] }).program.body) {
				if (statement.type !== "ImportDeclaration" || statement.importKind === "type" ||
					(statement.specifiers.length && statement.specifiers.every(specifier =>
						specifier.type === "ImportSpecifier" && specifier.importKind === "type"))) continue;
				if (statement.source.value.startsWith(".")) {
					queue.push(resolve(dirname(file), statement.source.value.replace(/\.js$/, ".ts")));
				}
			}
		}
		expect(visited.size).toBeGreaterThan(10);
	});
	it("never creates/resolves another identity, changes claims, moves an authenticator, or invokes registration", () => {
		for (const file of ["HapiFaceEnrollmentService.ts", "PostgresFaceEnrollmentRepository.ts", "FaceEnrollmentComposition.ts"]) {
			const source = readFileSync(resolve("src/authenticators", file), "utf8");
			expect(source).not.toMatch(/resolveOrCreate|registration|IdentityAccountLink|reassignUser|updateUserId|UPDATE identity_subjects|INSERT INTO identity_subjects/i);
		}
		const composition = readFileSync(resolve("src/authenticators/FaceEnrollmentComposition.ts"), "utf8");
		expect(composition).toContain("provider.createEnrollmentSession");
		expect(composition).toContain('env.HAPI_FACE_ENROLLMENT_ENABLED === "true"');
	});
});
