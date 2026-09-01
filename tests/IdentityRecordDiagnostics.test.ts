import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { randomUUID } from "crypto";
import type { FastifyInstance } from "fastify";
import Fastify from "fastify";

import { configuration } from "../src/config/ConfigurationService.js";
import { identityRegistry } from "../src/identity/IdentityRegistry.js";
import type { IdentitySubject } from "../src/models/IdentitySubject.js";
import { registerDiagnosticsRoutes } from "../src/routes/diagnostics.js";
import {
	storePrivateIDSession,
	storePrivateIDResult,
} from "../src/privateid/PrivateIDSessionStore.js";
import type { PrivateIDSession } from "../src/privateid/PrivateIDSession.js";

describe("POST /diagnostics/identity-record (Release Patch 6.4.2)", () => {
	let app: FastifyInstance;
	let testIdentitySubject: IdentitySubject;
	const apiKey = "test-api-key";

	beforeEach(async () => {
		process.env.BOOKWRM_IDENTITY_API_KEY = apiKey;

		app = Fastify();
		await registerDiagnosticsRoutes(app);

		// Create test identity subject
		testIdentitySubject = await identityRegistry.resolveOrCreate({
			provider: "PrivateID",
			providerSubject: `test-puid-${randomUUID()}`,
			email: "test@example.com",
			emailVerified: true,
			displayName: "Test User",
		});
	});

	afterEach(async () => {
		await app.close();
	});

	describe("Method 1: Lookup by oidcSubject", () => {
		it("returns identity subject when oidcSubject is provided", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					oidcSubject: testIdentitySubject.oidcSubject,
				},
			});

			expect(response.statusCode).toBe(200);
			const body = JSON.parse(response.payload);
			expect(body.identitySubject).toBeDefined();
			expect(body.identitySubject.oidcSubject).toBe(testIdentitySubject.oidcSubject);
			expect(body.identitySubject.email).toBe("test@example.com");
			expect(body.identitySubject.emailVerified).toBe(true);
			expect(body.identitySubject.displayName).toBe("Test User");
		});

		it("returns 404 when oidcSubject is not found", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					oidcSubject: randomUUID(),
				},
			});

			expect(response.statusCode).toBe(404);
			const body = JSON.parse(response.payload);
			expect(body.error).toBe("not_found");
		});
	});

	describe("Method 2: Lookup by provider + providerSubject", () => {
		it("returns identity subject when provider and providerSubject are provided", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					provider: "PrivateID",
					providerSubject: testIdentitySubject.primaryProviderSubject,
				},
			});

			expect(response.statusCode).toBe(200);
			const body = JSON.parse(response.payload);
			expect(body.identitySubject).toBeDefined();
			expect(body.identitySubject.oidcSubject).toBe(testIdentitySubject.oidcSubject);
			expect(body.identitySubject.primaryProvider).toBe("PrivateID");
			expect(body.identitySubject.primaryProviderSubject).toBe(
				testIdentitySubject.primaryProviderSubject
			);
		});

		it("returns 404 when provider subject is not found", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					provider: "PrivateID",
					providerSubject: `nonexistent-${randomUUID()}`,
				},
			});

			expect(response.statusCode).toBe(404);
		});
	});

	describe("Method 3: Lookup by sessionId", () => {
		it("returns identity subject when sessionId is provided and session has result", async () => {
			const sessionId = randomUUID();
			const transactionId = randomUUID();
			const session: PrivateIDSession = {
				sessionId,
				transactionId,
				status: "ready",
				launchUrl: "https://example.com",
				expires: Date.now() + 3600000,
				created: Date.now(),
				completed: Date.now(),
			};

			// Store session with result
			storePrivateIDSession(session);
			storePrivateIDResult(sessionId, {
				success: true,
				privateIdUserId: testIdentitySubject.primaryProviderSubject,
				confidence: 1,
				risk: 0,
				liveness: true,
				sessionId,
				transactionId,
				rawResponse: {},
			});

			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					sessionId,
				},
			});

			expect(response.statusCode).toBe(200);
			const body = JSON.parse(response.payload);
			expect(body.identitySubject).toBeDefined();
			expect(body.identitySubject.oidcSubject).toBe(testIdentitySubject.oidcSubject);
			expect(body.identitySubject.primaryProvider).toBe("PrivateID");
		});

		it("returns session_expired when sessionId is not found", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					sessionId: randomUUID(),
				},
			});

			expect(response.statusCode).toBe(404);
			const body = JSON.parse(response.payload);
			expect(body).toEqual({
				error: "session_expired",
				message: "The requested PrivateID session is no longer available in memory. Run the diagnostics immediately after a new authentication."
			});
		});
	});

	describe("All three methods resolve to same IdentitySubject", () => {
		it("returns identical IdentitySubject for all three lookup methods", async () => {
			const sessionId = randomUUID();
			const transactionId = randomUUID();
			const session: PrivateIDSession = {
				sessionId,
				transactionId,
				status: "ready",
				launchUrl: "https://example.com",
				expires: Date.now() + 3600000,
				created: Date.now(),
				completed: Date.now(),
			};

			storePrivateIDSession(session);
			storePrivateIDResult(sessionId, {
				success: true,
				privateIdUserId: testIdentitySubject.primaryProviderSubject,
				confidence: 1,
				risk: 0,
				liveness: true,
				sessionId,
				transactionId,
				rawResponse: {},
			});

			// Method 1: By oidcSubject
			const response1 = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					oidcSubject: testIdentitySubject.oidcSubject,
				},
			});

			// Method 2: By provider + providerSubject
			const response2 = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					provider: "PrivateID",
					providerSubject: testIdentitySubject.primaryProviderSubject,
				},
			});

			// Method 3: By sessionId
			const response3 = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					sessionId,
				},
			});

			expect(response1.statusCode).toBe(200);
			expect(response2.statusCode).toBe(200);
			expect(response3.statusCode).toBe(200);

			const body1 = JSON.parse(response1.payload);
			const body2 = JSON.parse(response2.payload);
			const body3 = JSON.parse(response3.payload);

			// All three should return identical identity subjects
			expect(body1.identitySubject).toEqual(body2.identitySubject);
			expect(body2.identitySubject).toEqual(body3.identitySubject);

			// Verify all contain expected fields
			expect(body1.identitySubject.oidcSubject).toBeDefined();
			expect(body1.identitySubject.primaryProvider).toBe("PrivateID");
			expect(body1.identitySubject.primaryProviderSubject).toBeDefined();
			expect(body1.identitySubject.email).toBe("test@example.com");
			expect(body1.identitySubject.emailVerified).toBe(true);
			expect(body1.identitySubject.displayName).toBe("Test User");
			expect(body1.identitySubject.createdAt).toBeDefined();
			expect(body1.identitySubject.updatedAt).toBeDefined();
		});
	});

	describe("Authentication", () => {
		it("returns 401 when Authorization header is missing", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					"content-type": "application/json",
				},
				payload: {
					oidcSubject: testIdentitySubject.oidcSubject,
				},
			});

			expect(response.statusCode).toBe(401);
			const body = JSON.parse(response.payload);
			expect(body.error).toBe("unauthorized");
		});

		it("returns 401 when API key is invalid", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: "Bearer invalid-key",
					"content-type": "application/json",
				},
				payload: {
					oidcSubject: testIdentitySubject.oidcSubject,
				},
			});

			expect(response.statusCode).toBe(401);
		});
	});

	describe("Validation", () => {
		it("returns 400 when no lookup parameters are provided", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {},
			});

			expect(response.statusCode).toBe(400);
			const body = JSON.parse(response.payload);
			expect(body.error_description).toContain("oidcSubject, provider+providerSubject, or sessionId");
		});

		it("returns 400 when provider is provided without providerSubject", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					provider: "PrivateID",
				},
			});

			expect(response.statusCode).toBe(400);
		});
	});

	describe("Response format", () => {
		it("returns exact IdentitySubject fields with no transformations", async () => {
			const response = await app.inject({
				method: "POST",
				url: "/diagnostics/identity-record",
				headers: {
					authorization: `Bearer ${apiKey}`,
					"content-type": "application/json",
				},
				payload: {
					oidcSubject: testIdentitySubject.oidcSubject,
				},
			});

			expect(response.statusCode).toBe(200);
			const body = JSON.parse(response.payload);

			// Should have exactly these fields at top level
			expect(Object.keys(body)).toEqual(["identitySubject"]);

			// identitySubject should have these fields
			const subject = body.identitySubject;
			expect(subject).toHaveProperty("oidcSubject");
			expect(subject).toHaveProperty("primaryProvider");
			expect(subject).toHaveProperty("primaryProviderSubject");
			expect(subject).toHaveProperty("email");
			expect(subject).toHaveProperty("emailVerified");
			expect(subject).toHaveProperty("displayName");
			expect(subject).toHaveProperty("createdAt");
			expect(subject).toHaveProperty("updatedAt");

			// Should NOT have any JWTs, tokens, or secrets
			expect(JSON.stringify(body)).not.toContain("jwt");
			expect(JSON.stringify(body)).not.toContain("token");
			expect(JSON.stringify(body)).not.toContain("secret");
			expect(JSON.stringify(body)).not.toContain("Bearer");
		});
	});
});
