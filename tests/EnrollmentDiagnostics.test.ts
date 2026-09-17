import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomUUID } from "crypto";
import type { FastifyInstance } from "fastify";
import Fastify from "fastify";

import { registerDiagnosticsRoutes } from "../src/routes/diagnostics.js";
import { PrivateIDEnrollmentTransactionRepository } from "../src/identity/PrivateIDEnrollmentTransactionRepository.js";
import { privateIdWebhookDiagnosticsRepository } from "../src/identity/infrastructure/PrivateIdWebhookDiagnosticsRepository.js";
import {
	storePrivateIDSession,
	markPrivateIDEnrollmentSession,
} from "../src/privateid/PrivateIDSessionStore.js";
import type { PrivateIDSession } from "../src/privateid/PrivateIDSession.js";

describe("Enrollment self-diagnostics routes (Release C4)", () => {
	let app: FastifyInstance;
	const apiKey = "test-api-key";

	beforeEach(async () => {
		process.env.BOOKWRM_IDENTITY_API_KEY = apiKey;
		app = Fastify();
		await registerDiagnosticsRoutes(app);
	});

	afterEach(async () => {
		vi.restoreAllMocks();
		await app.close();
	});

	function buildSession(): PrivateIDSession {
		return {
			sessionId: randomUUID(),
			transactionId: randomUUID(),
			status: "waiting",
			launchUrl: "https://example.com",
			expires: Date.now() + 3600000,
			created: Date.now(),
		};
	}

	describe("GET /diagnostics/session/:sessionId", () => {
		it("requires the service API key", async () => {
			const response = await app.inject({ method: "GET", url: "/diagnostics/session/unknown" });
			expect(response.statusCode).toBe(401);
		});

		it("returns exists:false for an unknown session", async () => {
			const response = await app.inject({
				method: "GET",
				url: "/diagnostics/session/unknown",
				headers: { authorization: `Bearer ${apiKey}` },
			});

			expect(response.statusCode).toBe(200);
			expect(response.json()).toEqual({ exists: false });
		});

		it("returns the session status and transactionId when found", async () => {
			const session = buildSession();
			storePrivateIDSession(session);

			const response = await app.inject({
				method: "GET",
				url: `/diagnostics/session/${session.sessionId}`,
				headers: { authorization: `Bearer ${apiKey}` },
			});

			expect(response.statusCode).toBe(200);
			expect(response.json()).toEqual({
				exists: true,
				store: "memory",
				status: "waiting",
				transactionId: session.transactionId,
			});
		});
	});

	describe("GET /diagnostics/enrollment-transaction/:transactionId", () => {
		it("returns exists:false when the transaction is not found", async () => {
			const findByIdSpy = vi.spyOn(PrivateIDEnrollmentTransactionRepository.prototype, "findById").mockResolvedValue(undefined);

			const response = await app.inject({
				method: "GET",
				url: "/diagnostics/enrollment-transaction/unknown",
				headers: { authorization: `Bearer ${apiKey}` },
			});

			expect(response.statusCode).toBe(200);
			expect(response.json()).toEqual({ exists: false });
			expect(findByIdSpy).toHaveBeenCalledWith("unknown");
		});

		it("returns status, expiry, and completed flag when found", async () => {
			const transactionId = randomUUID();
			vi.spyOn(PrivateIDEnrollmentTransactionRepository.prototype, "findById").mockResolvedValue({
				id: transactionId,
				userId: "user-1",
				purpose: "face_enrollment",
				providerTransactionId: randomUUID(),
				status: "pending",
				createdAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3600000).toISOString(),
			});

			const response = await app.inject({
				method: "GET",
				url: `/diagnostics/enrollment-transaction/${transactionId}`,
				headers: { authorization: `Bearer ${apiKey}` },
			});

			const body = response.json();
			expect(response.statusCode).toBe(200);
			expect(body.exists).toBe(true);
			expect(body.status).toBe("pending");
			expect(body.completed).toBe(false);
			expect(typeof body.expires).toBe("string");
		});
	});

	describe("GET /diagnostics/enrollment-trace/:sessionId", () => {
		it("reports failure at ENROLLMENT_TRANSACTION_CREATION when no enrollment transaction was linked", async () => {
			const session = buildSession();
			storePrivateIDSession(session);
			vi.spyOn(privateIdWebhookDiagnosticsRepository, "findActiveBySessionId").mockResolvedValue(undefined);

			const response = await app.inject({
				method: "GET",
				url: `/diagnostics/enrollment-trace/${session.sessionId}`,
				headers: { authorization: `Bearer ${apiKey}` },
			});

			const body = response.json();
			expect(response.statusCode).toBe(200);
			expect(body.privateIdSessionCreated).toBe(true);
			expect(body.enrollmentTransactionCreated).toBe(false);
			expect(body.failureStage).toBe("ENROLLMENT_TRANSACTION_CREATION");
		});

		it("reports failure at WEBHOOK_NOT_RECEIVED when no webhook has matched the session and the transaction is still pending", async () => {
			const session = buildSession();
			const enrollmentTransactionId = randomUUID();
			storePrivateIDSession(session);
			markPrivateIDEnrollmentSession(session.sessionId, enrollmentTransactionId);
			vi.spyOn(PrivateIDEnrollmentTransactionRepository.prototype, "findById").mockResolvedValue({
				id: enrollmentTransactionId,
				userId: "user-1",
				purpose: "face_enrollment",
				providerTransactionId: session.transactionId,
				status: "pending",
				createdAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3600000).toISOString(),
			});
			vi.spyOn(privateIdWebhookDiagnosticsRepository, "findActiveBySessionId").mockResolvedValue(undefined);

			const response = await app.inject({
				method: "GET",
				url: `/diagnostics/enrollment-trace/${session.sessionId}`,
				headers: { authorization: `Bearer ${apiKey}` },
			});

			const body = response.json();
			expect(response.statusCode).toBe(200);
			expect(body.enrollmentTransactionCreated).toBe(true);
			expect(body.webhookReceived).toBe(false);
			expect(body.webhookMatchedSession).toBe(false);
			expect(body.userAuthenticatorCreated).toBe(false);
			expect(body.failureStage).toBe("WEBHOOK_NOT_RECEIVED");
		});

		it("reports failure at WEBHOOK_SESSION_LOOKUP when the transaction moved off pending but no webhook diagnostic matched the session", async () => {
			const session = buildSession();
			const enrollmentTransactionId = randomUUID();
			storePrivateIDSession(session);
			markPrivateIDEnrollmentSession(session.sessionId, enrollmentTransactionId);
			vi.spyOn(PrivateIDEnrollmentTransactionRepository.prototype, "findById").mockResolvedValue({
				id: enrollmentTransactionId,
				userId: "user-1",
				purpose: "face_enrollment",
				providerTransactionId: session.transactionId,
				status: "failed",
				createdAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3600000).toISOString(),
			});
			vi.spyOn(privateIdWebhookDiagnosticsRepository, "findActiveBySessionId").mockResolvedValue(undefined);

			const response = await app.inject({
				method: "GET",
				url: `/diagnostics/enrollment-trace/${session.sessionId}`,
				headers: { authorization: `Bearer ${apiKey}` },
			});

			const body = response.json();
			expect(response.statusCode).toBe(200);
			expect(body.webhookReceived).toBe(true);
			expect(body.webhookMatchedSession).toBe(false);
			expect(body.failureStage).toBe("WEBHOOK_SESSION_LOOKUP");
		});

		it("reports no failure when the enrollment completed successfully", async () => {
			const session = buildSession();
			const enrollmentTransactionId = randomUUID();
			storePrivateIDSession(session);
			markPrivateIDEnrollmentSession(session.sessionId, enrollmentTransactionId);
			vi.spyOn(PrivateIDEnrollmentTransactionRepository.prototype, "findById").mockResolvedValue({
				id: enrollmentTransactionId,
				userId: "user-1",
				purpose: "face_enrollment",
				providerTransactionId: session.transactionId,
				status: "completed",
				createdAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3600000).toISOString(),
				completedAt: new Date().toISOString(),
			});
			vi.spyOn(privateIdWebhookDiagnosticsRepository, "findActiveBySessionId").mockResolvedValue({ raw_webhook_json: {} });

			const response = await app.inject({
				method: "GET",
				url: `/diagnostics/enrollment-trace/${session.sessionId}`,
				headers: { authorization: `Bearer ${apiKey}` },
			});

			const body = response.json();
			expect(response.statusCode).toBe(200);
			expect(body.webhookReceived).toBe(true);
			expect(body.webhookMatchedSession).toBe(true);
			expect(body.userAuthenticatorCreated).toBe(true);
			expect(body.failureStage).toBe(null);
		});

		it("requires the service API key", async () => {
			const response = await app.inject({ method: "GET", url: "/diagnostics/enrollment-trace/unknown" });
			expect(response.statusCode).toBe(401);
		});
	});
});
