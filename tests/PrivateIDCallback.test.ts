import { describe, expect, it } from "vitest";

import { PrivateIDClient } from "../src/privateid/PrivateIDClient.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";

describe("PrivateID callback", () => {
		it("returns processing when callback has no matching session", async () => {
				const { app } = await buildOidcTestApp();

				const response = await app.inject({
						method: "GET",
						url: "/privateid/callback?reason=success"
				});

				expect(response.statusCode).toBe(202);
				const payload = response.json() as Record<string, unknown>;
				expect(payload).toMatchObject({
						status: "pending",
						message: "Authentication Incomplete",
						retry: true
				});

				await app.close();
		});

		it("returns processing when callback arrives before webhook completion", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const response = await app.inject({
						method: "GET",
						url: `/privateid/callback?result=success&session_id=${encodeURIComponent(session.sessionId)}&txn_id=${encodeURIComponent(session.transactionId)}`
				});

				expect(response.statusCode).toBe(202);
				const payload = response.json() as Record<string, unknown>;
				expect(payload).toMatchObject({
						status: "created",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						message: "Authentication Incomplete",
						retry: true
				});

				expect((await client.getSession()).status).toBe("created");
				await app.close();
		});

		it("rejects webhook calls with invalid shared secret", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				await client.createAuthenticationSession();

				const response = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "wrong-secret"
						},
						payload: {
								status: "SUCCESS"
						}
				});

				expect(response.statusCode).toBe(401);
				await app.close();
		});

		it("accepts SUCCESS webhook and then allows callback continuation", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const webhookResponse = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "privateid-webhook-secret"
						},
						payload: {
								status: "SUCCESS",
								sessionId: session.sessionId,
								transactionId: session.transactionId,
								privateIdUserId: "dev-user-1"
						}
				});

				expect(webhookResponse.statusCode).toBe(200);
				expect((await client.getSession()).status).toBe("ready");

				const response = await app.inject({
						method: "GET",
						url: "/privateid/callback?reason=success"
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload).toMatchObject({
						status: "ready",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						message: "Continue OIDC authorization"
				});

				await app.close();
		});

		it("accepts FAILURE webhook and marks session failed", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const webhookResponse = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "privateid-webhook-secret"
						},
						payload: {
								status: "FAILURE",
								sessionId: session.sessionId,
								transactionId: session.transactionId
						}
				});

				expect(webhookResponse.statusCode).toBe(200);
				expect((await client.getSession()).status).toBe("failed");
				await app.close();
		});

		it("accepts PENDING webhook and keeps session waiting", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const webhookResponse = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "privateid-webhook-secret"
						},
						payload: {
								status: "PENDING",
								sessionId: session.sessionId,
								transactionId: session.transactionId
						}
				});

				expect(webhookResponse.statusCode).toBe(200);
				expect((await client.getSession()).status).toBe("waiting");
				await app.close();
		});

		it("accepts REQUIRES_INPUT webhook and keeps session waiting", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const webhookResponse = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "privateid-webhook-secret"
						},
						payload: {
								status: "REQUIRES_INPUT",
								sessionId: session.sessionId,
								transactionId: session.transactionId
						}
				});

				expect(webhookResponse.statusCode).toBe(200);
				expect((await client.getSession()).status).toBe("waiting");
				await app.close();
		});

		it("accepts EXPIRED webhook and marks session expired", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const webhookResponse = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "privateid-webhook-secret"
						},
						payload: {
								status: "EXPIRED",
								sessionId: session.sessionId,
								transactionId: session.transactionId
						}
				});

				expect(webhookResponse.statusCode).toBe(200);
				expect((await client.getSession()).status).toBe("expired");
				await app.close();
		});

		it("requires exact uppercase status values in webhook", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				await client.createAuthenticationSession();

				const response = await app.inject({
						method: "POST",
						url: "/privateid/webhook",
						headers: {
								"x-storythink-webhook-secret": "privateid-webhook-secret"
						},
						payload: {
								status: "success"
						}
				});

				expect(response.statusCode).toBe(400);
				await app.close();
		});

		it("returns authentication failed when callback reason is not success", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const response = await app.inject({
						method: "GET",
						url: `/privateid/callback?reason=failed&sessionId=${encodeURIComponent(session.sessionId)}&transactionId=${encodeURIComponent(session.transactionId)}`
				});

				expect(response.statusCode).toBe(200);
				expect(response.body).toBe("authentication failed");

				await app.close();
		});
	// Release Patch 7.0: PrivateID Contract Alignment tests
	it("session creation generates and stores transactionID", async () => {
		const { app } = await buildOidcTestApp();
		const client = new PrivateIDClient();
		const session = await client.createAuthenticationSession();

		expect(session.transactionId).toBeDefined();
		expect(session.transactionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i); // UUID format
		expect(session.sessionId).toBeDefined();

		await app.close();
	});

	it("webhook correlation succeeds using transactionID", async () => {
		const { app } = await buildOidcTestApp();
		const client = new PrivateIDClient();
		const session = await client.createAuthenticationSession();

		const webhookResponse = await app.inject({
			method: "POST",
			url: "/privateid/webhook",
			headers: {
				"x-storythink-webhook-secret": "privateid-webhook-secret"
			},
			payload: {
				status: "SUCCESS",
				sessionId: session.sessionId,
				transactionId: session.transactionId,
				privateIdUserId: "dev-user-1",
				puid: "stable-user-id",
				guid: "session-unique-id"
			}
		});

		expect(webhookResponse.statusCode).toBe(200);
		const payload = webhookResponse.json() as Record<string, unknown>;
		expect(payload).toMatchObject({
			status: "SUCCESS",
			sessionId: session.sessionId,
			transactionId: session.transactionId,
			completed: true
		});
		expect((await client.getSession()).status).toBe("ready");

		await app.close();
	});

	it("webhook accepts legacy metadata.correlationId if transactionID is absent", async () => {
		const { app } = await buildOidcTestApp();
		const client = new PrivateIDClient();
		const session = await client.createAuthenticationSession();

		// Simulate legacy webhook payload without transactionID but with metadata.correlationId
		const webhookResponse = await app.inject({
			method: "POST",
			url: "/privateid/webhook",
			headers: {
				"x-storythink-webhook-secret": "privateid-webhook-secret"
			},
			payload: {
				status: "SUCCESS",
				sessionId: session.sessionId,
				// Omit transactionId to test legacy fallback
				// Include legacy metadata.correlationId instead
				metadata: {
					correlationId: session.transactionId
				},
				privateIdUserId: "dev-user-1",
				puid: "stable-user-id",
				guid: "session-unique-id"
			}
		});

		expect(webhookResponse.statusCode).toBe(200);
		const payload = webhookResponse.json() as Record<string, unknown>;
		expect(payload).toMatchObject({
			status: "SUCCESS",
			sessionId: session.sessionId,
			completed: true
		});
		expect((await client.getSession()).status).toBe("ready");

		await app.close();
	});

	it("webhook prefers transactionID over legacy metadata.correlationId", async () => {
		const { app } = await buildOidcTestApp();
		const client = new PrivateIDClient();
		const session = await client.createAuthenticationSession();

		// Send webhook with both transactionID and metadata.correlationId
		// Should prefer transactionID
		const webhookResponse = await app.inject({
			method: "POST",
			url: "/privateid/webhook",
			headers: {
				"x-storythink-webhook-secret": "privateid-webhook-secret"
			},
			payload: {
				status: "SUCCESS",
				sessionId: session.sessionId,
				transactionId: session.transactionId, // Preferred field
				metadata: {
					correlationId: "different-id" // Should be ignored
				},
				privateIdUserId: "dev-user-1",
				puid: "stable-user-id",
				guid: "session-unique-id"
			}
		});

		expect(webhookResponse.statusCode).toBe(200);
		const payload = webhookResponse.json() as Record<string, unknown>;
		expect(payload).toMatchObject({
			status: "SUCCESS",
			sessionId: session.sessionId,
			transactionId: session.transactionId, // Verified correct transactionId in response
			completed: true
		});

		await app.close();
	});});