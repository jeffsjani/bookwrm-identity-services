import { describe, expect, it } from "vitest";

import { PrivateIDClient } from "../src/privateid/PrivateIDClient.js";
import { buildOidcTestApp } from "./oidcTestHarness.js";

describe("PrivateID callback", () => {
		it("accepts a success callback and advances the shared session", async () => {
				const { app } = await buildOidcTestApp();
				const client = new PrivateIDClient();
				const session = await client.createAuthenticationSession();

				const response = await app.inject({
						method: "GET",
						url: `/privateid/callback?result=success&session_id=${encodeURIComponent(session.sessionId)}&txn_id=${encodeURIComponent(session.transactionId)}`
				});

				expect(response.statusCode).toBe(200);
				const payload = response.json() as Record<string, unknown>;
				expect(payload).toMatchObject({
						status: "ready",
						sessionId: session.sessionId,
						transactionId: session.transactionId,
						identityResolved: true
				});

				expect((await client.getSession()).status).toBe("ready");
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

				expect(response.statusCode).toBe(401);
				expect(response.body).toBe("authentication failed");

				await app.close();
		});
});