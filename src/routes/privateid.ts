import type { FastifyInstance } from "fastify";

import { identityService } from "../identity/IdentityService.js";
import { PrivateIDAuthenticationProvider } from "../privateid/PrivateIDAuthenticationProvider.js";

type QueryRecord = Record<string, unknown>;

function normalizedKey(value: string): string {
		return value.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function pickQueryValue(query: QueryRecord, aliases: string[]): string | undefined {
		const aliasSet = new Set(aliases.map((alias) => normalizedKey(alias)));
		for (const [key, rawValue] of Object.entries(query)) {
				if (!aliasSet.has(normalizedKey(key))) {
						continue;
				}

				const value = Array.isArray(rawValue) ? rawValue[0] : rawValue;
				if (typeof value === "string" && value.trim().length > 0) {
						return value.trim();
				}
		}

		return undefined;
}

export async function registerPrivateIdRoutes(app: FastifyInstance): Promise<void> {
		app.get("/privateid/callback", async (request, reply) => {
				const query = (request.query ?? {}) as QueryRecord;
				app.log.info(
						{
								path: request.url,
								method: request.method,
								query,
								headers: request.headers
						},
						"PrivateID callback received"
				);

				const reason = pickQueryValue(query, ["reason", "status", "result"]);
				const sessionId = pickQueryValue(query, ["sessionId", "session_id", "sid"]);
				const transactionId = pickQueryValue(query, ["transactionId", "transaction_id", "txId", "txnId"]);

				if (!reason || !sessionId || !transactionId) {
						reply.code(400);
						return {
							error: "invalid_request",
							error_description: "PrivateID callback must include reason, sessionId, and transactionId"
						};
				}

				if (reason.trim().toLowerCase() !== "success") {
					reply.code(401);
					reply.type("text/plain");
					return "authentication failed";
				}

				const provider = new PrivateIDAuthenticationProvider();
				const { session, result, user } = await provider.completeCallback({ reason, sessionId, transactionId });

				if (result?.privateIdUserId) {
						try {
								await identityService.resolveIdentity(result.privateIdUserId);
						} catch (error) {
								app.log.warn(
										{
												error,
												privateIdUserId: result.privateIdUserId,
												sessionId,
												transactionId
										},
										"PrivateID callback identity resolution failed"
								);
						}
				}

				reply.code(200);
				return {
						status: session.status,
						reason,
						sessionId,
						transactionId,
						identityResolved: Boolean(result?.privateIdUserId),
						authenticatedUserId: user.id
				};
		});
}