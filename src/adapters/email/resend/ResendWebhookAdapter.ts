import type { FastifyInstance } from "fastify";
import { Webhook } from "svix";
import { z } from "zod";
import type { EmailVerificationService } from "../../../email/EmailVerificationService.js";
import { VerificationError } from "../../../email/VerificationChallenge.js";

const payloadSchema = z.object({ type: z.string(), data: z.object({ email_id: z.string().min(1) }) });
const states = {
	"email.delivered": "DELIVERED", "email.delivery_delayed": "DEFERRED", "email.bounced": "BOUNCED",
	"email.complained": "COMPLAINED", "email.suppressed": "SUPPRESSED", "email.failed": "PROVIDER_FAILED"
} as const;

export async function registerResendWebhook(app: FastifyInstance, service: EmailVerificationService, secret?: string): Promise<void> {
	const webhook = secret ? new Webhook(secret) : undefined;
	await app.register(async scoped => {
		scoped.removeContentTypeParser("application/json");
		scoped.addContentTypeParser("application/json", { parseAs: "buffer", bodyLimit: 65_536 }, (_request, body, done) => done(null, body));
		scoped.post("/v1/identity/email/webhooks/resend", async (request, reply) => {
			if (!webhook) return reply.code(503).send({ error: "WEBHOOK_NOT_CONFIGURED" });
			let payload: z.infer<typeof payloadSchema>;
			const headers: Record<string, string> = {};
			try {
				for (const key of ["svix-id", "svix-timestamp", "svix-signature"]) {
					const value = request.headers[key];
					if (typeof value !== "string") throw new Error("Missing signature");
					headers[key] = value;
				}
				if (!Buffer.isBuffer(request.body)) throw new Error("Invalid body");
				const rawBody = request.body.toString("utf8");
				webhook.verify(rawBody, headers);
				payload = payloadSchema.parse(JSON.parse(rawBody));
			} catch { return reply.code(400).send({ error: "INVALID_WEBHOOK" }); }
			const state = states[payload.type as keyof typeof states];
			if (!state) return reply.code(204).send();
			try {
				await service.recordProviderEvent(payload.data.email_id, `resend:${headers["svix-id"]}`, state);
				return reply.code(204).send();
			} catch (error) {
				return reply.code(error instanceof VerificationError ? error.statusCode : 503).send({ error: "DELIVERY_UNAVAILABLE" });
			}
		});
	});
}