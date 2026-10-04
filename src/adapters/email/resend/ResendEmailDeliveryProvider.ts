import type { EmailDeliveryProvider, VerificationEmail } from "../../../email/EmailDeliveryProvider.js";

export class ResendEmailDeliveryProvider implements EmailDeliveryProvider {
	constructor(private readonly apiKey: string, private readonly from: string, private readonly transport: typeof fetch = fetch) {
		if (!apiKey || !from || /[\r\n]/.test(from)) throw new Error("Resend requires RESEND_API_KEY and HAPI_EMAIL_FROM");
	}
	async sendVerificationEmail(input: VerificationEmail, signal: AbortSignal): Promise<{ messageId: string }> {
		const minutes = input.expiresIn / 60;
		const duration = Number.isInteger(minutes) ? `${minutes} minutes` : `${input.expiresIn} seconds`;
		const text = `Verify your HAPI ID\n\nYour verification code is:\n\n${input.code}\n\nThis code expires in ${duration}.\n\nIf you didn't request this code, you can ignore this email.\n\nHAPI ID`;
		const response = await this.transport("https://api.resend.com/emails", {
			method: "POST", signal,
			headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json", "Idempotency-Key": input.sendId },
			body: JSON.stringify({ from: this.from, to: [input.destination], subject: "Your HAPI ID verification code", text })
		});
		if (!response.ok) throw new Error("Email provider rejected request");
		const body = await response.json() as { id?: unknown };
		if (typeof body.id !== "string" || !body.id) throw new Error("Email provider response invalid");
		return { messageId: body.id };
	}
}