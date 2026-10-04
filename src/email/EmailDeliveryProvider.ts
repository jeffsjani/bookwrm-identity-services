import type { VerificationPurpose } from "./VerificationChallenge.js";

export interface VerificationEmail {
	destination: string;
	code: string;
	purpose: VerificationPurpose;
	expiresIn: number;
	tenant: string;
	application: string | null;
	sendId: string;
}

export interface EmailDeliveryProvider {
	sendVerificationEmail(input: VerificationEmail, signal: AbortSignal): Promise<{ messageId: string }>;
}

export class InMemoryEmailDeliveryProvider implements EmailDeliveryProvider {
	readonly messages: VerificationEmail[] = [];
	async sendVerificationEmail(input: VerificationEmail): Promise<{ messageId: string }> {
		this.messages.push(structuredClone(input));
		return { messageId: input.sendId };
	}
}