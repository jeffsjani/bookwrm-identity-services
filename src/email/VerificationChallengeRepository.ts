import type { VerificationChallenge, VerificationContext } from "./VerificationChallenge.js";

export type DeliveryState = "CHALLENGE_CREATED" | "SEND_REQUESTED" | "PROVIDER_ACCEPTED" | "DELIVERED" |
	"DEFERRED" | "BOUNCED" | "COMPLAINED" | "SUPPRESSED" | "USER_VERIFIED" | "PROVIDER_FAILED" | "PROVIDER_TIMEOUT";

export interface DeliveryEvent extends VerificationContext {
	id: string;
	challengeId: string;
	destinationHash: string;
	sendId: string | null;
	providerMessageId: string | null;
	state: DeliveryState;
	occurredAt: string;
}

export type VerificationAuditType = "EMAIL_VERIFICATION_STARTED" | "EMAIL_VERIFICATION_SENT" |
	"EMAIL_VERIFICATION_RESENT" | "EMAIL_VERIFICATION_FAILED" | "EMAIL_VERIFICATION_VERIFIED" |
	"EMAIL_VERIFICATION_EXPIRED" | "EMAIL_VERIFICATION_LOCKED" | "EMAIL_VERIFICATION_RATE_LIMITED";

export interface VerificationAuditEvent extends VerificationContext {
	id: string;
	challengeId: string;
	destinationHash: string;
	type: VerificationAuditType;
	occurredAt: string;
}

export interface VerificationSnapshot {
	challenges: VerificationChallenge[];
	delivery: DeliveryEvent[];
	audit: VerificationAuditEvent[];
}

export interface VerificationChallengeRepository {
	findById(id: string): Promise<VerificationChallenge | undefined>;
	findByProviderMessageId(id: string): Promise<DeliveryEvent | undefined>;
	transaction<Result>(context: VerificationContext, destinationHash: string,
		work: (snapshot: VerificationSnapshot) => Result): Promise<Result>;
}