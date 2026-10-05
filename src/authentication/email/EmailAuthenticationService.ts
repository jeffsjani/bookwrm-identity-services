import type { EmailVerificationService } from "../../email/EmailVerificationService.js";
import type { VerificationChallengeRepository } from "../../email/VerificationChallengeRepository.js";
import { VerificationError } from "../../email/VerificationChallenge.js";
import { EmailAuthenticationError, type EmailAuthenticationContext, type EmailAuthenticationRepository } from "./EmailAuthenticationTypes.js";

export class EmailAuthenticationService {
	constructor(private readonly verification: EmailVerificationService,
		private readonly challenges: Pick<VerificationChallengeRepository, "findById">,
		private readonly repository: EmailAuthenticationRepository) {}

	async start(authority: EmailAuthenticationContext, email: string) {
		return this.operation(authority, null, async () => {
			const result = await this.verification.start(authority.context, email, "AUTHENTICATION");
			await this.repository.audit(authority, "EMAIL_AUTHENTICATION_STARTED", result.challengeId, "CHALLENGE_SENT");
			return result;
		});
	}

	async resend(authority: EmailAuthenticationContext, challengeId: string) {
		return this.operation(authority, challengeId, async () => {
			await this.assertChallenge(authority, challengeId);
			return this.verification.resend(authority.context, challengeId);
		});
	}

	async verify(authority: EmailAuthenticationContext, challengeId: string, code: string) {
		return this.operation(authority, challengeId, async () => {
			await this.assertChallenge(authority, challengeId);
			await this.verification.verify(authority.context, challengeId, code, "AUTHENTICATION");
			await this.repository.audit(authority, "EMAIL_AUTHENTICATION_VERIFIED", challengeId, "EMAIL_PROVED");
			return this.repository.establish(authority, challengeId);
		});
	}

	consumeResult(authority: EmailAuthenticationContext, token: string) {
		return this.repository.consumeResult(authority, token);
	}

	private async assertChallenge(authority: EmailAuthenticationContext, id: string) {
		const challenge = await this.challenges.findById(id);
		if (!challenge || challenge.tenantId !== authority.context.tenantId ||
			challenge.applicationId !== authority.context.applicationId || challenge.purpose !== "AUTHENTICATION") {
			throw new VerificationError("INVALID_CHALLENGE");
		}
	}

	private async operation<T>(authority: EmailAuthenticationContext, challengeId: string | null, work: () => Promise<T>): Promise<T> {
		try { return await work(); }
		catch (error) {
			// Eligibility failures are already audited atomically by the repository.
			if (!(error instanceof EmailAuthenticationError)) {
				await this.repository.audit(authority,
					error instanceof VerificationError && error.code === "RATE_LIMITED"
						? "EMAIL_AUTHENTICATION_RATE_LIMITED" : "EMAIL_AUTHENTICATION_FAILED",
					challengeId, error instanceof VerificationError ? error.code : "AUTHENTICATION_UNAVAILABLE");
			}
			throw error;
		}
	}
}
