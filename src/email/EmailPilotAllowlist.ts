import { normalizeEmail } from "./EmailNormalizationService.js";
import type { VerificationContext } from "./VerificationChallenge.js";

export type EmailPilotAllowlist = {
	configured: boolean;
	allows(email: string, context?: VerificationContext): boolean;
};

export function emailPilotAllowlistFromEnvironment(
	env: NodeJS.ProcessEnv,
	production = false
): EmailPilotAllowlist {
	const raw = env.HAPI_EMAIL_PILOT_ALLOWLIST;
	const applicationId = env.HAPI_EMAIL_PILOT_APPLICATION_ID?.trim();
	const emails = new Set<string>();
	if (raw !== undefined) {
		const entries = raw.split(",");
		if (entries.some(entry => !entry.trim())) throw new Error("HAPI_EMAIL_PILOT_ALLOWLIST must contain exact email addresses");
		for (const entry of entries) {
			try {
				emails.add(normalizeEmail(entry));
			} catch {
				throw new Error("HAPI_EMAIL_PILOT_ALLOWLIST must contain exact email addresses");
			}
		}
	}
	if (applicationId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(applicationId)) {
		throw new Error("HAPI_EMAIL_PILOT_APPLICATION_ID must be a UUID");
	}
	const configured = emails.size > 0 && Boolean(applicationId);
	const enforced = production || raw !== undefined || applicationId !== undefined;
	return {
		configured: production ? configured : emails.size > 0,
		allows: (email, context) => !enforced || (emails.has(normalizeEmail(email)) &&
			(!production && !applicationId || context?.applicationId === applicationId))
	};
}