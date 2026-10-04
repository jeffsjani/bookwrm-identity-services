export interface VerificationPolicy {
	otpLength: number;
	expirationSeconds: number;
	maxAttempts: number;
	resendCooldownSeconds: number;
	maxSendsPerChallenge: number;
	maxSendsPerDestinationHour: number;
	maxSendsPerDestinationDay: number;
	providerTimeoutMs: number;
}

export const defaultVerificationPolicy: Readonly<VerificationPolicy> = Object.freeze({
	otpLength: 6,
	expirationSeconds: 600,
	maxAttempts: 5,
	resendCooldownSeconds: 60,
	maxSendsPerChallenge: 5,
	maxSendsPerDestinationHour: 10,
	maxSendsPerDestinationDay: 30,
	providerTimeoutMs: 10_000
});

export function verificationPolicyFromEnvironment(env: NodeJS.ProcessEnv): VerificationPolicy {
	const policy = { ...defaultVerificationPolicy };
	for (const key of Object.keys(policy) as (keyof VerificationPolicy)[]) {
		const variable = `HAPI_EMAIL_${key.replace(/[A-Z]/g, character => `_${character}`).toUpperCase()}`;
		if (env[variable] !== undefined) policy[key] = Number(env[variable]);
		if (!Number.isSafeInteger(policy[key]) || policy[key] < 1) throw new Error(`Invalid ${variable}`);
	}
	if (policy.otpLength < 6 || policy.otpLength > 9) throw new Error("HAPI_EMAIL_OTP_LENGTH must be between 6 and 9");
	return policy;
}