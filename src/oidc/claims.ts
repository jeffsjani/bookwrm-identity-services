export const oidcClaims = {
		openid: ["sub"],
		profile: ["name", "family_name", "given_name", "preferred_username"],
		email: ["email", "email_verified"]
} as const;
