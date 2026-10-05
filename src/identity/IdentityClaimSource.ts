// Sources permitted to propose identity claims. Only IdentityRegistry may persist them.
export type IdentityClaimSource =
		| "PRIVATE_ID"
		| "GOOGLE"
		| "APPLE"
		| "PASSKEY"
		| "ENTERPRISE"
		| "BOOKWRM"
		| "MANUAL"
		| "SYSTEM"
		// HAPI ID H3: canonical identity claims established from verified HAPI email evidence (H2).
		| "HAPI_EMAIL";
