// Sources permitted to propose identity claims. Only IdentityRegistry may persist them.
export type IdentityClaimSource =
		| "PRIVATE_ID"
		| "GOOGLE"
		| "APPLE"
		| "PASSKEY"
		| "ENTERPRISE"
		| "MANUAL"
		| "SYSTEM";
