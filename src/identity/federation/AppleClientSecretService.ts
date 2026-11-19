import { importPKCS8, SignJWT } from "jose";

export const APPLE_CLIENT_SECRET_AUDIENCE = "https://appleid.apple.com";
// Apple accepts client-secret JWTs valid up to 6 months; HAPI mints a fresh short-lived secret
// per authorization-code exchange instead of a long-lived shared artifact.
const DEFAULT_TTL_SECONDS = 300;
const MAX_TTL_SECONDS = 15_777_000;

export type AppleClientSecretConfiguration = {
		// Apple Developer Team ID (JWT iss).
		teamId: string;
		// The Services ID / app bundle ID acting as the OAuth client (JWT sub).
		clientId: string;
		// Key ID of the Apple-issued ES256 signing key (JWT header kid).
		keyId: string;
		// PKCS#8 PEM private key downloaded from Apple. Held only in memory via the secret
		// configuration surface; never logged, persisted, or echoed in errors.
		privateKeyPem: string;
		ttlSeconds?: number;
		now?: () => Date;
};

// HAPI ID V2-D: generates the ES256 client-secret JWT Apple requires at its token endpoint
// (Sign in with Apple docs, "Creating a client secret"). Deliberately stateless: a fresh JWT is
// minted for every server-side authorization-code exchange, so no secret artifact ever needs to
// be stored. The private key never leaves this service and never appears in any error or log.
export class AppleClientSecretService {
		private readonly ttlSeconds: number;
		private readonly now: () => Date;

		constructor(private readonly config: AppleClientSecretConfiguration) {
				for (const field of ["teamId", "clientId", "keyId", "privateKeyPem"] as const) {
						if (typeof config[field] !== "string" || config[field].trim().length === 0) {
								throw new Error(`AppleClientSecretService requires ${field}`);
						}
				}
				this.ttlSeconds = Math.min(config.ttlSeconds ?? DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS);
				if (this.ttlSeconds <= 0) {
						throw new Error("AppleClientSecretService ttlSeconds must be positive");
				}
				this.now = config.now ?? (() => new Date());
		}

		async generate(): Promise<string> {
				let privateKey;
				try {
						privateKey = await importPKCS8(this.config.privateKeyPem, "ES256");
				} catch {
						// Deliberately detail-free: the failure reason could echo key material context.
						throw new Error("Apple client-secret private key is not a valid ES256 PKCS#8 key");
				}
				const issuedAt = Math.floor(this.now().getTime() / 1000);
				return new SignJWT({})
						.setProtectedHeader({ alg: "ES256", kid: this.config.keyId })
						.setIssuer(this.config.teamId)
						.setSubject(this.config.clientId)
						.setAudience(APPLE_CLIENT_SECRET_AUDIENCE)
						.setIssuedAt(issuedAt)
						.setExpirationTime(issuedAt + this.ttlSeconds)
						.sign(privateKey);
		}
}
