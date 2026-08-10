import dotenv from "dotenv";

dotenv.config();

export type ConfigurationEnvironment = "development" | "test" | "production" | string;

export type ConfigurationSnapshot = Record<string, string | undefined>;

export type RedisConfiguration = {
		url?: string;
		host: string;
		port: number;
		password?: string;
		tls: boolean;
		enabled: boolean;
};

export type OIDCKeyConfiguration = {
		privateKey: string[];
		publicKey: string[];
		jwksJson?: string;
};

const DEFAULTS = {
		NODE_ENV: "development",
		PORT: "3000",
		LOG_LEVEL: "info",
		REDIS_HOST: "127.0.0.1",
		REDIS_PORT: "6379",
		REDIS_TLS: "false",
		OIDC_USE_REDIS_MOCK: "false",
		OIDC_RATE_LIMIT_IP: "120",
		OIDC_RATE_LIMIT_CLIENT: "300",
		OIDC_RATE_LIMIT_USER: "180",
		OIDC_KEY_ROTATION_INTERVAL_SECONDS: "3600",
		OIDC_CACHE_TTL_SECONDS: "60",
		OIDC_BREAKER_FAILURE_THRESHOLD: "5",
		OIDC_BREAKER_RESET_TIMEOUT_MS: "30000",
		OIDC_ENABLED: "true",
		PRIVATEID_MOCK_MODE: "false",
		MOCK_AUTH_ENABLED: "true",
		REDIS_ENABLED: "true",
		CACHE_ENABLED: "true",
		METRICS_ENABLED: "true"
} as const;

export class ConfigurationService {
		private snapshot: ConfigurationSnapshot;

		constructor(snapshot: ConfigurationSnapshot = process.env) {
				this.snapshot = { ...snapshot };
		}

		reload(): void {
				this.snapshot = { ...process.env };
		}

		get(key: string, fallback?: string): string | undefined {
				const value = this.snapshot[key] ?? process.env[key];
				return value ?? fallback;
		}

		require(key: string): string {
				const value = this.get(key);
				if (typeof value !== "string" || value.trim().length === 0) {
						throw new Error(`Missing required configuration value: ${key}`);
				}

				return value;
		}

		getNumber(key: string, fallback: number): number {
				const value = this.get(key);
				if (typeof value !== "string" || value.trim().length === 0) {
						return fallback;
				}

				const parsed = Number(value);
				return Number.isFinite(parsed) ? parsed : fallback;
		}

		getBoolean(key: string, fallback: boolean): boolean {
				const value = this.get(key);
				if (typeof value !== "string") {
						return fallback;
				}

				const normalized = value.trim().toLowerCase();
				if (normalized === "true") {
						return true;
				}

				if (normalized === "false") {
						return false;
				}

				return fallback;
		}

		getEnvironment(): ConfigurationEnvironment {
				return this.get("NODE_ENV", DEFAULTS.NODE_ENV) ?? DEFAULTS.NODE_ENV;
		}

		isProduction(): boolean {
				return this.getEnvironment() === "production";
		}

		isTest(): boolean {
				return this.getEnvironment() === "test";
		}

		getPort(): number {
				return this.getNumber("PORT", Number(DEFAULTS.PORT));
		}

		getLogLevel(): string {
				return this.get("LOG_LEVEL", DEFAULTS.LOG_LEVEL) ?? DEFAULTS.LOG_LEVEL;
		}

		getBase44BaseUrl(): string {
				return this.require("BASE44_BASE_URL");
		}

		getIdentityApiPath(): string {
				return this.require("IDENTITY_API_PATH");
		}

		getIdentityApiKey(): string {
				return this.require("BOOKWRM_IDENTITY_API_KEY");
		}

		getOidcIssuer(defaultIssuer: string): string {
				return this.get("OIDC_ISSUER", defaultIssuer) ?? defaultIssuer;
		}

		getRedisConfiguration(): RedisConfiguration {
				const url = this.get("REDIS_URL");
				const enabled = this.getBoolean("REDIS_ENABLED", true);

				return {
						url: url && url.trim().length > 0 ? url.trim() : undefined,
						host: this.get("REDIS_HOST", DEFAULTS.REDIS_HOST) ?? DEFAULTS.REDIS_HOST,
						port: this.getNumber("REDIS_PORT", Number(DEFAULTS.REDIS_PORT)),
						password: this.get("REDIS_PASSWORD")?.trim() || undefined,
						tls: this.getBoolean("REDIS_TLS", false),
						enabled
				};
		}

		getOIDCKeyConfiguration(): OIDCKeyConfiguration {
				return {
						privateKey: this.readMultilineValues("JWT_PRIVATE_KEY"),
						publicKey: this.readMultilineValues("JWT_PUBLIC_KEY"),
						jwksJson: this.get("OIDC_JWKS_JSON")?.trim() || undefined
				};
		}

		getFeatureFlag(key: string, fallback: boolean): boolean {
				return this.getBoolean(key, fallback);
		}

		getDefaults(): typeof DEFAULTS {
				return DEFAULTS;
		}

		validatePrivateIdConfiguration(): void {
				if (!this.isProduction()) {
						return;
				}

				const redirectUrl = this.get("PRIVATEID_REDIRECT_URL")?.trim();
				if (!redirectUrl) {
						throw new Error("Configuration validation failed: PRIVATEID_REDIRECT_URL is required in production");
				}
		}

		private readMultilineValues(key: string): string[] {
				const raw = this.get(key);
				if (!raw) {
						return [];
				}

				const trimmed = raw.trim();
				if (!trimmed) {
						return [];
				}

				if (trimmed.startsWith("[")) {
						try {
							const parsed = JSON.parse(trimmed) as string[];
							return parsed.map((entry) => this.normalizeMultilineValue(entry));
						} catch {
							return [this.normalizeMultilineValue(trimmed)];
						}
				}

				const pemBlocks = trimmed.match(/-----BEGIN [^-]+-----[\s\S]+?-----END [^-]+-----/g);
				if (pemBlocks && pemBlocks.length > 0) {
						return pemBlocks.map((entry) => this.normalizeMultilineValue(entry));
				}

				return [this.normalizeMultilineValue(trimmed)];
		}

		private normalizeMultilineValue(value: string): string {
				return value.replace(/\\n/g, "\n").trim();
		}
}

export const configuration = new ConfigurationService();