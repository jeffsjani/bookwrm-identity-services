import dotenv from "dotenv";

dotenv.config();

function requireEnv(name: string): string {
		const value = process.env[name];

		if (!value) {
				throw new Error(`Missing required environment variable: ${name}`);
		}

		return value;
}

export const env = {

		NODE_ENV: process.env.NODE_ENV ?? "development",

		PORT: Number(process.env.PORT ?? 3000),

		LOG_LEVEL: process.env.LOG_LEVEL ?? "info",

		BASE44_BASE_URL: requireEnv("BASE44_BASE_URL"),

		IDENTITY_API_PATH: requireEnv("IDENTITY_API_PATH"),

		BOOKWRM_IDENTITY_API_KEY:
				requireEnv("BOOKWRM_IDENTITY_API_KEY")

};

export type Env = typeof env;
