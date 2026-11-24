import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const PREFIX = "scrypt";
const COST = 16384;
const BLOCK_SIZE = 8;
const PARALLELIZATION = 1;
const KEY_LENGTH = 32;

function derive(secret: string, salt: Buffer): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		scrypt(secret, salt, KEY_LENGTH, { N: COST, r: BLOCK_SIZE, p: PARALLELIZATION, maxmem: 64 * 1024 * 1024 },
			(error, key) => error ? reject(error) : resolve(key));
	});
}

export function isHashedOIDCClientSecret(value: string): boolean {
	return value.startsWith(`${PREFIX}$`);
}

export async function hashOIDCClientSecret(secret: string): Promise<string> {
	if (!secret || secret.includes("\0") || secret.length > 4096) {
		throw new Error("OIDC client secret is missing or malformed");
	}
	const salt = randomBytes(16);
	const derived = await derive(secret, salt);
	return `${PREFIX}$${COST}$${BLOCK_SIZE}$${PARALLELIZATION}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

export async function verifyOIDCClientSecret(stored: string, supplied: string): Promise<boolean> {
	if (!stored || !supplied) return false;
	if (!isHashedOIDCClientSecret(stored)) {
		const storedBuffer = Buffer.from(stored, "utf8");
		const suppliedBuffer = Buffer.from(supplied, "utf8");
		if (storedBuffer.length !== suppliedBuffer.length) return false;
		return timingSafeEqual(storedBuffer, suppliedBuffer);
	}

	if (supplied.includes("\0") || supplied.length > 4096) return false;
	const parts = stored.split("$");
	if (parts.length !== 6 || parts[0] !== PREFIX) return false;
	if (parts[1] !== String(COST) || parts[2] !== String(BLOCK_SIZE) || parts[3] !== String(PARALLELIZATION)) return false;
	const salt = Buffer.from(parts[4], "base64url");
	const expected = Buffer.from(parts[5], "base64url");
	if (salt.length !== 16 || expected.length !== KEY_LENGTH ||
		salt.toString("base64url") !== parts[4] || expected.toString("base64url") !== parts[5]) return false;
	const derived = await derive(supplied, salt);
	return timingSafeEqual(expected, derived);
}
