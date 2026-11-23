import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const PREFIX = "scrypt";
const COST = 16384;
const BLOCK_SIZE = 8;
const PARALLELIZATION = 1;
const KEY_LENGTH = 32;

export function isHashedOIDCClientSecret(value: string): boolean {
	return value.startsWith(`${PREFIX}$`);
}

export async function hashOIDCClientSecret(secret: string): Promise<string> {
	if (!secret || secret.includes("\0") || secret.length > 4096) {
		throw new Error("OIDC client secret is missing or malformed");
	}
	const salt = randomBytes(16);
	const derived = scryptSync(secret, salt, KEY_LENGTH, {
		N: COST,
		p: PARALLELIZATION,
		r: BLOCK_SIZE,
		maxmem: 64 * 1024 * 1024
	}) as Buffer;
	return `${PREFIX}$${COST}$${BLOCK_SIZE}$${PARALLELIZATION}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

export async function verifyOIDCClientSecret(stored: string, supplied: string): Promise<boolean> {
	if (!stored || !supplied || supplied.includes("\0") || supplied.length > 4096) return false;
	if (!isHashedOIDCClientSecret(stored)) {
		const storedBuffer = Buffer.from(stored, "utf8");
		const suppliedBuffer = Buffer.from(supplied, "utf8");
		if (storedBuffer.length !== suppliedBuffer.length) return false;
		return timingSafeEqual(storedBuffer, suppliedBuffer);
	}

	const parts = stored.split("$");
	if (parts.length !== 6 || parts[0] !== PREFIX) return false;
	const cost = Number(parts[1]);
	const blockSize = Number(parts[2]);
	const parallelization = Number(parts[3]);
	if (!Number.isInteger(cost) || cost < COST || cost > 1048576 ||
		!Number.isInteger(blockSize) || blockSize !== BLOCK_SIZE ||
		!Number.isInteger(parallelization) || parallelization !== PARALLELIZATION) return false;
	try {
		const salt = Buffer.from(parts[4], "base64url");
		const expected = Buffer.from(parts[5], "base64url");
		if (salt.length !== 16 || expected.length !== KEY_LENGTH) return false;
		const derived = scryptSync(supplied, salt, KEY_LENGTH, {
			N: cost,
			p: parallelization,
			r: blockSize,
			maxmem: 128 * 1024 * 1024
		});
		return timingSafeEqual(expected, derived);
	} catch {
		return false;
	}
}
