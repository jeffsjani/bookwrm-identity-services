import { domainToASCII } from "node:url";
import { VerificationError } from "./VerificationChallenge.js";

export function normalizeEmail(input: string): string {
	const email = input.trim();
	const separator = email.lastIndexOf("@");
	const local = email.slice(0, separator);
	const domainInput = email.slice(separator + 1);
	const domain = /^[\p{L}\p{N}\p{M}.\u3002\uFF0E\uFF61-]+$/u.test(domainInput) ? domainToASCII(domainInput).toLowerCase() : "";
	const normalized = `${local}@${domain}`;
	if (separator < 1 || local.length > 64 || email.length > 254 || normalized.length > 254 ||
		! /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local) ||
		local.startsWith(".") || local.endsWith(".") || local.includes("..") ||
		!domain.includes(".") || domain.length > 253 ||
		!domain.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
		throw new VerificationError("INVALID_EMAIL");
	}
	return normalized;
}