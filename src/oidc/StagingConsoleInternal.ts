import { randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";

const HEADER = "x-hapi-console-internal";
const marker = randomBytes(32).toString("base64url");

export function stagingConsoleInternalHeaders(): Record<string, string> {
	return { [HEADER]: marker };
}

export function isStagingConsoleInternalRequest(request: FastifyRequest): boolean {
	return request.headers[HEADER] === marker &&
		["/token", "/userinfo", "/jwks"].includes(request.url);
}

export function protectStagingConsoleInternalLogs(app: FastifyInstance): void {
	app.addHook("onRequest", async request => {
		if (isStagingConsoleInternalRequest(request)) request.log.level = "silent";
	});
}
