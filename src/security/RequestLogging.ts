import type { FastifyInstance, FastifyRequest } from "fastify";

export function requestLogPath(url: string): string {
	return url.split("?", 1)[0];
}

export function serializeRequestForLog(request: FastifyRequest) {
	return {
		method: request.method, url: requestLogPath(request.url),
		version: typeof request.headers["accept-version"] === "string" ? request.headers["accept-version"] : undefined,
		host: request.host, remoteAddress: request.socket?.remoteAddress, remotePort: request.socket?.remotePort
	};
}

export function registerPathOnlyNotFoundHandler(app: FastifyInstance): void {
	app.setNotFoundHandler((request, reply) => {
		const message = `Route ${request.method}:${requestLogPath(request.url)} not found`;
		request.log.info(message);
		return reply.code(404).send({ message, error: "Not Found", statusCode: 404 });
	});
}
