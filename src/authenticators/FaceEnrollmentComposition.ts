import type pg from "pg";
import type { FastifyInstance } from "fastify";
import { getPostgresPool } from "../identity/infrastructure/PostgresInfrastructure.js";
import { RedisOIDCStore } from "../oidc/infrastructure/RedisOIDCStore.js";
import { PrivateIDClient } from "../privateid/PrivateIDClient.js";
import { markHapiFaceEnrollmentSession } from "../privateid/PrivateIDSessionStore.js";
import { registerHapiFaceEnrollmentRoutes } from "../routes/hapiFaceEnrollment.js";
import { PostgresFaceEnrollmentRepository } from "./PostgresFaceEnrollmentRepository.js";
import { HapiFaceEnrollmentService } from "./HapiFaceEnrollmentService.js";

// H5.4: the richer HapiFaceEnrollmentService (not just the webhook/callback FaceEnrollmentCallbacks pick)
// is returned so the Face Setup ceremony can call capabilityStatus/acceptConsent/start/status directly,
// in-process, instead of making HTTP calls back into /v1 (see H5.4 #11). /v1 routes are unaffected.
export async function configureFaceEnrollment(app: FastifyInstance, env = process.env): Promise<HapiFaceEnrollmentService | undefined> {
	if (env.HAPI_FACE_ENROLLMENT_ENABLED !== undefined && !["true", "false"].includes(env.HAPI_FACE_ENROLLMENT_ENABLED)) {
		throw new Error("HAPI_FACE_ENROLLMENT_ENABLED must be true or false");
	}
	const enabled = env.HAPI_FACE_ENROLLMENT_ENABLED === "true";
	if ((env.IDENTITY_REGISTRY_DRIVER ?? "postgres").trim().toLowerCase() === "memory") {
		if (enabled) throw new Error("HAPI Face enrollment requires PostgreSQL");
		return;
	}
	if (enabled && env.HAPI_EMAIL_AUTHENTICATION_ENABLED !== "true") {
		throw new Error("HAPI Face enrollment requires H4 email authentication");
	}
	const repository = new PostgresFaceEnrollmentRepository(getPostgresPool() as pg.Pool);
	await repository.ensureSchema();
	const provider = new PrivateIDClient();
	const service = new HapiFaceEnrollmentService(repository, async transactionId => {
		const session = await provider.createEnrollmentSession(transactionId, AbortSignal.timeout(10_000));
		markHapiFaceEnrollmentSession(session.sessionId);
		return session;
	}, enabled);
	await registerHapiFaceEnrollmentRoutes(app, service, new RedisOIDCStore());
	// Always recognize durable H5 transactions so disabling cannot send them into legacy identity creation.
	return service;
}
