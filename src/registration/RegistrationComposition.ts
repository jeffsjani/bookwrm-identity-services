import type pg from "pg";
import type { FastifyInstance } from "fastify";
import { getPostgresPool } from "../identity/infrastructure/PostgresInfrastructure.js";
import { PostgresApplicationRepository } from "../identity/PostgresApplicationRepository.js";
import { PostgresTenantRepository } from "../identity/PostgresTenantRepository.js";
import { PostgresOIDCClientRepository } from "../identity/PostgresOIDCClientRepository.js";
import { PostgresRegistrationRepository } from "./PostgresRegistrationRepository.js";
import { RegistrationService } from "./RegistrationService.js";
import { registerRegistrationRoutes } from "../routes/registration.js";

// H3 is always active on the Postgres Identity Registry driver (it has no in-memory production
// mode -- "memory" is test-only, see InMemoryRegistrationRepository). Mirrors
// adapters/email/EmailVerificationComposition.ts's wiring shape.
export async function configureRegistration(app: FastifyInstance, env = process.env): Promise<void> {
	if ((env.IDENTITY_REGISTRY_DRIVER ?? "postgres").trim().toLowerCase() === "memory") return;
	const repository = new PostgresRegistrationRepository(getPostgresPool() as pg.Pool);
	await repository.ensureSchema();
	const service = new RegistrationService(repository);
	await registerRegistrationRoutes(app, service, {
		clients: new PostgresOIDCClientRepository(), applications: new PostgresApplicationRepository(), tenants: new PostgresTenantRepository()
	});
}
