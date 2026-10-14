import type { FastifyInstance } from "fastify";
import { PostgresApplicationRepository } from "../identity/PostgresApplicationRepository.js";
import { PostgresTenantRepository } from "../identity/PostgresTenantRepository.js";
import { PostgresOIDCClientRepository } from "../identity/PostgresOIDCClientRepository.js";
import { identityRegistry } from "../identity/IdentityRegistry.js";
import type { HapiFaceEnrollmentService } from "./HapiFaceEnrollmentService.js";
import type { ConfiguredEmailOIDCHandoff } from "../adapters/email/EmailVerificationComposition.js";
import { FaceSetupInteractionStore } from "./FaceSetupInteractionStore.js";
import { registerFaceSetupRoutes } from "../routes/faceSetup.js";
import { configuration } from "../config/ConfigurationService.js";

// H5.4: wires the HAPI-owned Face Setup reauthorization ceremony. Only registered once both H5 Face
// enrollment and H4/H6 interactive email authentication are already configured -- neither dependency is
// reimplemented here, both are reused as-is per the documented H5/H4 contracts.
export async function configureFaceSetupCeremony(app: FastifyInstance,
	faceEnrollment: Pick<HapiFaceEnrollmentService, "acceptConsent" | "start" | "status" | "capabilityStatus"> | undefined,
	emailAuthentication: ConfiguredEmailOIDCHandoff | undefined, env = process.env): Promise<void> {
	if (!faceEnrollment || !emailAuthentication?.interactive) return;
	if (env.HAPI_FACE_SETUP_ENABLED !== undefined && !["true", "false"].includes(env.HAPI_FACE_SETUP_ENABLED)) {
		throw new Error("HAPI_FACE_SETUP_ENABLED must be true or false");
	}
	// The pilot allowlist is a certified set of canonical oidc subjects (never raw emails) populated
	// out-of-band once a subject's eligibility has been reviewed; an empty/unset list denies everyone.
	const pilotSubjects = new Set((env.HAPI_FACE_SETUP_PILOT_SUBJECTS ?? "").split(",")
		.map(value => value.trim()).filter(Boolean));
	const clientAuthority = {
		clients: new PostgresOIDCClientRepository(),
		applications: new PostgresApplicationRepository(),
		tenants: new PostgresTenantRepository()
	};
	await registerFaceSetupRoutes(app, {
		interactions: new FaceSetupInteractionStore(),
		service: faceEnrollment,
		interactive: emailAuthentication.interactive,
		identitySubjects: identityRegistry,
		clientAuthority,
		isPilotSubject: sub => pilotSubjects.has(sub),
		isEnabled: () => configuration.getFeatureFlag("HAPI_FACE_SETUP_ENABLED", false)
	});
}
