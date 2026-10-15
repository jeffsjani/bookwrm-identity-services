import type { FastifyRequest } from "fastify";
import { bucketRemainingTtl, type RemainingTtlBucket } from "../oidc/UniversalLoginDiagnostics.js";
import type { FaceSetupInspection } from "./FaceSetupInteractionStore.js";
import { FACE_SETUP_COOKIE, type FaceSetupInteraction } from "./FaceSetupTypes.js";

type FaceSetupEvent =
	| "FACE_SETUP_INTERACTION_CREATED" | "FACE_SETUP_INTERACTION_LOADED"
	| "FACE_SETUP_CONSENT_STARTED" | "FACE_SETUP_CONSENT_ACCEPTED"
	| "FACE_SETUP_DUPLICATE_SUBMISSION" | "FACE_SETUP_ENROLLMENT_STARTED"
	| "FACE_SETUP_INTERACTION_CONSUMED" | "FACE_SETUP_INTERACTION_FAILED"
	| "FACE_SETUP_CALLBACK_PENDING" | "FACE_SETUP_CALLBACK_RESOLVED";
export type FaceSetupReason =
	| "COOKIE_MISSING" | "INTERACTION_NOT_FOUND" | "INTERACTION_INVALID" | "INTERACTION_EXPIRED"
	| "INTERACTION_ALREADY_CONSUMED" | "CSRF_MISMATCH" | "PHASE_INVALID"
	| "AUTHORITY_INVALID" | "CLIENT_INVALID" | "INTERACTION_SAVE_FAILED" | "INTERACTION_STORE_UNAVAILABLE"
	| "ENROLLMENT_FAILED" | "ENROLLMENT_CONFLICT" | "UNEXPECTED_FAILURE";
type Fields = {
	event: FaceSetupEvent;
	requestId: string;
	cookiePresent: boolean;
	interactionFound: boolean;
	interactionState: string;
	remainingTtlBucket: RemainingTtlBucket;
	reasonCode?: FaceSetupReason;
	httpStatus: number;
};

export function logFaceSetup(request: FastifyRequest, event: FaceSetupEvent, httpStatus: number,
	interaction?: FaceSetupInteraction, reasonCode?: FaceSetupReason, inspection?: FaceSetupInspection): void {
	const fields: Fields = {
		event, requestId: request.id,
		cookiePresent: Boolean(request.headers.cookie?.split(";").some(value => value.trim().startsWith(`${FACE_SETUP_COOKIE}=`))),
		interactionFound: Boolean(interaction),
		interactionState: event === "FACE_SETUP_INTERACTION_CONSUMED" ? "consumed" : interaction?.phase ?? inspection?.state ?? "unknown",
		remainingTtlBucket: bucketRemainingTtl(inspection?.remainingMs ??
			(interaction ? interaction.expiresAt - Date.now() : undefined)),
		reasonCode, httpStatus
	};
	request.log.info(fields, "Face Setup lifecycle");
}
