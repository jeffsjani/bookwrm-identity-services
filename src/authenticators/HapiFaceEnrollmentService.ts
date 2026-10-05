import type { PrivateIDSession } from "../privateid/PrivateIDSession.js";
import {
	FaceEnrollmentError, requireRecentEmailAuthority, requireStatusAuthority,
	type FaceEnrollmentAuthority, type FaceEnrollmentCallbacks, type FaceEnrollmentRepository
} from "./FaceEnrollmentTypes.js";

export class HapiFaceEnrollmentService implements FaceEnrollmentCallbacks {
	constructor(private readonly repository: FaceEnrollmentRepository,
		private readonly createSession: (transactionId: string) => Promise<PrivateIDSession>,
		private readonly enabled = true) {}

	async start(authority: FaceEnrollmentAuthority) {
		if (!this.enabled) throw new FaceEnrollmentError("FACE_ENROLLMENT_DISABLED", 404);
		requireRecentEmailAuthority(authority);
		const reservation = await this.repository.reserve(authority);
		if (reservation.alreadyEnrolled) return { enrolled: true, alreadyEnrolled: true };
		let session: PrivateIDSession;
		try {
			session = await this.createSession(reservation.providerTransactionId);
		} catch {
			await this.repository.fail(reservation.providerTransactionId);
			// Provider exceptions can include raw response bodies; never expose them in route logs.
			throw new FaceEnrollmentError("PROVIDER_SESSION_FAILED", 502);
		}
		try {
			let launchUrl: URL;
			try { launchUrl = new URL(session.launchUrl); }
			catch { throw new FaceEnrollmentError("INVALID_PROVIDER_SESSION", 502); }
			if (session.transactionId !== reservation.providerTransactionId ||
				!session.sessionId || launchUrl.protocol !== "https:" ||
				!Number.isFinite(session.expires) || session.expires <= Date.now()) {
				throw new FaceEnrollmentError("INVALID_PROVIDER_SESSION", 502);
			}
			const expiresAt = await this.repository.bind(reservation, session);
			return { enrolled: false, enrollmentId: reservation.providerTransactionId,
				launchUrl: session.launchUrl, expiresAt };
		} catch (error) {
			await this.repository.fail(reservation.providerTransactionId);
			throw error;
		}
	}

	webhook(transactionId: string | undefined, sessionId: string | undefined, status: string, puid: string | undefined) {
		return this.repository.webhook(transactionId, sessionId, status, puid, this.enabled);
	}

	status(enrollmentId: string, authority: FaceEnrollmentAuthority) {
		if (!this.enabled) throw new FaceEnrollmentError("FACE_ENROLLMENT_DISABLED", 404);
		requireStatusAuthority(authority);
		return this.repository.status(enrollmentId, authority);
	}

	callback(transactionId: string | undefined, sessionId: string | undefined) {
		return this.repository.callback(transactionId, sessionId);
	}
}
