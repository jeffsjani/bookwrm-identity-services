import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type pg from "pg";
import { PrivateIDEnrollmentTransactionRepository } from "../identity/PrivateIDEnrollmentTransactionRepository.js";
import { UserAuthenticatorRepository } from "../identity/UserAuthenticatorRepository.js";
import type { PrivateIDSession } from "../privateid/PrivateIDSession.js";
import {
	FaceEnrollmentError, FACE_ENROLLMENT_TTL_MS, requireRecentEmailAuthority,
	type FaceEnrollmentAuthority, type FaceEnrollmentReply, type FaceEnrollmentReservation
} from "./FaceEnrollmentTypes.js";

type Binding = {
	enrollment_id: string; identity_subject_id: string; tenant_id: string; application_id: string;
	client_id: string; session_id: string | null; authenticator_id: string | null;
	provider_transaction_id: string; status: string; expires_at: Date;
};
type Context = Pick<Binding, "identity_subject_id" | "tenant_id" | "application_id" | "client_id">;
type AuditType = "AUTHENTICATOR_ENROLLMENT_STARTED" | "AUTHENTICATOR_ENROLLED" |
	"AUTHENTICATOR_ALREADY_ACTIVE" | "AUTHENTICATOR_ENROLLMENT_CONFLICT" | "AUTHENTICATOR_ENROLLMENT_FAILED";

export class PostgresFaceEnrollmentRepository {
	constructor(private readonly pool: pg.Pool) {}

	async ensureSchema(): Promise<void> {
		await this.pool.query(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
	}

	private async transaction<T>(work: (client: pg.PoolClient) => Promise<T>): Promise<T> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = await work(client);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally { client.release(); }
	}

	private async now(client: pg.PoolClient): Promise<Date> {
		return (await client.query<{ now: Date }>("SELECT clock_timestamp() AS now")).rows[0].now;
	}

	private async audit(client: pg.PoolClient, binding: Context, enrollmentId: string | null,
		type: AuditType, outcome: string): Promise<void> {
		await client.query(`INSERT INTO authenticator_enrollment_audit
			(id,tenant_id,application_id,client_id,identity_subject_id,enrollment_id,provider,type,outcome,occurred_at)
			VALUES ($1,$2,$3,$4,$5,$6,'privateid',$7,$8,clock_timestamp())`,
		[randomUUID(), binding.tenant_id, binding.application_id, binding.client_id,
			binding.identity_subject_id, enrollmentId, type, outcome]);
	}

	private async activeContext(client: pg.PoolClient, subjectId: string, clientId: string): Promise<Context | undefined> {
		const result = await client.query<Context>(`SELECT i.id AS identity_subject_id,
			t.id AS tenant_id,a.id AS application_id,c.client_id FROM identity_subjects i
			JOIN applications a ON a.id=i.application_id JOIN tenants t ON t.id=a.tenant_id
			JOIN oidc_clients c ON c.application_id=a.id
			WHERE i.id=$1 AND c.client_id=$2 AND i.status='ACTIVE'
			AND i.primary_provider='HAPI_EMAIL' AND i.email_verified=true
			AND i.email=i.primary_provider_subject AND a.status='active' AND t.status='active'
			AND c.token_endpoint_auth_method<>'none' FOR SHARE OF a,t,c`, [subjectId, clientId]);
		return result.rows[0];
	}

	async reserve(authority: FaceEnrollmentAuthority): Promise<FaceEnrollmentReservation> {
		const result = await this.transaction(async client => {
			const subject = (await client.query<{ id: string }>(
				"SELECT id FROM identity_subjects WHERE oidc_subject::text=$1 FOR UPDATE", [authority.sub])).rows[0];
			const context = subject ? await this.activeContext(client, subject.id, authority.clientId) : undefined;
			const now = await this.now(client);
			requireRecentEmailAuthority(authority, now.getTime());
			if (!subject || !context) throw new FaceEnrollmentError("ENROLLMENT_NOT_AUTHORIZED", 403);
			const active = (await new UserAuthenticatorRepository(client).findByUser(subject.id))
				.find(authenticator => authenticator.status === "active" && authenticator.authenticatorType === "face");
			if (active) {
				await this.audit(client, context, null, "AUTHENTICATOR_ALREADY_ACTIVE", "ALREADY_ACTIVE");
				return { alreadyEnrolled: true } as const;
			}
			const pending = (await client.query<Binding>(`SELECT b.*,e.provider_transaction_id,e.status,e.expires_at
				FROM hapi_face_enrollment_bindings b JOIN privateid_enrollment_transactions e ON e.id=b.enrollment_id
				WHERE b.identity_subject_id=$1 AND e.status='pending' FOR UPDATE OF e`, [subject.id])).rows;
			for (const binding of pending) {
				if (binding.expires_at > now) {
					await this.audit(client, context, binding.enrollment_id,
						"AUTHENTICATOR_ENROLLMENT_CONFLICT", "ENROLLMENT_IN_PROGRESS");
					return new FaceEnrollmentError("ENROLLMENT_IN_PROGRESS");
				}
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(binding.enrollment_id, "expired", now);
				await this.audit(client, context, binding.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED", "EXPIRED");
			}
			const transactionId = randomUUID();
			const providerTransactionId = randomUUID();
			await new PrivateIDEnrollmentTransactionRepository(client).create({
				id: transactionId, userId: subject.id, providerTransactionId, purpose: "face_enrollment",
				status: "pending", expiresAt: new Date(now.getTime() + FACE_ENROLLMENT_TTL_MS).toISOString()
			});
			await client.query(`INSERT INTO hapi_face_enrollment_bindings
				(enrollment_id,identity_subject_id,tenant_id,application_id,client_id,authenticated_at)
				VALUES ($1,$2,$3,$4,$5,$6)`, [transactionId, subject.id, context.tenant_id,
				context.application_id, context.client_id, new Date(authority.authenticatedAt!)]);
			return { alreadyEnrolled: false, transactionId, providerTransactionId } as const;
		});
		if (result instanceof FaceEnrollmentError) throw result;
		return result;
	}

	private async find(client: pg.Pool | pg.PoolClient, transactionId?: string, sessionId?: string): Promise<Binding | undefined> {
		const rows = (await client.query<Binding>(`SELECT b.*,e.provider_transaction_id,e.status,e.expires_at
			FROM hapi_face_enrollment_bindings b JOIN privateid_enrollment_transactions e ON e.id=b.enrollment_id
			WHERE e.provider_transaction_id::text=$1 OR b.session_id=$2`,
		[transactionId ?? null, sessionId ?? null])).rows;
		if (rows.length > 1) throw new FaceEnrollmentError("ENROLLMENT_BINDING_MISMATCH", 400);
		return rows[0];
	}

	async bind(reservation: Extract<FaceEnrollmentReservation, { alreadyEnrolled: false }>, session: PrivateIDSession): Promise<string> {
		return this.transaction(async client => {
			const binding = await this.find(client, reservation.providerTransactionId);
			if (!binding || binding.enrollment_id !== reservation.transactionId) throw new FaceEnrollmentError("INVALID_ENROLLMENT");
			await client.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [binding.identity_subject_id]);
			await client.query("SELECT id FROM privateid_enrollment_transactions WHERE id=$1 FOR UPDATE", [binding.enrollment_id]);
			const current = await this.find(client, reservation.providerTransactionId);
			const context = await this.activeContext(client, binding.identity_subject_id, binding.client_id);
			const now = await this.now(client);
			if (!current || current.status !== "pending" || current.session_id || !context ||
				context.tenant_id !== binding.tenant_id || context.application_id !== binding.application_id ||
				current.expires_at <= now) throw new FaceEnrollmentError("INVALID_ENROLLMENT");
			const expiresAt = new Date(Math.min(session.expires, current.expires_at.getTime()));
			if (expiresAt <= now) throw new FaceEnrollmentError("INVALID_PROVIDER_SESSION", 502);
			await client.query("UPDATE hapi_face_enrollment_bindings SET session_id=$2 WHERE enrollment_id=$1",
				[binding.enrollment_id, session.sessionId]);
			await client.query("UPDATE privateid_enrollment_transactions SET expires_at=$2 WHERE id=$1",
				[binding.enrollment_id, expiresAt]);
			await this.audit(client, context, binding.enrollment_id, "AUTHENTICATOR_ENROLLMENT_STARTED", "CEREMONY_READY");
			return expiresAt.toISOString();
		});
	}

	async fail(providerTransactionId: string): Promise<void> {
		await this.transaction(async client => {
			const binding = await this.find(client, providerTransactionId);
			if (!binding) throw new FaceEnrollmentError("INVALID_ENROLLMENT");
			await client.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [binding.identity_subject_id]);
			await client.query("SELECT id FROM privateid_enrollment_transactions WHERE id=$1 FOR UPDATE", [binding.enrollment_id]);
			const current = await this.find(client, providerTransactionId);
			if (current?.status === "pending") {
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(binding.enrollment_id, "failed", await this.now(client));
				await this.audit(client, binding, binding.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED", "PROVIDER_SESSION_FAILED");
			}
		});
	}

	async webhook(transactionId: string | undefined, sessionId: string | undefined,
		status: string, puid: string | undefined, enabled: boolean): Promise<FaceEnrollmentReply | undefined> {
		return this.transaction(async client => {
			const binding = await this.find(client, transactionId, sessionId);
			if (!binding) return undefined;
			if (!enabled) return { statusCode: 503, body: { error: "FACE_ENROLLMENT_DISABLED" } };
			if (!transactionId || binding.provider_transaction_id !== transactionId ||
				!binding.session_id || (sessionId && binding.session_id !== sessionId)) {
				await this.audit(client, binding, binding.enrollment_id, "AUTHENTICATOR_ENROLLMENT_CONFLICT", "BINDING_MISMATCH");
				return { statusCode: 400, body: { error: "ENROLLMENT_BINDING_MISMATCH" } };
			}
			// Same lock ordering for start, publish, failure, and completion.
			await client.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [binding.identity_subject_id]);
			await client.query("SELECT id FROM privateid_enrollment_transactions WHERE id=$1 FOR UPDATE", [binding.enrollment_id]);
			const current = await this.find(client, transactionId);
			if (!current) throw new FaceEnrollmentError("INVALID_ENROLLMENT");
			const now = await this.now(client);
			const authenticators = new UserAuthenticatorRepository(client);
			if (current.status === "completed") {
				const authenticator = puid ? await authenticators.findByProviderSubject("privateid", puid) : undefined;
				if (status === "SUCCESS" && authenticator?.id === current.authenticator_id &&
					authenticator.userId === current.identity_subject_id && authenticator.status === "active") {
					await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ALREADY_ACTIVE", "IDEMPOTENT_COMPLETION");
					return { statusCode: 200, body: { enrolled: true, alreadyEnrolled: true } };
				}
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_CONFLICT", "COMPLETED_EVIDENCE_MISMATCH");
				return { statusCode: 409, body: { error: "ENROLLMENT_CONFLICT" } };
			}
			if (current.status !== "pending") return { statusCode: 409, body: { error: "ENROLLMENT_NOT_PENDING" } };
			const context = await this.activeContext(client, current.identity_subject_id, current.client_id);
			const freshNow = await this.now(client);
			if (current.expires_at <= freshNow || !context || context.tenant_id !== current.tenant_id ||
				context.application_id !== current.application_id) {
				const expired = current.expires_at <= freshNow;
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, expired ? "expired" : "failed", freshNow);
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED",
					expired ? "EXPIRED" : "AUTHORITY_NO_LONGER_ACTIVE");
				return { statusCode: 409, body: { error: "ENROLLMENT_NOT_AUTHORIZED" } };
			}
			if (status === "PENDING" || status === "REQUIRES_INPUT") {
				return { statusCode: 200, body: { enrolled: false, status: "pending" } };
			}
			if (status === "FAILURE" || status === "EXPIRED") {
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, status === "EXPIRED" ? "expired" : "failed", now);
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED", "PROVIDER_REJECTED");
				return { statusCode: 200, body: { enrolled: false, status: "failed" } };
			}
			if (status !== "SUCCESS" || !puid || puid.length > 1024) {
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED", "INVALID_PROVIDER_EVIDENCE");
				return { statusCode: 400, body: { error: "INVALID_PROVIDER_EVIDENCE" } };
			}
			// Serializes the absent-row case across different subjects sharing a PUID.
			await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", ["hapi-face:" + puid]);
			const providerIdentity = (await client.query<{ id: string }>(`SELECT id FROM identity_subjects
				WHERE primary_provider='PrivateID' AND primary_provider_subject=$1 FOR SHARE`, [puid])).rows[0];
			await client.query("SELECT id FROM user_authenticators WHERE provider='privateid' AND provider_subject=$1 FOR UPDATE", [puid]);
			const existing = await authenticators.findByProviderSubject("privateid", puid);
			const active = (await authenticators.findByUser(current.identity_subject_id))
				.find(authenticator => authenticator.status === "active" && authenticator.authenticatorType === "face");
			if (providerIdentity || (existing && (existing.userId !== current.identity_subject_id || existing.status !== "active")) ||
				(active && active.providerSubject !== puid)) {
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, "failed", now);
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_CONFLICT", "AUTHENTICATOR_OWNERSHIP_CONFLICT");
				return { statusCode: 409, body: { error: "ENROLLMENT_CONFLICT" } };
			}
			const afterLock = await this.now(client);
			if (current.expires_at <= afterLock) {
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, "expired", afterLock);
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED", "EXPIRED");
				return { statusCode: 409, body: { error: "ENROLLMENT_NOT_AUTHORIZED" } };
			}
			// Existing uniqueness constraints remain the final defense against legacy concurrent writers.
			await client.query("SAVEPOINT authenticator_insert");
			const inserted = existing ?? (await client.query<{ id: string }>(`INSERT INTO user_authenticators
				(id,user_id,provider,provider_subject,authenticator_type,status,linked_at,verified_at,created_at,updated_at)
				VALUES ($1,$2,'privateid',$3,'face','active',$4,$4,$4,$4) ON CONFLICT DO NOTHING RETURNING id`,
			[randomUUID(), current.identity_subject_id, puid, afterLock])).rows[0];
			const concurrent = !inserted ? await authenticators.findByProviderSubject("privateid", puid) : undefined;
			const authenticator = inserted ?? (concurrent?.userId === current.identity_subject_id &&
				concurrent.status === "active" ? concurrent : undefined);
			const completedAt = await this.now(client);
			if (current.expires_at <= completedAt) {
				await client.query("ROLLBACK TO SAVEPOINT authenticator_insert");
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, "expired", completedAt);
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_FAILED", "EXPIRED");
				return { statusCode: 409, body: { error: "ENROLLMENT_NOT_AUTHORIZED" } };
			}
			if (!authenticator) {
				await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, "failed", completedAt);
				await this.audit(client, current, current.enrollment_id, "AUTHENTICATOR_ENROLLMENT_CONFLICT", "CONCURRENT_AUTHENTICATOR_CONFLICT");
				return { statusCode: 409, body: { error: "ENROLLMENT_CONFLICT" } };
			}
			await client.query("UPDATE hapi_face_enrollment_bindings SET authenticator_id=$2 WHERE enrollment_id=$1",
				[current.enrollment_id, authenticator.id]);
			await new PrivateIDEnrollmentTransactionRepository(client).updateStatus(current.enrollment_id, "completed", completedAt);
			const alreadyEnrolled = Boolean(existing || concurrent);
			await this.audit(client, current, current.enrollment_id, alreadyEnrolled ? "AUTHENTICATOR_ALREADY_ACTIVE" : "AUTHENTICATOR_ENROLLED",
				alreadyEnrolled ? "EXISTING_AUTHENTICATOR" : "ATTACHED");
			return { statusCode: 200, body: { enrolled: true, alreadyEnrolled } };
		});
	}

	async callback(transactionId: string | undefined, sessionId: string | undefined): Promise<FaceEnrollmentReply | undefined> {
		const binding = await this.find(this.pool, transactionId, sessionId);
		if (!binding) return undefined;
		if ((transactionId && transactionId !== binding.provider_transaction_id) ||
			(sessionId && sessionId !== binding.session_id)) {
			return { statusCode: 400, body: { error: "ENROLLMENT_BINDING_MISMATCH" } };
		}
		return { statusCode: 200, body: { enrolled: binding.status === "completed", status: binding.status } };
	}
}
