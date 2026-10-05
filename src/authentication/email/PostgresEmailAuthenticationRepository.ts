import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type pg from "pg";
import type { IdentitySubject } from "../../models/IdentitySubject.js";
import { PostgresIdentitySubjectRepository } from "../../identity/PostgresIdentitySubjectRepository.js";
import {
	EmailAuthenticationError, type EmailAuthenticationAuditType, type EmailAuthenticationContext,
	type EmailAuthenticationRepository, type EmailPrincipal
} from "./EmailAuthenticationTypes.js";

const RESULT_TTL_SECONDS = 60;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
type ChallengeRow = {
	id: string; tenant_id: string; application_id: string | null; channel: string; purpose: string;
	status: string; destination_normalized: string; verified_at: Date | null;
	consumed_at: Date | null; expires_at: Date;
};
type ResultRow = {
	identity_subject_id: string; tenant_id: string; application_id: string; client_id: string;
	verification_challenge_id: string; authenticated_at: Date; expires_at: Date; consumed_at: Date | null;
	destination_normalized: string;
};

export class PostgresEmailAuthenticationRepository implements EmailAuthenticationRepository {
	constructor(private readonly pool: pg.Pool) {}

	async ensureSchema(): Promise<void> {
		await this.pool.query(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
	}

	async audit(context: EmailAuthenticationContext, type: EmailAuthenticationAuditType,
		challengeId: string | null, outcome: string): Promise<void> {
		await this.writeAudit(this.pool, context, type, challengeId, outcome);
	}

	private async writeAudit(client: pg.Pool | pg.PoolClient, authority: EmailAuthenticationContext,
		type: EmailAuthenticationAuditType, challengeId: string | null, outcome: string): Promise<void> {
		await client.query(`INSERT INTO email_authentication_audit
			(id,tenant_id,application_id,client_id,challenge_id,type,outcome,occurred_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
		[randomUUID(), authority.context.tenantId, authority.context.applicationId,
			authority.clientId, challengeId, type, outcome]);
	}

	private eligible(subject: IdentitySubject | undefined, email: string, applicationId: string | null): subject is IdentitySubject {
		return Boolean(subject && subject.primaryProvider === "HAPI_EMAIL" &&
			subject.primaryProviderSubject === email && subject.email === email &&
			subject.status === "ACTIVE" && subject.emailVerified === true &&
			subject.applicationId === applicationId);
	}

	async establish(authority: EmailAuthenticationContext, verificationId: string) {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const challenge = (await client.query<ChallengeRow>(
				"SELECT * FROM verification_challenges WHERE id=$1 FOR UPDATE", [verificationId])).rows[0];
			const { context } = authority;
			let now = (await client.query<{ now: Date }>("SELECT clock_timestamp() AS now")).rows[0].now;
			if (!challenge || challenge.tenant_id !== context.tenantId ||
				challenge.application_id !== context.applicationId || challenge.channel !== "EMAIL" ||
				challenge.purpose !== "AUTHENTICATION" || challenge.status !== "VERIFIED" ||
				!challenge.verified_at || challenge.consumed_at || challenge.expires_at <= now) {
				await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_FAILED", verificationId, "INVALID_EVIDENCE");
				await client.query("COMMIT");
				throw new EmailAuthenticationError();
			}
			// Lock the existing canonical identity; no creation/registration path is available.
			await client.query(`SELECT id FROM identity_subjects
				WHERE primary_provider='HAPI_EMAIL' AND primary_provider_subject=$1 FOR UPDATE`,
			[challenge.destination_normalized]);
			const subjects = new PostgresIdentitySubjectRepository(client);
			const subject = await subjects.findByProviderSubject("HAPI_EMAIL", challenge.destination_normalized);
			now = (await client.query<{ now: Date }>("SELECT clock_timestamp() AS now")).rows[0].now;
			if (challenge.expires_at <= now) {
				await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_FAILED", verificationId, "INVALID_EVIDENCE");
				await client.query("COMMIT");
				throw new EmailAuthenticationError();
			}
			await client.query(`UPDATE verification_challenges SET status='CONSUMED',
				consumed_at=$2,updated_at=$2 WHERE id=$1`, [verificationId, now]);
			if (!this.eligible(subject, challenge.destination_normalized, context.applicationId)) {
				await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_FAILED", verificationId,
					subject ? "IDENTITY_NOT_ELIGIBLE" : "NO_ELIGIBLE_IDENTITY");
				await client.query("COMMIT");
				throw new EmailAuthenticationError();
			}
			const token = randomBytes(32).toString("base64url");
			await client.query(`INSERT INTO email_authentication_results
				(token_hash,verification_challenge_id,identity_subject_id,tenant_id,application_id,
				client_id,authenticated_at,expires_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			[digest(token), verificationId, subject.id, context.tenantId, context.applicationId,
				authority.clientId, now, new Date(now.getTime() + RESULT_TTL_SECONDS * 1000)]);
			await client.query("UPDATE identity_subjects SET last_authenticated_at=$2 WHERE id=$1", [subject.id, now]);
			await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_SUCCEEDED", verificationId, "RESULT_ISSUED");
			await client.query("COMMIT");
			return { authenticated: true as const, subject: subject.oidcSubject, authenticationResult: token,
				expiresIn: RESULT_TTL_SECONDS, authenticationMethod: "HAPI_EMAIL" as const,
				authenticatedAt: now.toISOString(), assurance: "email_otp" as const };
		} catch (error) {
			if (!(error instanceof EmailAuthenticationError)) await client.query("ROLLBACK");
			throw error;
		} finally { client.release(); }
	}

	async consumeResult(authority: EmailAuthenticationContext, token: string): Promise<EmailPrincipal> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = (await client.query<ResultRow>(
				`SELECT r.*,v.destination_normalized FROM email_authentication_results r
				JOIN verification_challenges v ON v.id=r.verification_challenge_id
				WHERE r.token_hash=$1 FOR UPDATE OF r`, [digest(token)])).rows[0];
			let now = (await client.query<{ now: Date }>("SELECT clock_timestamp() AS now")).rows[0].now;
			const { context } = authority;
			if (!result || result.consumed_at || result.expires_at <= now ||
				result.tenant_id !== context.tenantId || result.application_id !== context.applicationId ||
				result.client_id !== authority.clientId) {
				await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_FAILED", null, "INVALID_RESULT");
				await client.query("COMMIT");
				throw new EmailAuthenticationError();
			}
			await client.query("SELECT id FROM identity_subjects WHERE id=$1 FOR UPDATE", [result.identity_subject_id]);
			const subject = await new PostgresIdentitySubjectRepository(client).findById(result.identity_subject_id);
			now = (await client.query<{ now: Date }>("SELECT clock_timestamp() AS now")).rows[0].now;
			if (result.expires_at <= now) {
				await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_FAILED",
					result.verification_challenge_id, "INVALID_RESULT");
				await client.query("COMMIT");
				throw new EmailAuthenticationError();
			}
			await client.query("UPDATE email_authentication_results SET consumed_at=$2 WHERE token_hash=$1", [digest(token), now]);
			if (!this.eligible(subject, result.destination_normalized, context.applicationId)) {
				await this.writeAudit(client, authority, "EMAIL_AUTHENTICATION_FAILED",
					result.verification_challenge_id, "IDENTITY_NOT_ELIGIBLE_AT_HANDOFF");
				await client.query("COMMIT");
				throw new EmailAuthenticationError();
			}
			await client.query("COMMIT");
			return { id: subject.id, sub: subject.oidcSubject, email: subject.email, emailVerified: true,
				authenticationMethod: "HAPI_EMAIL", authenticatedAt: result.authenticated_at.toISOString(),
				assurance: "email_otp" };
		} catch (error) {
			if (!(error instanceof EmailAuthenticationError)) await client.query("ROLLBACK");
			throw error;
		} finally { client.release(); }
	}
}
