import { randomUUID } from "node:crypto";
import type { PostgresClient } from "./infrastructure/PostgresInfrastructure.js";

export type ApplicationAccountLink = {
	id: string;
	identitySubjectId: string;
	applicationId: string;
	externalAccountId: string;
	status: "active" | "suspended";
	createdAt: string;
	updatedAt: string;
};

// Server-issued continuity evidence, never a browser/application request body.
export type AccountLinkEvidence = {
	authority: "OIDC_CONTINUITY" | "BOOKWRM_SERVICE_CONTINUITY";
	clientId: string;
	requestId: string;
	authenticationMethod: "HAPI_EMAIL" | "PRIVATEID_FACE";
};
export type ReconcileApplicationLink = Pick<ApplicationAccountLink, "identitySubjectId" | "applicationId" | "externalAccountId"> & {
	evidence: AccountLinkEvidence;
};
export class ApplicationAccountLinkConflict extends Error {
	constructor() { super("Application account link conflicts with an existing association"); }
}
export interface ApplicationAccountLinks {
	find(applicationId: string, externalAccountId: string): Promise<ApplicationAccountLink | undefined>;
	reconcile(input: ReconcileApplicationLink): Promise<{ link: ApplicationAccountLink; created: boolean }>;
}
function assertEvidence(input: ReconcileApplicationLink): void {
	if (!input.externalAccountId.trim() || !input.evidence.clientId || !input.evidence.requestId ||
		!["OIDC_CONTINUITY", "BOOKWRM_SERVICE_CONTINUITY"].includes(input.evidence.authority)) {
		throw new Error("Authoritative account continuity evidence is required");
	}
}
export class InMemoryApplicationAccountLinks implements ApplicationAccountLinks {
	private readonly links: ApplicationAccountLink[] = [];
	readonly audit: Array<ReconcileApplicationLink & { result: string }> = [];
	async find(applicationId: string, externalAccountId: string) {
		const link = this.links.find(link => link.applicationId === applicationId && link.externalAccountId === externalAccountId);
		return link ? { ...link } : undefined;
	}
	async reconcile(input: ReconcileApplicationLink) {
		assertEvidence(input);
		const existing = this.links.find(link => link.applicationId === input.applicationId &&
			(link.externalAccountId === input.externalAccountId || link.identitySubjectId === input.identitySubjectId));
		const conflict = existing && (existing.externalAccountId !== input.externalAccountId ||
			existing.identitySubjectId !== input.identitySubjectId || existing.status !== "active");
		this.audit.push({ ...input, result: conflict ? "conflict" : existing ? "existing" : "created" });
		if (conflict) throw new ApplicationAccountLinkConflict();
		if (existing) return { link: { ...existing }, created: false };
		const now = new Date().toISOString();
		const link: ApplicationAccountLink = { id: randomUUID(), identitySubjectId: input.identitySubjectId,
			applicationId: input.applicationId, externalAccountId: input.externalAccountId,
			status: "active", createdAt: now, updatedAt: now };
		this.links.push(link);
		return { link: { ...link }, created: true };
	}
}

type LinkRow = {
	id: string; identity_subject_id: string; application_id: string; external_account_id: string;
	status: ApplicationAccountLink["status"]; created_at: Date; updated_at: Date;
};
function fromRow(row: LinkRow): ApplicationAccountLink {
	return { id: row.id, identitySubjectId: row.identity_subject_id, applicationId: row.application_id,
		externalAccountId: row.external_account_id, status: row.status,
		createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString() };
}
export class PostgresApplicationAccountLinks implements ApplicationAccountLinks {
	constructor(private readonly client: PostgresClient) {}
	async find(applicationId: string, externalAccountId: string) {
		const result = await this.client.query<LinkRow>(
			"SELECT * FROM application_account_links WHERE application_id=$1 AND external_account_id=$2",
			[applicationId, externalAccountId]);
		return result.rows[0] ? fromRow(result.rows[0]) : undefined;
	}
	async reconcile(input: ReconcileApplicationLink) {
		assertEvidence(input);
		const authorized = await this.client.query(`SELECT 1 FROM identity_subjects i, applications a
			JOIN tenants t ON t.id=a.tenant_id JOIN oidc_clients c ON c.application_id=a.id
			WHERE i.id=$1 AND a.id=$2 AND c.client_id=$3 AND i.status='ACTIVE'
			AND a.status='active' AND t.status='active' AND c.status='active'`,
		[input.identitySubjectId, input.applicationId, input.evidence.clientId]);
		if (!authorized.rows[0]) throw new Error("Account continuity authority is not active for this application");
		const id = randomUUID();
		const created = await this.client.query<LinkRow>(`WITH inserted AS (
			INSERT INTO application_account_links
				(id,identity_subject_id,application_id,external_account_id,created_at,updated_at)
			SELECT $1,i.id,a.id,$4,NOW(),NOW() FROM identity_subjects i, applications a
			JOIN oidc_clients c ON c.application_id=a.id
			WHERE i.id=$2 AND a.id=$3 AND i.status='ACTIVE' AND a.status='active'
				AND c.client_id=$6 AND c.status='active'
			ON CONFLICT DO NOTHING RETURNING *
		), audit AS (
			INSERT INTO application_account_link_audit
				(id,identity_subject_id,application_id,external_account_id,authority,client_id,request_id,authentication_method,result)
			SELECT $1,$2,$3,$4,$5,$6,$7,$8,'created' FROM inserted
		) SELECT * FROM inserted`, [id, input.identitySubjectId, input.applicationId, input.externalAccountId,
			input.evidence.authority, input.evidence.clientId, input.evidence.requestId, input.evidence.authenticationMethod]);
		if (created.rows[0]) return { link: fromRow(created.rows[0]), created: true };
		const existing = await this.find(input.applicationId, input.externalAccountId);
		const matches = existing?.identitySubjectId === input.identitySubjectId && existing.status === "active";
		await this.client.query(`INSERT INTO application_account_link_audit
			(id,identity_subject_id,application_id,external_account_id,authority,client_id,request_id,authentication_method,result)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			[id, input.identitySubjectId, input.applicationId, input.externalAccountId, input.evidence.authority,
				input.evidence.clientId, input.evidence.requestId, input.evidence.authenticationMethod, matches ? "existing" : "conflict"]);
		if (!matches || !existing) throw new ApplicationAccountLinkConflict();
		return { link: existing, created: false };
	}
}
