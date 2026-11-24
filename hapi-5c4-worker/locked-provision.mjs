import pg from "pg";

const connect = pg.Client.prototype.connect;
pg.Client.prototype.connect = async function (...args) {
	await connect.apply(this, args);
	const lock = await this.query("SELECT pg_try_advisory_lock(1212248153, 534) AS acquired");
	if (lock.rows[0]?.acquired !== true) throw new Error("lock unavailable");
	const result = await this.query(`SELECT
		(SELECT count(*) FROM public.tenants WHERE id = $1 OR slug = 'hapi-pilot') AS tenants,
		(SELECT count(*) FROM public.applications WHERE id = $2 OR application_key = 'HAPI_PILOT'
			OR (tenant_id = $1 AND slug = 'hapi-pilot-certification')) AS applications,
		(SELECT count(*) FROM public.oidc_clients WHERE client_id = 'hapi-pilot-certification') AS clients`,
	["c04e7cf0-9e90-49cb-b26f-9ec8e3e7fd18", "5716f2cc-519e-40d9-8b51-011e7be409a7"]);
	if (Object.values(result.rows[0]).some(count => Number(count) !== 0)) throw new Error("existing metadata");
};

await import("./scripts/provision-production-pilot.mjs");