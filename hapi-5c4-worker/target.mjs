import { X509Certificate } from "node:crypto";

export const productionTarget = Object.freeze({
	project: "c62f8911-c750-4f4b-a5e0-4ebe692e0f0c",
	environment: "33e171c1-f9ff-4f5e-9fdf-20297115e7e1",
	host: "postgres.railway.internal",
	port: "5432",
	database: "railway",
	schema: "public",
	fingerprint: "25:FB:AD:52:D6:17:3B:C8:8D:62:24:52:02:67:4B:33:0D:B1:84:E6:60:1C:08:8D:02:A6:6F:D8:D4:2F:5F:D6"
});

export function validateTarget(env, certificate, target = productionTarget) {
	if (env.RAILWAY_PROJECT_ID !== target.project || env.RAILWAY_ENVIRONMENT_ID !== target.environment ||
		env.OIDC_ISSUER !== "https://id.hapiinc.com" || env.PGOPTIONS || env.NODE_OPTIONS ||
		(env.NODE_TLS_REJECT_UNAUTHORIZED && env.NODE_TLS_REJECT_UNAUTHORIZED !== "1")) throw new Error("target");
	if ((certificate.match(/-----BEGIN CERTIFICATE-----/g) || []).length !== 1 ||
		new X509Certificate(certificate).fingerprint256 !== target.fingerprint) throw new Error("certificate");
	const url = new URL(env.DATABASE_URL);
	if (!["postgres:", "postgresql:"].includes(url.protocol) || url.hash || !url.username || !url.password ||
		url.hostname !== target.host || url.port !== target.port ||
		decodeURIComponent(url.pathname.slice(1)) !== target.database) throw new Error("database");
	const allowed = new Set(["sslmode", "sslrootcert", "application_name", "connect_timeout"]);
	for (const key of url.searchParams.keys()) {
		if (!allowed.has(key) || url.searchParams.getAll(key).length !== 1) throw new Error("database options");
	}
	return url;
}