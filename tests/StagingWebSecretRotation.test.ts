import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
	rotateStagingWebSecretAtBoot,
	STAGING_WEB_CLIENT_SECRET_VARIABLE,
	STAGING_WEB_SECRET_ROTATION_FLAG,
	type StagingWebSecretRotationDependencies
} from "../src/identity/StagingWebSecretRotation.js";
import type { PostgresClient, TransactionRunner } from "../src/identity/infrastructure/PostgresInfrastructure.js";
import { STAGING_CONSOLE_CALLBACK } from "../src/oidc/StagingTestConsole.js";

// =============================================================================
// HAPI ID V2-E Stage 3 — boot-time staging-web secret rotation (fail-closed matrix)
// =============================================================================

const STAGING_ISSUER = "https://id-staging.hapiinc.com";
const NEW_SECRET = "n3w-".padEnd(48, "x");
const OLD_SECRET = "0ld-".padEnd(48, "y");
const APPLICATION_ID = "11111111-1111-4111-8111-111111111111";

type ClientRow = {
	application_id: string;
	client_id: string;
	client_secret: string;
	token_endpoint_auth_method: string;
	require_pkce: boolean;
	status: string;
	redirect_uris: string[];
	grant_types: string[];
	updated_at: Date;
};

type FakeDb = {
	settings: Record<string, string>;
	clients: ClientRow[];
	stagingApplicationPresent: boolean;
	queries: string[];
	transactionCount: number;
	runTransaction: TransactionRunner;
};

function stagingWebRow(overrides: Partial<ClientRow> = {}): ClientRow {
	return {
		application_id: APPLICATION_ID,
		client_id: "staging-web",
		client_secret: OLD_SECRET,
		token_endpoint_auth_method: "client_secret_basic",
		require_pkce: true,
		status: "active",
		redirect_uris: ["https://staging-app.hapiinc.com/callback"],
		grant_types: ["authorization_code"],
		updated_at: new Date("2026-11-01T00:00:00Z"),
		...overrides
	};
}

function stagingNativeRow(overrides: Partial<ClientRow> = {}): ClientRow {
	return {
		application_id: APPLICATION_ID,
		client_id: "staging-native",
		client_secret: "",
		token_endpoint_auth_method: "none",
		require_pkce: true,
		status: "active",
		redirect_uris: ["com.hapi.staging:/callback"],
		grant_types: ["authorization_code"],
		updated_at: new Date("2026-11-01T00:00:00Z"),
		...overrides
	};
}

// Minimal staging registry simulation: routes each statement of the rotation to in-memory state.
function fakeStagingDb(overrides: Partial<Pick<FakeDb, "settings" | "clients" | "stagingApplicationPresent">> = {}): FakeDb {
	const db: FakeDb = {
		settings: {
			log_statement: "none",
			log_min_duration_statement: "-1",
			log_parameter_max_length_on_error: "0"
		},
		clients: [stagingWebRow(), stagingNativeRow()],
		stagingApplicationPresent: true,
		queries: [],
		transactionCount: 0,
		runTransaction: undefined as unknown as TransactionRunner,
		...overrides
	};

	const client: PostgresClient = {
		async query<T extends Record<string, unknown>>(text: string, values: unknown[] = []): Promise<{ rows: T[] }> {
			db.queries.push(text);
			if (text.includes("FROM pg_settings")) {
				return { rows: Object.entries(db.settings).map(([name, setting]) => ({ name, setting })) as unknown as T[] };
			}
			if (text.includes("<> ALL($1)")) {
				const allowed = values[0] as string[];
				const foreign = db.clients.find((row) => !allowed.includes(row.client_id));
				return { rows: (foreign ? [{ client_id: foreign.client_id }] : []) as unknown as T[] };
			}
			if (text.includes("JOIN tenants")) {
				return { rows: (db.stagingApplicationPresent ? [{ id: APPLICATION_ID }] : []) as unknown as T[] };
			}
			if (text.startsWith("UPDATE oidc_clients")) {
				const targets = db.clients.filter((row) => row.client_id === "staging-web");
				for (const row of targets) {
					row.client_secret = values[0] as string;
					row.updated_at = new Date();
				}
				return { rows: targets.map((row) => ({ client_id: row.client_id })) as unknown as T[] };
			}
			if (text.includes("FROM oidc_clients WHERE client_id = $1")) {
				const row = db.clients.find((candidate) => candidate.client_id === values[0]);
				return { rows: (row ? [{ ...row }] : []) as unknown as T[] };
			}
			throw new Error(`Unexpected query in fake staging db: ${text}`);
		}
	};

	db.runTransaction = async (fn) => {
		db.transactionCount += 1;
		return fn(client);
	};
	return db;
}

function dependencies(db: FakeDb, overrides: Partial<StagingWebSecretRotationDependencies> = {}): StagingWebSecretRotationDependencies {
	return {
		env: {
			[STAGING_WEB_SECRET_ROTATION_FLAG]: "true",
			[STAGING_WEB_CLIENT_SECRET_VARIABLE]: NEW_SECRET
		},
		issuer: STAGING_ISSUER,
		driver: "postgres",
		runTransaction: db.runTransaction,
		...overrides
	};
}

function captureLog(): { entries: Array<{ details: object; message: string }>; info: (details: object, message: string) => void } {
	const entries: Array<{ details: object; message: string }> = [];
	return { entries, info: (details, message) => entries.push({ details, message }) };
}

describe("StagingWebSecretRotation (boot-time, flag-gated)", () => {
	it("is a silent no-op when the activation flag is absent", async () => {
		const db = fakeStagingDb();
		const log = captureLog();
		const result = await rotateStagingWebSecretAtBoot(log, dependencies(db, { env: { [STAGING_WEB_CLIENT_SECRET_VARIABLE]: NEW_SECRET } }));
		expect(result).toBe("disabled");
		expect(db.transactionCount).toBe(0);
		expect(log.entries).toHaveLength(0);
	});

	it("rotates exactly staging-web, preserves staging-native, and never logs the secret", async () => {
		const db = fakeStagingDb();
		const nativeBefore = { ...db.clients[1] };
		const log = captureLog();

		const result = await rotateStagingWebSecretAtBoot(log, dependencies(db));

		expect(result).toBe("rotated");
		expect(db.clients[0].client_secret).toBe(NEW_SECRET);
		expect(db.clients[1]).toEqual(nativeBefore);

		const logged = JSON.stringify(log.entries);
		expect(logged).not.toContain(NEW_SECRET);
		expect(logged).not.toContain(OLD_SECRET);
		expect(logged).toContain(createHash("md5").update(NEW_SECRET).digest("hex").slice(0, 8));
	});

	it("is repeat-safe: re-running with the already-stored secret reports unchanged", async () => {
		const db = fakeStagingDb({ clients: [stagingWebRow({ client_secret: NEW_SECRET }), stagingNativeRow()] });
		const result = await rotateStagingWebSecretAtBoot(captureLog(), dependencies(db));
		expect(result).toBe("unchanged");
		expect(db.clients[0].client_secret).toBe(NEW_SECRET);
	});

	it("allows the additive staging-console callback during secret rotation", async () => {
		const db = fakeStagingDb({ clients: [stagingWebRow({
			redirect_uris: ["https://staging-app.hapiinc.com/callback", STAGING_CONSOLE_CALLBACK]
		}), stagingNativeRow()] });
		expect(await rotateStagingWebSecretAtBoot(captureLog(), dependencies(db))).toBe("rotated");
	});

	it("refuses when the configured issuer is not exactly the staging issuer", async () => {
		const db = fakeStagingDb();
		await expect(
			rotateStagingWebSecretAtBoot(captureLog(), dependencies(db, { issuer: "https://identity.bookwrm.com" }))
		).rejects.toThrow(/refused: configured issuer/);
		expect(db.transactionCount).toBe(0);
	});

	it("refuses when the identity registry driver is not postgres", async () => {
		const db = fakeStagingDb();
		await expect(
			rotateStagingWebSecretAtBoot(captureLog(), dependencies(db, { driver: "memory" }))
		).rejects.toThrow(/refused: identity registry driver/);
		expect(db.transactionCount).toBe(0);
	});

	it("refuses a missing, short, or placeholder secret without touching the database", async () => {
		for (const secret of [undefined, "short", "__STAGING_WEB_SECRET__".padEnd(40, "_")]) {
			const db = fakeStagingDb();
			await expect(
				rotateStagingWebSecretAtBoot(
					captureLog(),
					dependencies(db, {
						env: { [STAGING_WEB_SECRET_ROTATION_FLAG]: "true", [STAGING_WEB_CLIENT_SECRET_VARIABLE]: secret }
					})
				)
			).rejects.toThrow(/refused: STAGING_WEB_CLIENT_SECRET/);
			expect(db.transactionCount).toBe(0);
		}
	});

	it("refuses when a non-staging OIDC client exists (not the dedicated staging database)", async () => {
		const db = fakeStagingDb({
			clients: [stagingWebRow(), stagingNativeRow(), stagingWebRow({ client_id: "bookwrm-base44-production" })]
		});
		await expect(rotateStagingWebSecretAtBoot(captureLog(), dependencies(db))).rejects.toThrow(
			/non-staging OIDC client "bookwrm-base44-production"/
		);
		expect(db.clients[0].client_secret).toBe(OLD_SECRET);
	});

	it("refuses when the hapi-staging tenant/application fingerprint is missing", async () => {
		const db = fakeStagingDb({ stagingApplicationPresent: false });
		await expect(rotateStagingWebSecretAtBoot(captureLog(), dependencies(db))).rejects.toThrow(
			/staging identity not established/
		);
		expect(db.clients[0].client_secret).toBe(OLD_SECRET);
	});

	it("refuses when staging-web does not match the certified staging configuration", async () => {
		const db = fakeStagingDb({
			clients: [stagingWebRow({ redirect_uris: ["https://evil.example.com/callback"] }), stagingNativeRow()]
		});
		await expect(rotateStagingWebSecretAtBoot(captureLog(), dependencies(db))).rejects.toThrow(
			/does not match the certified staging configuration/
		);
		expect(db.clients[0].client_secret).toBe(OLD_SECRET);
	});

	it("refuses when server-side parameter logging could capture the secret", async () => {
		const db = fakeStagingDb({
			settings: { log_statement: "all", log_min_duration_statement: "-1", log_parameter_max_length_on_error: "0" }
		});
		await expect(rotateStagingWebSecretAtBoot(captureLog(), dependencies(db))).rejects.toThrow(/log_statement=all/);
		expect(db.clients[0].client_secret).toBe(OLD_SECRET);
	});
});
