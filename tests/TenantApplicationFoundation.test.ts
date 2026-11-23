import { randomUUID } from "node:crypto";
import { describe, it, expect, beforeEach } from "vitest";

import { ensureOidcTestEnvironment } from "./oidcTestHarness.js";
import { ensureBookwrmApplicationSeed } from "../src/adapters/base44/Base44ApplicationSeed.js";
import { InMemoryTenantRepository } from "../src/identity/InMemoryTenantRepository.js";
import { InMemoryApplicationRepository } from "../src/identity/InMemoryApplicationRepository.js";
import { InMemoryOIDCClientRepository } from "../src/identity/InMemoryOIDCClientRepository.js";
import { InMemoryIdentitySubjectRepository } from "../src/identity/InMemoryIdentitySubjectRepository.js";
import { IdentityRegistry } from "../src/identity/IdentityRegistry.js";
import { BOOKWRM_TENANT_ID, BOOKWRM_APPLICATION_ID } from "../src/identity/WellKnownIdentities.js";
import { registerOIDCClients } from "../src/oidc/clients.js";
import { configuration } from "../src/config/ConfigurationService.js";

describe("HAPI ID H1 - Bookwrm Tenant/Application seed (memory driver)", () => {
		beforeEach(() => {
				ensureOidcTestEnvironment();
		});

		it("seeds Tenant #1 + Application #1 + an OIDCClient matching the legacy env-driven Base44 config", async () => {
				const tenants = new InMemoryTenantRepository();
				const applications = new InMemoryApplicationRepository();
				const oidcClients = new InMemoryOIDCClientRepository();

				const result = await ensureBookwrmApplicationSeed({ tenants, applications, oidcClients });

				expect(result.tenantId).toBe(BOOKWRM_TENANT_ID);
				expect(result.applicationId).toBe(BOOKWRM_APPLICATION_ID);
				expect(result.clientSeeded).toBe(true);

				const tenant = await tenants.findById(BOOKWRM_TENANT_ID);
				expect(tenant).toMatchObject({ slug: "bookwrm", status: "active" });

				const application = await applications.findById(BOOKWRM_APPLICATION_ID);
				expect(application).toMatchObject({ tenantId: BOOKWRM_TENANT_ID, slug: "bookwrm-base44", status: "active" });

				const [legacyClient] = registerOIDCClients();
				const persisted = await oidcClients.findByClientId(legacyClient.client_id);
				expect(persisted?.applicationId).toBe(BOOKWRM_APPLICATION_ID);
				expect(persisted?.clientSecret).toBe(legacyClient.client_secret);
				expect(persisted?.redirectUris).toEqual(legacyClient.redirect_uris);
				expect(persisted?.requirePkce).toBe(legacyClient.require_pkce);
		});

		it("is idempotent across repeated seed runs (no duplicate rows, same ids)", async () => {
				const tenants = new InMemoryTenantRepository();
				const applications = new InMemoryApplicationRepository();
				const oidcClients = new InMemoryOIDCClientRepository();

				const first = await ensureBookwrmApplicationSeed({ tenants, applications, oidcClients });
				const second = await ensureBookwrmApplicationSeed({ tenants, applications, oidcClients });

				expect(second.tenantId).toBe(first.tenantId);
				expect(second.applicationId).toBe(first.applicationId);
				expect(await tenants.list()).toHaveLength(1);
				expect(await applications.listByTenant(BOOKWRM_TENANT_ID)).toHaveLength(1);
				expect(await oidcClients.list()).toHaveLength(1);
		});

		it("does not backfill or migrate Bookwrm account mappings on the HAPI production issuer", async () => {
			const previous = {
				issuer: process.env.OIDC_ISSUER,
				driver: process.env.IDENTITY_REGISTRY_DRIVER,
				clientId: process.env.OIDC_BASE44_CLIENT_ID
			};
			process.env.OIDC_ISSUER = "https://id.hapiinc.com";
			process.env.IDENTITY_REGISTRY_DRIVER = "postgres";
			delete process.env.OIDC_BASE44_CLIENT_ID;
			configuration.reload();
			const statements: string[] = [];
			try {
				await ensureBookwrmApplicationSeed({
					tenants: new InMemoryTenantRepository(),
					applications: new InMemoryApplicationRepository(),
					oidcClients: new InMemoryOIDCClientRepository(),
					postgresClient: { async query(text: string) { statements.push(text); return { rows: [] }; } }
				});
				expect(statements).toEqual([]);
			} finally {
				if (previous.issuer === undefined) delete process.env.OIDC_ISSUER;
				else process.env.OIDC_ISSUER = previous.issuer;
				if (previous.driver === undefined) delete process.env.IDENTITY_REGISTRY_DRIVER;
				else process.env.IDENTITY_REGISTRY_DRIVER = previous.driver;
				if (previous.clientId === undefined) delete process.env.OIDC_BASE44_CLIENT_ID;
				else process.env.OIDC_BASE44_CLIENT_ID = previous.clientId;
				configuration.reload();
			}
		});

		it("preserves legacy Bookwrm mapping migration behavior on staging", async () => {
			const previous = {
				issuer: process.env.OIDC_ISSUER,
				driver: process.env.IDENTITY_REGISTRY_DRIVER,
				clientId: process.env.OIDC_BASE44_CLIENT_ID
			};
			process.env.OIDC_ISSUER = "https://id-staging.hapiinc.com";
			process.env.IDENTITY_REGISTRY_DRIVER = "postgres";
			delete process.env.OIDC_BASE44_CLIENT_ID;
			configuration.reload();
			const statements: string[] = [];
			try {
				await ensureBookwrmApplicationSeed({
					tenants: new InMemoryTenantRepository(),
					applications: new InMemoryApplicationRepository(),
					oidcClients: new InMemoryOIDCClientRepository(),
					postgresClient: { async query(text: string) { statements.push(text); return { rows: [] }; } }
				});
				expect(statements).toHaveLength(2);
				expect(statements[0]).toContain("UPDATE identity_subjects");
				expect(statements[1]).toContain("application_account_links");
			} finally {
				if (previous.issuer === undefined) delete process.env.OIDC_ISSUER;
				else process.env.OIDC_ISSUER = previous.issuer;
				if (previous.driver === undefined) delete process.env.IDENTITY_REGISTRY_DRIVER;
				else process.env.IDENTITY_REGISTRY_DRIVER = previous.driver;
				if (previous.clientId === undefined) delete process.env.OIDC_BASE44_CLIENT_ID;
				else process.env.OIDC_BASE44_CLIENT_ID = previous.clientId;
				configuration.reload();
			}
		});
});

describe("HAPI ID H1 - IdentityRegistry applicationId scoping", () => {
		it("defaults new IdentitySubjects to Bookwrm's Application when no applicationId is supplied", async () => {
				const repository = new InMemoryIdentitySubjectRepository();
				const registry = new IdentityRegistry(repository);

				const subject = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: `puid-${randomUUID()}`
				});

				expect(subject.applicationId).toBe(BOOKWRM_APPLICATION_ID);
		});

		it("honors an explicit applicationId override (future non-Bookwrm tenants)", async () => {
				const repository = new InMemoryIdentitySubjectRepository();
				const registry = new IdentityRegistry(repository);
				const customApplicationId = randomUUID();

				const subject = await registry.resolveOrCreate({
						provider: "PrivateID",
						providerSubject: `puid-${randomUUID()}`,
						applicationId: customApplicationId
				});

				expect(subject.applicationId).toBe(customApplicationId);
		});
});
