import { configuration } from "../config/ConfigurationService.js";
import { secretProvider } from "../config/SecretProvider.js";
import { getClaimAudit, type ClaimAuditEntry } from "./IdentityClaimAudit.js";
import { getIdentityAudit, type IdentityAuditEntry } from "./IdentityAudit.js";
import { getCorrelationStoreSize } from "../oidc/CorrelationStore.js";
import { getPendingIdentityStats } from "./PendingIdentity.js";
import { identityRegistry } from "./IdentityRegistry.js";
import { getPostgresPool, getSchemaVersionInfo, type SchemaVersionInfo } from "./infrastructure/PostgresInfrastructure.js";
import type { IdentityProvider, IdentitySubject } from "../models/IdentitySubject.js";
import { getRedisClient } from "../oidc/infrastructure/RedisInfrastructure.js";
import { oidcService } from "../oidc/OIDCService.js";

export type IdentityHistory = {
		created: string;
		updated: string;
		lastAuthenticated?: string;
		claimUpdatedAt?: IdentitySubject["claimUpdatedAt"];
		status: IdentitySubject["status"];
};

export type AuthenticatorLink = {
		provider: IdentityProvider;
		providerSubject: string;
		linkedAt: string;
};

export type TimelineEventType = "IDENTITY_CREATED" | "AUTHENTICATOR_LINKED" | "CLAIMS_UPDATED" | "LAST_LOGIN";

export type TimelineEvent = {
		type: TimelineEventType;
		timestamp: string;
		description: string;
};

export type ComponentHealth = {
		status: "healthy" | "unhealthy" | "not_configured";
		detail?: string;
		latencyMs?: number;
};

export type IdentityAdministrationHealth = {
		registry: ComponentHealth;
		redis: ComponentHealth;
		postgresql: ComponentHealth;
		oidc: ComponentHealth;
		jwks: ComponentHealth;
		privateId: ComponentHealth;
		correlation: ComponentHealth & { pendingCount: number };
		pendingIdentity: ComponentHealth & { total: number; pending: number; blocked: number };
		schemaVersion: string | null;
		migrationStatus: SchemaVersionInfo["migrationStatus"];
};

function toHistory(subject: IdentitySubject): IdentityHistory {
		return {
				created: subject.createdAt,
				updated: subject.updatedAt,
				lastAuthenticated: subject.lastAuthenticatedAt,
				claimUpdatedAt: subject.claimUpdatedAt,
				status: subject.status
		};
}

// Today only the primary provider is modeled; shape already supports multiple authenticators (Task 4).
function toAuthenticators(subject: IdentitySubject): AuthenticatorLink[] {
		return [
				{
						provider: subject.primaryProvider,
						providerSubject: subject.primaryProviderSubject,
						linkedAt: subject.createdAt
				}
		];
}

function toTimeline(subject: IdentitySubject, audit: ClaimAuditEntry[]): TimelineEvent[] {
		const events: TimelineEvent[] = [
				{
						type: "IDENTITY_CREATED",
						timestamp: subject.createdAt,
						description: `IdentitySubject created via ${subject.primaryProvider}`
				},
				{
						type: "AUTHENTICATOR_LINKED",
						timestamp: subject.createdAt,
						description: `${subject.primaryProvider} linked as primary authenticator`
				}
		];

		for (const entry of audit) {
				events.push({
						type: "CLAIMS_UPDATED",
						timestamp: entry.timestamp,
						description: `${entry.claim} changed from "${entry.oldValue}" to "${entry.newValue}" via ${entry.source}`
				});
		}

		if (subject.lastAuthenticatedAt) {
				events.push({
						type: "LAST_LOGIN",
						timestamp: subject.lastAuthenticatedAt,
						description: `Last authenticated via ${subject.primaryProvider}`
				});
		}

		return events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

async function checkRedis(): Promise<ComponentHealth> {
		if (!configuration.getFeatureFlag("REDIS_ENABLED", true)) {
				return { status: "not_configured" };
		}

		const startedAt = Date.now();
		try {
				await getRedisClient().ping();
				return { status: "healthy", latencyMs: Date.now() - startedAt };
		} catch (error) {
				return { status: "unhealthy", detail: error instanceof Error ? error.message : "ping failed", latencyMs: Date.now() - startedAt };
		}
}

async function checkPostgres(): Promise<ComponentHealth> {
		if (configuration.getIdentityRegistryDriver() !== "postgres") {
				return { status: "not_configured", detail: "IDENTITY_REGISTRY_DRIVER is not postgres" };
		}

		const startedAt = Date.now();
		try {
				await getPostgresPool().query("SELECT 1");
				return { status: "healthy", latencyMs: Date.now() - startedAt };
		} catch (error) {
				return { status: "unhealthy", detail: error instanceof Error ? error.message : "query failed", latencyMs: Date.now() - startedAt };
		}
}

async function checkRegistry(): Promise<ComponentHealth> {
		const startedAt = Date.now();
		try {
				await identityRegistry.findByOidcSubject("__identity_admin_health_check__");
				return { status: "healthy", latencyMs: Date.now() - startedAt };
		} catch (error) {
				return { status: "unhealthy", detail: error instanceof Error ? error.message : "lookup failed", latencyMs: Date.now() - startedAt };
		}
}

function checkOidc(): ComponentHealth {
		return oidcService.isProviderReady()
				? { status: "healthy" }
				: { status: "unhealthy", detail: "provider not ready" };
}

function checkJwks(): ComponentHealth {
		return oidcService.hasSigningKeysAvailable()
				? { status: "healthy" }
				: { status: "unhealthy", detail: "no signing keys configured" };
}

function checkPrivateId(): ComponentHealth {
		const authConfiguration = secretProvider.getPrivateIdAuthConfiguration();
		const configured = Boolean(authConfiguration.authApiKey) && Boolean(configuration.get("PRIVATEID_AUTH_BASE_URL")?.trim());
		return configured ? { status: "healthy" } : { status: "not_configured" };
}

function checkCorrelation(): ComponentHealth & { pendingCount: number } {
		const pendingCount = getCorrelationStoreSize();
		return { status: "healthy", pendingCount };
}

function checkPendingIdentity(): ComponentHealth & { total: number; pending: number; blocked: number } {
		const stats = getPendingIdentityStats();
		return { status: "healthy", ...stats };
}

async function checkSchemaVersion(): Promise<SchemaVersionInfo> {
		if (configuration.getIdentityRegistryDriver() !== "postgres") {
				return { schemaVersion: null, migrationStatus: "unknown" };
		}

		try {
				return await getSchemaVersionInfo();
		} catch {
				return { schemaVersion: null, migrationStatus: "unknown" };
		}
}

// Read-only aggregation over IdentityRegistry + governance metadata for the Identity Administration API (Phase 4).
export class IdentityAdministrationService {
		async listSubjects(): Promise<IdentitySubject[]> {
				return identityRegistry.listSubjects();
		}

		async getSubject(oidcSubject: string): Promise<IdentitySubject | undefined> {
				return identityRegistry.findByOidcSubject(oidcSubject);
		}

		async getByProvider(provider: IdentityProvider, providerSubject: string): Promise<IdentitySubject | undefined> {
				return identityRegistry.findByProvider(provider, providerSubject);
		}

		async getByEmail(email: string): Promise<IdentitySubject[]> {
				return identityRegistry.findByEmail(email);
		}

		getHistory(subject: IdentitySubject): IdentityHistory {
				return toHistory(subject);
		}

		getAuthenticators(subject: IdentitySubject): AuthenticatorLink[] {
				return toAuthenticators(subject);
		}

		getAudit(oidcSubject: string): { claims: ClaimAuditEntry[]; identity: IdentityAuditEntry[] } {
				return { claims: getClaimAudit(oidcSubject), identity: getIdentityAudit(oidcSubject) };
		}

		getTimeline(subject: IdentitySubject): TimelineEvent[] {
				return toTimeline(subject, getClaimAudit(subject.oidcSubject));
		}

		async getHealth(): Promise<IdentityAdministrationHealth> {
				const [registry, redis, postgresql, schemaVersionInfo] = await Promise.all([
						checkRegistry(),
						checkRedis(),
						checkPostgres(),
						checkSchemaVersion()
				]);
				return {
						registry,
						redis,
						postgresql,
						oidc: checkOidc(),
						jwks: checkJwks(),
						privateId: checkPrivateId(),
						correlation: checkCorrelation(),
						pendingIdentity: checkPendingIdentity(),
						schemaVersion: schemaVersionInfo.schemaVersion,
						migrationStatus: schemaVersionInfo.migrationStatus
				};
		}
}

export const identityAdministrationService = new IdentityAdministrationService();
