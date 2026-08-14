import { IdentityPlatformClient } from "../clients/IdentityPlatformClient.js";
import { identityCache } from "../cache/IdentityCache.js";
import { ApiResponse } from "../models/ApiResponse.js";
import { IdentityContext } from "../models/IdentityContext.js";
import { IdentityHealth } from "../models/IdentityHealth.js";
import { IdentityPolicy } from "../models/IdentityPolicy.js";
import { IdentityTimeline } from "../models/IdentityTimeline.js";
import { Notification } from "../models/Notification.js";
import { SecurityContext } from "../models/SecurityContext.js";
import { TrustedDevice } from "../models/TrustedDevice.js";

// TEMP-EMAIL-TRACE: Sprint 8.19.2 - classifies a claim value as present/empty/undefined for pipeline tracing.
function describeEmailState(value: string | undefined): "present" | "empty" | "undefined" {
		if (value === undefined) {
				return "undefined";
		}

		return value.length > 0 ? "present" : "empty";
}

export class IdentityService {
		constructor(private readonly client: IdentityPlatformClient = new IdentityPlatformClient()) {}

		async health(): Promise<ApiResponse<IdentityHealth>> {
				return this.client.health();
		}

		async getIdentityContext(userId?: string): Promise<ApiResponse<IdentityContext>> {
				const cacheKey = `identity:${userId ?? "default"}`;
				const cached = await identityCache.get<ApiResponse<IdentityContext>>(cacheKey);
				if (cached) {
						// TEMP-EMAIL-TRACE: Sprint 8.19.2
						console.info("TEMP-EMAIL-TRACE getIdentityContext(cached)", { emailState: describeEmailState(cached.data?.email) });
						return cached;
				}

				const response = await this.client.getIdentityContext(userId);
				// TEMP-EMAIL-TRACE: Sprint 8.19.2
				console.info("TEMP-EMAIL-TRACE getIdentityContext(upstream)", { emailState: describeEmailState(response.data?.email) });
				await identityCache.set(cacheKey, response);
				return response;
		}

		async resolveIdentity(privateIdUserId?: string): Promise<ApiResponse<IdentityContext>> {
				await identityCache.invalidate(`identity:${privateIdUserId ?? "default"}`);
				await identityCache.invalidate(`security:${privateIdUserId ?? "default"}`);
				await identityCache.invalidate(`policies:${privateIdUserId ?? "default"}`);
				const response = await this.client.resolveIdentity(privateIdUserId);
				// TEMP-EMAIL-TRACE: Sprint 8.19.2
				console.info("TEMP-EMAIL-TRACE resolveIdentity(upstream)", { emailState: describeEmailState(response.data?.email) });
				return response;
		}

		async reverify(): Promise<ApiResponse<IdentityContext>> {
				await identityCache.invalidate("identity:default");
				await identityCache.invalidate("security:default");
				await identityCache.invalidate("policies:default");
				return this.client.reverify();
		}

		async getSecurityContext(): Promise<ApiResponse<SecurityContext>> {
				const cacheKey = "security:default";
				const cached = await identityCache.get<ApiResponse<SecurityContext>>(cacheKey);
				if (cached) {
						return cached;
				}

				const response = await this.client.getSecurityContext();
				await identityCache.set(cacheKey, response);
				return response;
		}

		async getPolicies(): Promise<ApiResponse<IdentityPolicy[]>> {
				const cacheKey = "policies:default";
				const cached = await identityCache.get<ApiResponse<IdentityPolicy[]>>(cacheKey);
				if (cached) {
						return cached;
				}

				const response = await this.client.getPolicies();
				await identityCache.set(cacheKey, response);
				return response;
		}

		async getTimeline(): Promise<ApiResponse<IdentityTimeline[]>> {
				return this.client.getTimeline();
		}

		async getNotifications(): Promise<ApiResponse<Notification[]>> {
				return this.client.getNotifications();
		}

		async getTrustedDevices(): Promise<ApiResponse<TrustedDevice[]>> {
				return this.client.getTrustedDevices();
		}

		// TEMPORARY (Sprint 8.20 validation): raw Base44 debugIdentifiers passthrough.
		async debugIdentifiers(userId: string): Promise<ApiResponse<unknown>> {
				return this.client.debugIdentifiers(userId);
		}
}

export const identityService = new IdentityService();
