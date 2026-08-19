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

export class IdentityService {
		constructor(private readonly client: IdentityPlatformClient = new IdentityPlatformClient()) {}

		async health(): Promise<ApiResponse<IdentityHealth>> {
				return this.client.health();
		}

		async getIdentityContext(userId?: string): Promise<ApiResponse<IdentityContext>> {
				const cacheKey = `identity:${userId ?? "default"}`;
				const cached = await identityCache.get<ApiResponse<IdentityContext>>(cacheKey);
				if (cached) {
						return cached;
				}

				const response = await this.client.getIdentityContext(userId);
				await identityCache.set(cacheKey, response);
				return response;
		}

		async resolveIdentity(privateIdUserId?: string): Promise<ApiResponse<IdentityContext>> {
				await identityCache.invalidate(`identity:${privateIdUserId ?? "default"}`);
				await identityCache.invalidate(`security:${privateIdUserId ?? "default"}`);
				await identityCache.invalidate(`policies:${privateIdUserId ?? "default"}`);
				return this.client.resolveIdentity(privateIdUserId);
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
}

export const identityService = new IdentityService();
