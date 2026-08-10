import { configuration } from "../config/ConfigurationService.js";
import { ApiResponse } from "../models/ApiResponse.js";
import { IdentityContext } from "../models/IdentityContext.js";
import { IdentityHealth } from "../models/IdentityHealth.js";
import { IdentityPolicy } from "../models/IdentityPolicy.js";
import { IdentityTimeline } from "../models/IdentityTimeline.js";
import { Notification } from "../models/Notification.js";
import { SecurityContext } from "../models/SecurityContext.js";
import { TrustedDevice } from "../models/TrustedDevice.js";
import { ApiError } from "../utils/ApiError.js";
import { identityCircuitBreaker } from "../infrastructure/CircuitBreaker.js";

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRIES = 2;
const RETRYABLE_STATUS_CODES = new Set([500, 502, 503, 504]);

export class IdentityPlatformClient {
		async health(): Promise<ApiResponse<IdentityHealth>> {
				return this.invoke<IdentityHealth>("health");
		}

		async getIdentityContext(userId?: string): Promise<ApiResponse<IdentityContext>> {
				const payload = userId ? { userId } : {};
				return this.invoke<IdentityContext>("getIdentityContext", payload);
		}

		async resolveIdentity(privateIdUserId?: string): Promise<ApiResponse<IdentityContext>> {
				const payload = privateIdUserId ? { privateIdUserId } : {};
				return this.invoke<IdentityContext>("resolveIdentity", payload);
		}

		async reverify(): Promise<ApiResponse<IdentityContext>> {
				return this.invoke<IdentityContext>("reverify");
		}

		async getSecurityContext(): Promise<ApiResponse<SecurityContext>> {
				return this.invoke<SecurityContext>("getSecurityContext");
		}

		async getPolicies(): Promise<ApiResponse<IdentityPolicy[]>> {
				return this.invoke<IdentityPolicy[]>("getPolicies");
		}

		async getTimeline(): Promise<ApiResponse<IdentityTimeline[]>> {
				return this.invoke<IdentityTimeline[]>("getTimeline");
		}

		async getNotifications(): Promise<ApiResponse<Notification[]>> {
				return this.invoke<Notification[]>("getNotifications");
		}

		async getTrustedDevices(): Promise<ApiResponse<TrustedDevice[]>> {
				return this.invoke<TrustedDevice[]>("getTrustedDevices");
		}

		private async invoke<T>(
				action: string,
				payload: any = {}
		): Promise<ApiResponse<T>> {
				const requestId = crypto.randomUUID();
				const startedAt = Date.now();
				let retryCount = 0;

				for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
						const controller = new AbortController();
						const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

						try {
								const response = await identityCircuitBreaker.execute(async () => {
										return fetch(
											`${configuration.getBase44BaseUrl()}${configuration.getIdentityApiPath()}`,
											{
												method: "POST",
												headers: {
														"Content-Type": "application/json",
														Authorization:
															`Bearer ${configuration.getIdentityApiKey()}`
												},
												signal: controller.signal,
												body: JSON.stringify({
														version: "v1",
														action,
														...payload
												})
											}
										);
								});

								clearTimeout(timeoutId);

								if (!response.ok) {
										const responseError = this.errorForStatusCode(response.status, action, requestId);

										if (this.shouldRetry(responseError.statusCode, attempt)) {
												retryCount += 1;
												continue;
										}

										throw responseError;
								}

								const result = await response.json() as ApiResponse<T>;
								this.logRequest({
										RequestId: requestId,
										Action: action,
										Latency: Date.now() - startedAt,
										Success: true,
										RetryCount: retryCount
								});

								return result;
						} catch (error) {
								clearTimeout(timeoutId);

								const normalizedError = this.normalizeError(error, action, requestId);

								if (this.shouldRetry(normalizedError.statusCode, attempt)) {
										retryCount += 1;
										continue;
								}

								this.logRequest({
										RequestId: requestId,
										Action: action,
										Latency: Date.now() - startedAt,
										Success: false,
										RetryCount: retryCount
								});

								throw normalizedError;
						}
				}

				const exhaustedError = ApiError.internal({
						action,
						requestId,
						reason: "Retry loop exhausted"
				});

				this.logRequest({
						RequestId: requestId,
						Action: action,
						Latency: Date.now() - startedAt,
						Success: false,
						RetryCount: retryCount
				});

				throw exhaustedError;
		}

		private shouldRetry(statusCode: number, attempt: number): boolean {
				if (attempt >= MAX_RETRIES) {
						return false;
				}

				if (statusCode === 401 || statusCode === 403) {
						return false;
				}

				return RETRYABLE_STATUS_CODES.has(statusCode);
		}

		private errorForStatusCode(statusCode: number, action: string, requestId: string): ApiError {
				const details = {
					action,
					requestId,
					statusCode
				};

				switch (statusCode) {
						case 401:
								return ApiError.unauthorized(details);
						case 403:
								return ApiError.forbidden(details);
						case 404:
								return ApiError.notFound(details);
						case 408:
								return ApiError.timeout(details);
						case 500:
								return ApiError.internal(details);
						case 503:
								return ApiError.unavailable(details);
						case 502:
								return new ApiError(502, "Bad Gateway", details);
						case 504:
								return new ApiError(504, "Gateway Timeout", details);
						default:
								return new ApiError(statusCode, `HTTP ${statusCode}`, details);
				}
		}

		private normalizeError(error: unknown, action: string, requestId: string): ApiError {
				if (error instanceof ApiError) {
						return error;
				}

				if (error instanceof DOMException && error.name === "AbortError") {
						return ApiError.timeout({
							action,
							requestId,
							timeoutMs: DEFAULT_TIMEOUT_MS
						});
				}

				if (error instanceof TypeError) {
						return ApiError.unavailable({
							action,
							requestId,
							message: error.message
						});
				}

				if (error instanceof Error) {
						return ApiError.internal({
							action,
							requestId,
							message: error.message
						});
				}

				return ApiError.internal({
						action,
						requestId,
						message: "Unknown request failure"
				});
		}

		private logRequest(logData: {
				RequestId: string;
				Action: string;
				Latency: number;
				Success: boolean;
				RetryCount: number;
		}): void {
				console.info(JSON.stringify({
						...logData,
						Environment: configuration.getEnvironment()
				}));
		}
}