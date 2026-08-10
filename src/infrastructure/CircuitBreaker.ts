import { configuration } from "../config/ConfigurationService.js";

export type CircuitBreakerState = "closed" | "open" | "half-open";

export type CircuitBreakerSnapshot = {
		state: CircuitBreakerState;
		failureCount: number;
		openedAt?: number;
		lastFailureAt?: number;
};

export class CircuitBreaker {
		private state: CircuitBreakerState = "closed";
		private failureCount = 0;
		private openedAt?: number;
		private lastFailureAt?: number;

		private readonly failureThreshold = configuration.getNumber("OIDC_BREAKER_FAILURE_THRESHOLD", 5);
		private readonly resetTimeoutMs = configuration.getNumber("OIDC_BREAKER_RESET_TIMEOUT_MS", 30_000);

		async execute<T>(operation: () => Promise<T>): Promise<T> {
				if (this.state === "open") {
						if (typeof this.openedAt === "number" && Date.now() - this.openedAt >= this.resetTimeoutMs) {
								this.state = "half-open";
						} else {
								throw this.breakerOpenError();
						}
				}

				try {
						const result = await operation();
						this.onSuccess();
						return result;
				} catch (error) {
						this.onFailure();
						throw error;
				}
		}

		getSnapshot(): CircuitBreakerSnapshot {
				return {
						state: this.state,
						failureCount: this.failureCount,
						openedAt: this.openedAt,
						lastFailureAt: this.lastFailureAt
				};
		}

		private onSuccess(): void {
				this.failureCount = 0;
				this.lastFailureAt = undefined;
				this.openedAt = undefined;
				this.state = "closed";
		}

		private onFailure(): void {
				this.failureCount += 1;
				this.lastFailureAt = Date.now();

				if (this.state === "half-open" || this.failureCount >= this.failureThreshold) {
						this.state = "open";
						this.openedAt = Date.now();
				}
		}

		private breakerOpenError(): Error {
				const error = new Error("Circuit breaker is open");
				(error as Error & { statusCode?: number }).statusCode = 503;
				return error;
		}
}

export const identityCircuitBreaker = new CircuitBreaker();