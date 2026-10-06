export type DependencyHealthStatus = "unknown" | "healthy" | "degraded" | "unavailable";

export type DependencyFailureReason = "timeout" | "circuit_open" | "upstream_error" | "rejected" | "error";

export type DependencyHealthSnapshot = {
		status: DependencyHealthStatus;
		checkedAt?: string;
		latencyMs?: number;
		reason?: DependencyFailureReason;
};

type DependencyHealthLogger = {
		info(object: Record<string, unknown>, message: string): void;
		warn(object: Record<string, unknown>, message: string): void;
};

export type DependencyHealthMonitorOptions = {
		name: string;
		probe: () => Promise<unknown>;
		refreshIntervalMs?: number;
		now?: () => number;
		breakerState?: () => string;
		logger?: DependencyHealthLogger;
};

const DEFAULT_REFRESH_INTERVAL_MS = 30_000;

// Observes an external (non-core) dependency without ever blocking the caller: observe() returns the
// cached status and, when stale, starts at most one background probe.
export class DependencyHealthMonitor {
		private snapshot: DependencyHealthSnapshot = { status: "unknown" };
		private inFlight?: Promise<DependencyHealthSnapshot>;
		private lastStartedAt?: number;

		private readonly name: string;
		private readonly probe: () => Promise<unknown>;
		private readonly refreshIntervalMs: number;
		private readonly now: () => number;
		private readonly breakerState?: () => string;
		private readonly logger?: DependencyHealthLogger;

		constructor(options: DependencyHealthMonitorOptions) {
				this.name = options.name;
				this.probe = options.probe;
				this.refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS;
				this.now = options.now ?? (() => Date.now());
				this.breakerState = options.breakerState;
				this.logger = options.logger;
		}

		getSnapshot(): DependencyHealthSnapshot {
				return { ...this.snapshot };
		}

		observe(): DependencyHealthSnapshot {
				const stale = this.lastStartedAt === undefined || this.now() - this.lastStartedAt >= this.refreshIntervalMs;
				if (stale && !this.inFlight) {
						void this.refresh();
				}

				return this.getSnapshot();
		}

		refresh(): Promise<DependencyHealthSnapshot> {
				if (this.inFlight) {
						return this.inFlight;
				}

				this.lastStartedAt = this.now();
				this.inFlight = this.runProbe().finally(() => {
						this.inFlight = undefined;
				});
				return this.inFlight;
		}

		async settled(): Promise<DependencyHealthSnapshot> {
				return this.inFlight ? this.inFlight : this.getSnapshot();
		}

		private async runProbe(): Promise<DependencyHealthSnapshot> {
				const startedAt = this.now();
				let next: DependencyHealthSnapshot;

				try {
						await this.probe();
						next = { status: "healthy" };
				} catch (error) {
						next = this.classifyFailure(error);
				}

				next.checkedAt = new Date(this.now()).toISOString();
				next.latencyMs = Math.max(0, this.now() - startedAt);
				this.record(next);
				return this.getSnapshot();
		}

		private classifyFailure(error: unknown): DependencyHealthSnapshot {
				if (this.breakerState?.() === "open") {
						return { status: "degraded", reason: "circuit_open" };
				}

				const statusCode = typeof (error as { statusCode?: unknown })?.statusCode === "number"
						? (error as { statusCode: number }).statusCode
						: undefined;

				if (statusCode === 408) {
						return { status: "degraded", reason: "timeout" };
				}

				if (statusCode !== undefined && statusCode >= 400 && statusCode < 500 && statusCode !== 429) {
						return { status: "unavailable", reason: "rejected" };
				}

				if (statusCode !== undefined) {
						return { status: "degraded", reason: "upstream_error" };
				}

				return { status: "degraded", reason: "error" };
		}

		private record(next: DependencyHealthSnapshot): void {
				const previous = this.snapshot.status;
				this.snapshot = next;

				if (!this.logger || previous === next.status) {
						return;
				}

				const fields = {
						event: "DEPENDENCY_HEALTH_CHANGED",
						dependency: this.name,
						previousStatus: previous,
						status: next.status,
						reason: next.reason,
						latencyMs: next.latencyMs
				};

				// Background probes are never awaited, so logging must not be able to reject them.
				try {
						if (next.status === "healthy") {
								this.logger.info(fields, "DEPENDENCY_HEALTH_CHANGED");
						} else {
								this.logger.warn(fields, "DEPENDENCY_HEALTH_CHANGED");
						}
				} catch {
						// Ignore logger failures.
				}
		}
}
