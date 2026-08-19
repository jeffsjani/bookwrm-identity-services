import { Counter, Histogram, Registry, collectDefaultMetrics } from "prom-client";

type OIDCMetricLabels = {
		flow: string;
		client_id: string;
		status: string;
};

const registry = new Registry();
collectDefaultMetrics({ register: registry });

// Shared with IdentityMetrics.ts so /metrics exposes both OIDC and Identity Registry metrics from one registry.
export function getSharedMetricsRegistry(): Registry {
		return registry;
}

const oidcRequestCounter = new Counter({
		name: "oidc_requests_total",
		help: "Total OIDC requests",
		labelNames: ["flow", "client_id", "status"] as const,
		registers: [registry]
});

const oidcRequestLatencyMs = new Histogram({
		name: "oidc_request_latency_ms",
		help: "OIDC request latency in milliseconds",
		labelNames: ["flow", "client_id", "status"] as const,
		buckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000],
		registers: [registry]
});

export function recordOIDCRequest(labels: OIDCMetricLabels, latencyMs: number): void {
		oidcRequestCounter.inc(labels);
		oidcRequestLatencyMs.observe(labels, latencyMs);
}

export function metricsContentType(): string {
		return registry.contentType;
}

export async function renderMetrics(): Promise<string> {
		return registry.metrics();
}
