import type { PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";

// Correlates an OIDC authorization request to its PrivateID session using a Railway-generated
// correlationId, independent of any Bookwrm-hosted identity state.
type CorrelationRecord = {
		context: PendingAuthorizationContext;
		privateIdSessionId?: string;
};

const recordsByCorrelationId = new Map<string, CorrelationRecord>();
const correlationIdBySessionId = new Map<string, string>();

export function storeCorrelation(correlationId: string, context: PendingAuthorizationContext): void {
		recordsByCorrelationId.set(correlationId, { context });
}

// Links the PrivateID sessionId returned from session creation back to its correlationId.
export function linkPrivateIdSession(correlationId: string, sessionId: string): void {
		const record = recordsByCorrelationId.get(correlationId);
		if (!record) {
				return;
		}

		record.privateIdSessionId = sessionId;
		correlationIdBySessionId.set(sessionId, correlationId);
}

// Retrieves and removes the pending context so it can only complete the authorization once.
export function consumeByCorrelationId(correlationId: string): PendingAuthorizationContext | undefined {
		const record = recordsByCorrelationId.get(correlationId);
		if (!record) {
				return undefined;
		}

		recordsByCorrelationId.delete(correlationId);
		if (record.privateIdSessionId) {
				correlationIdBySessionId.delete(record.privateIdSessionId);
		}

		return record.context;
}

export function findCorrelationIdForSession(sessionId: string): string | undefined {
		return correlationIdBySessionId.get(sessionId);
}

// Health/observability only (Phase 5 Task 1); not used for any decision logic.
export function getCorrelationStoreSize(): number {
		return recordsByCorrelationId.size;
}
