import type { PrivateIDResult } from "./PrivateIDResult.js";
import type { PrivateIDSession } from "./PrivateIDSession.js";
import type { AuthenticatedUser } from "../authentication/AuthenticationProvider.js";

export type PrivateIDSessionRecord = {
		session: PrivateIDSession;
		result?: PrivateIDResult;
		authenticatedUser?: AuthenticatedUser;
};

const sessionRecords = new Map<string, PrivateIDSessionRecord>();
const transactionIndex = new Map<string, string>();
let currentSessionId: string | undefined;

export function storePrivateIDSession(session: PrivateIDSession): void {
		sessionRecords.set(session.sessionId, {
			session,
			result: undefined,
			authenticatedUser: undefined
		});
		transactionIndex.set(session.transactionId, session.sessionId);
		currentSessionId = session.sessionId;
}

export function findPrivateIDSession(sessionId?: string, transactionId?: string): PrivateIDSessionRecord | undefined {
		if (sessionId) {
				const record = sessionRecords.get(sessionId);
				if (record && (!transactionId || record.session.transactionId === transactionId)) {
						return record;
				}
		}

		if (transactionId) {
				const mappedSessionId = transactionIndex.get(transactionId);
				if (mappedSessionId) {
						return sessionRecords.get(mappedSessionId);
				}
		}

		return undefined;
}

export function storePrivateIDResult(sessionId: string, result: PrivateIDResult): void {
		const record = sessionRecords.get(sessionId);
		if (record) {
				record.result = result;
		}
}

export function storePrivateIDAuthenticatedUser(sessionId: string, user: AuthenticatedUser): void {
		const record = sessionRecords.get(sessionId);
		if (record) {
			record.authenticatedUser = user;
		}
}

export function getPrivateIDAuthenticatedUser(sessionId: string): AuthenticatedUser | undefined {
		return sessionRecords.get(sessionId)?.authenticatedUser;
}

export function getCurrentPrivateIDSessionRecord(): PrivateIDSessionRecord | undefined {
		if (!currentSessionId) {
				return undefined;
		}

		return sessionRecords.get(currentSessionId);
}

export function resolvePrivateIDSessionRecord(sessionId?: string, transactionId?: string): PrivateIDSessionRecord | undefined {
		const fromIdentifiers = findPrivateIDSession(sessionId, transactionId);
		if (fromIdentifiers) {
				return fromIdentifiers;
		}

		return getCurrentPrivateIDSessionRecord();
}

export function updatePrivateIDSessionStatus(sessionId: string, status: PrivateIDSession["status"], completed?: number): void {
		const record = sessionRecords.get(sessionId);
		if (!record) {
				return;
		}

		record.session.status = status;
		if (completed) {
				record.session.completed = completed;
		}
}