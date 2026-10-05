import { randomBytes } from "node:crypto";
import type { PrivateIDResult } from "./PrivateIDResult.js";
import type { PrivateIDSession } from "./PrivateIDSession.js";
import type { AuthenticatedUser, PendingAuthorizationContext } from "../authentication/AuthenticationProvider.js";
import type { ApiResponse } from "../models/ApiResponse.js";
import type { IdentityContext } from "../models/IdentityContext.js";

export type PrivateIDSessionRecord = {
		session: PrivateIDSession;
		result?: PrivateIDResult;
		authenticatedUser?: AuthenticatedUser;
		identityContext?: ApiResponse<IdentityContext>;
		// Set at session creation (Release Patch 5A) from whether a correlationId was supplied; never inferred from webhook payload fields.
		oidcOrigin: boolean;
		enrollmentTransactionId?: string;
		hapiEnrollment?: boolean;
};

const sessionRecords = new Map<string, PrivateIDSessionRecord>();
const transactionIndex = new Map<string, string>();
const pendingAuthorizationRequests = new Map<string, PendingAuthorizationContext>();
const browserReturns = new Map<string, { sessionId: string; expiresAt: number }>();
export const PRIVATEID_BROWSER_RETURN_COOKIE = "hapi_privateid_oidc_return";
let currentSessionId: string | undefined;

function browserReturnHandle(cookie: string | undefined): string | undefined {
	return cookie?.split(";").map(value => value.trim())
		.find(value => value.startsWith(`${PRIVATEID_BROWSER_RETURN_COOKIE}=`))?.slice(PRIVATEID_BROWSER_RETURN_COOKIE.length + 1);
}

export function storePrivateIDBrowserReturn(sessionId: string): string | undefined {
	const record = sessionRecords.get(sessionId);
	if (!record?.oidcOrigin || record.hapiEnrollment || record.session.expires <= Date.now()) return undefined;
	for (const [handle, context] of browserReturns) if (context.expiresAt <= Date.now()) browserReturns.delete(handle);
	const handle = randomBytes(32).toString("base64url");
	browserReturns.set(handle, { sessionId, expiresAt: Math.min(record.session.expires, Date.now() + 300_000) });
	return handle;
}

export function findPrivateIDBrowserReturn(cookie: string | undefined): PrivateIDSessionRecord | undefined {
	const handle = browserReturnHandle(cookie);
	const context = handle ? browserReturns.get(handle) : undefined;
	if (!context || context.expiresAt <= Date.now()) {
		if (handle) browserReturns.delete(handle);
		return undefined;
	}
	const record = sessionRecords.get(context.sessionId);
	return record?.oidcOrigin && !record.hapiEnrollment ? record : undefined;
}

export function clearPrivateIDBrowserReturn(cookie: string | undefined): void {
	const handle = browserReturnHandle(cookie);
	if (handle) browserReturns.delete(handle);
}

export function storePrivateIDSession(session: PrivateIDSession, options: { oidcOrigin?: boolean } = {}): void {
		sessionRecords.set(session.sessionId, {
			session,
			result: undefined,
			authenticatedUser: undefined,
			identityContext: undefined,
			oidcOrigin: options.oidcOrigin ?? false
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

export function markPrivateIDEnrollmentSession(sessionId: string, enrollmentTransactionId: string): void {
		const record = sessionRecords.get(sessionId);
		if (record) {
			record.enrollmentTransactionId = enrollmentTransactionId;
		}
}

export function markHapiFaceEnrollmentSession(sessionId: string): void {
		const record = sessionRecords.get(sessionId);
		if (record) record.hapiEnrollment = true;
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

export function storePrivateIDIdentityContext(sessionId: string, identityContext: ApiResponse<IdentityContext>): void {
		const record = sessionRecords.get(sessionId);
		if (record) {
			record.identityContext = identityContext;
		}
}

export function getPrivateIDIdentityContext(sessionId: string): ApiResponse<IdentityContext> | undefined {
		return sessionRecords.get(sessionId)?.identityContext;
}

export function storePendingAuthorizationRequest(sessionId: string, context: PendingAuthorizationContext): void {
		pendingAuthorizationRequests.set(sessionId, context);
}

// Retrieves and removes the pending request so it can only resume the flow once.
export function consumePendingAuthorizationRequest(sessionId: string): PendingAuthorizationContext | undefined {
		const context = pendingAuthorizationRequests.get(sessionId);
		pendingAuthorizationRequests.delete(sessionId);
		return context;
}

// Non-mutating peek for diagnostics (Release C4.5) -- never consumes the pending context.
export function hasPendingAuthorizationRequest(sessionId: string): boolean {
		return pendingAuthorizationRequests.has(sessionId);
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