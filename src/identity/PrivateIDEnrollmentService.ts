import { randomUUID } from "node:crypto";

import type { AuthenticatedPrincipal } from "../authentication/AuthenticatedPrincipal.js";
import type { PrivateIDEnrollmentTransaction } from "../models/PrivateIDEnrollmentTransaction.js";
import type { PrivateIDSession } from "../privateid/PrivateIDSession.js";
import { PrivateIDClient } from "../privateid/PrivateIDClient.js";
import { markPrivateIDEnrollmentSession } from "../privateid/PrivateIDSessionStore.js";
import { PrivateIDEnrollmentTransactionRepository } from "./PrivateIDEnrollmentTransactionRepository.js";
import { UserAuthenticatorRepository } from "./UserAuthenticatorRepository.js";
import { configuration } from "../config/ConfigurationService.js";
import { inMemoryUserAuthenticatorRepository } from "./InMemoryUserAuthenticatorRepository.js";
import { identityRegistry, type IdentityRegistry } from "./IdentityRegistry.js";

type EnrollmentTransactionStore = Pick<
	PrivateIDEnrollmentTransactionRepository,
	"create" | "findByProviderTransactionId" | "updateStatus"
>;
type AuthenticatorStore = Pick<UserAuthenticatorRepository, "create">;
type EnrollmentSessionCreator = (providerTransactionId: string) => Promise<PrivateIDSession>;
type IdentityRegistryStore = Pick<IdentityRegistry, "resolveOrCreate">;

function defaultAuthenticatorStore(): AuthenticatorStore {
	return configuration.getIdentityRegistryDriver() === "memory"
		? inMemoryUserAuthenticatorRepository
		: new UserAuthenticatorRepository();
}

export class PrivateIDEnrollmentService {
	constructor(
		private readonly transactions: EnrollmentTransactionStore = new PrivateIDEnrollmentTransactionRepository(),
		private readonly authenticators: AuthenticatorStore = defaultAuthenticatorStore(),
		private readonly createSession: EnrollmentSessionCreator = (transactionId) => new PrivateIDClient().createEnrollmentSession(transactionId),
		private readonly identities: IdentityRegistryStore = identityRegistry
	) {}

	async startEnrollment(principal: AuthenticatedPrincipal): Promise<{ transaction: PrivateIDEnrollmentTransaction; session: PrivateIDSession }> {
		const providerTransactionId = randomUUID();
		const session = await this.createSession(providerTransactionId);
		const transaction = await this.transactions.create({
			id: randomUUID(),
			userId: principal.userId,
			purpose: "face_enrollment",
			providerTransactionId,
			status: "pending",
			expiresAt: new Date(session.expires).toISOString()
		});
		markPrivateIDEnrollmentSession(session.sessionId, transaction.id);
		return { transaction, session };
	}

	async completeEnrollment(providerTransactionId: string, providerSubject: string): Promise<PrivateIDEnrollmentTransaction | undefined> {
		const transaction = await this.transactions.findByProviderTransactionId(providerTransactionId);
		if (!transaction || transaction.status !== "pending") {
			return undefined;
		}
		if (new Date(transaction.expiresAt).getTime() <= Date.now()) {
			return this.transactions.updateStatus(transaction.id, "expired");
		}

		const now = new Date().toISOString();

		// Bookwrm User -> IdentitySubject -> UserAuthenticator: reuse an existing IdentitySubject for this
		// PUID (exactly one provider identifier, matching UserAuthenticator.providerSubject below) or mint
		// one via the existing creation service -- never duplicate that logic here. status defaults to
		// ACTIVE inside resolveOrCreate.
		const identitySubject = await this.identities.resolveOrCreate({
			provider: "PrivateID",
			providerSubject: providerSubject
		});

		await this.authenticators.create({
			id: randomUUID(),
			userId: identitySubject.id,
			provider: "privateid",
			providerSubject,
			authenticatorType: "face",
			status: "active",
			linkedAt: now,
			verifiedAt: now
		});
		return this.transactions.updateStatus(transaction.id, "completed", new Date(now));
	}
}

export const privateIDEnrollmentService = new PrivateIDEnrollmentService();