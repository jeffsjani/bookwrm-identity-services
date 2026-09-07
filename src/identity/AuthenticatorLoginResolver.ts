import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import type { AuthenticatorLoginTransaction } from "../models/AuthenticatorLoginTransaction.js";
import type { AuthenticatorProvider, UserAuthenticator } from "../models/UserAuthenticator.js";
import type { IdentitySubject } from "../models/IdentitySubject.js";
import { AuthenticatorLoginTransactionRepository } from "./AuthenticatorLoginTransactionRepository.js";
import { InMemoryAuthenticatorLoginTransactionRepository } from "./InMemoryAuthenticatorLoginTransactionRepository.js";
import { inMemoryUserAuthenticatorRepository } from "./InMemoryUserAuthenticatorRepository.js";
import { inMemoryIdentitySubjectRepository } from "./InMemoryIdentitySubjectRepository.js";
import { PostgresIdentitySubjectRepository } from "./PostgresIdentitySubjectRepository.js";
import { UserAuthenticatorRepository } from "./UserAuthenticatorRepository.js";

type AuthenticatorStore = Pick<UserAuthenticatorRepository, "findByProviderSubject">;
type UserStore = { findById(id: string): Promise<IdentitySubject | undefined> };
type LoginTransactionStore = Pick<AuthenticatorLoginTransactionRepository, "create" | "complete">;

export class AuthenticatorLoginError extends Error {
	constructor(readonly code: "AUTHENTICATION_FAILED" | "AUTHENTICATOR_REVOKED" | "USER_INACTIVE") {
		super(code === "AUTHENTICATOR_REVOKED" ? "Authenticator Revoked" : code === "USER_INACTIVE" ? "User Inactive" : "Authentication Failed");
	}
}

function defaultAuthenticators(): AuthenticatorStore {
	return configuration.getIdentityRegistryDriver() === "memory"
		? inMemoryUserAuthenticatorRepository
		: new UserAuthenticatorRepository();
}

function defaultLoginTransactions(): LoginTransactionStore {
	return configuration.getIdentityRegistryDriver() === "memory"
		? new InMemoryAuthenticatorLoginTransactionRepository()
		: new AuthenticatorLoginTransactionRepository();
}

function defaultUsers(): UserStore {
	return configuration.getIdentityRegistryDriver() === "memory"
		? inMemoryUserRepository
		: new PostgresIdentitySubjectRepository();
}

export const inMemoryUserRepository = inMemoryIdentitySubjectRepository;

// Authentication resolves a pre-existing authenticator and user. It never creates either identity record.
export class AuthenticatorLoginResolver {
	constructor(
		private readonly authenticators: AuthenticatorStore = defaultAuthenticators(),
		private readonly users: UserStore = defaultUsers(),
		private readonly transactions: LoginTransactionStore = defaultLoginTransactions()
	) {}

	async resolveAuthenticator(provider: AuthenticatorProvider, providerSubject: string): Promise<UserAuthenticator> {
		const authenticator = await this.authenticators.findByProviderSubject(provider, providerSubject);
		if (!authenticator) throw new AuthenticatorLoginError("AUTHENTICATION_FAILED");
		if (authenticator.status === "revoked") throw new AuthenticatorLoginError("AUTHENTICATOR_REVOKED");
		return authenticator;
	}

	async resolveUserFromAuthenticator(authenticator: UserAuthenticator): Promise<IdentitySubject> {
		const user = await this.users.findById(authenticator.userId);
		if (!user || user.status !== "ACTIVE") throw new AuthenticatorLoginError("USER_INACTIVE");
		return user;
	}

	async resolveLogin(provider: AuthenticatorProvider, providerTransactionId: string, providerSubject: string): Promise<IdentitySubject> {
		const transaction = await this.transactions.create({
			id: randomUUID(), provider, providerTransactionId, status: "pending"
		});
		try {
			const authenticator = await this.resolveAuthenticator(provider, providerSubject);
			const user = await this.resolveUserFromAuthenticator(authenticator);
			await this.transactions.complete(transaction.id, "completed", providerSubject, user.id);
			return user;
		} catch (error) {
			await this.transactions.complete(transaction.id, "failed", providerSubject);
			throw error;
		}
	}
}

export const authenticatorLoginResolver = new AuthenticatorLoginResolver();