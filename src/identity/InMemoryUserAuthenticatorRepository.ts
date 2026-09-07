import type { AuthenticatorProvider, UserAuthenticator } from "../models/UserAuthenticator.js";
import type { CreateUserAuthenticatorInput, UpdateUserAuthenticatorInput } from "./UserAuthenticatorRepository.js";

export class InMemoryUserAuthenticatorRepository {
	private readonly authenticatorsById = new Map<string, UserAuthenticator>();

	async findByProvider(provider: AuthenticatorProvider): Promise<UserAuthenticator[]> {
		return [...this.authenticatorsById.values()].filter((authenticator) => authenticator.provider === provider).map((authenticator) => ({ ...authenticator }));
	}

	async findByProviderSubject(provider: AuthenticatorProvider, providerSubject: string): Promise<UserAuthenticator | undefined> {
		const authenticator = [...this.authenticatorsById.values()].find(
			(value) => value.provider === provider && value.providerSubject === providerSubject
		);
		return authenticator ? { ...authenticator } : undefined;
	}

	async findByUser(userId: string): Promise<UserAuthenticator[]> {
		return [...this.authenticatorsById.values()].filter((authenticator) => authenticator.userId === userId).map((authenticator) => ({ ...authenticator }));
	}

	async create(input: CreateUserAuthenticatorInput): Promise<UserAuthenticator> {
		if (await this.findByProviderSubject(input.provider, input.providerSubject)) {
			throw new Error("UserAuthenticator provider subject already linked");
		}
		if (input.status === "active" && input.authenticatorType === "face") {
			const existingActive = (await this.findByUser(input.userId)).find(
				(authenticator) => authenticator.status === "active" && authenticator.authenticatorType === "face"
			);
			if (existingActive) {
				throw new Error("User already has an active face authenticator");
			}
		}
		const now = new Date().toISOString();
		const authenticator: UserAuthenticator = { ...input, linkedAt: input.linkedAt ?? now, createdAt: now, updatedAt: now };
		this.authenticatorsById.set(authenticator.id, authenticator);
		return { ...authenticator };
	}

	async update(id: string, changes: UpdateUserAuthenticatorInput): Promise<UserAuthenticator | undefined> {
		const authenticator = this.authenticatorsById.get(id);
		if (!authenticator) return undefined;
		Object.assign(authenticator, changes, { updatedAt: new Date().toISOString() });
		return { ...authenticator };
	}

	async revoke(id: string): Promise<UserAuthenticator | undefined> {
		return this.update(id, { status: "revoked", revokedAt: new Date().toISOString() });
	}
}

export const inMemoryUserAuthenticatorRepository = new InMemoryUserAuthenticatorRepository();