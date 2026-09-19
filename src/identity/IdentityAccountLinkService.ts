import { randomUUID } from "node:crypto";

import { configuration } from "../config/ConfigurationService.js";
import type { IdentitySubject } from "../models/IdentitySubject.js";
import type { IdentityAccountLink } from "../models/IdentityAccountLink.js";
import { identityRegistry } from "./IdentityRegistry.js";
import { identityClaimResolver } from "./IdentityClaimResolver.js";
import { inMemoryIdentityAccountLinkRepository } from "./InMemoryIdentityAccountLinkRepository.js";
import { PostgresIdentityAccountLinkRepository } from "./PostgresIdentityAccountLinkRepository.js";
import type { IdentityAccountLinkRepository } from "./IdentityAccountLinkRepository.js";

export class IdentityAccountLinkError extends Error {
		constructor(readonly code: "UNKNOWN_OIDC_SUBJECT" | "ACCOUNT_LINK_CONFLICT") {
				super(
						code === "UNKNOWN_OIDC_SUBJECT"
								? "Unknown IdentitySubject for the supplied oidcSubject"
								: "Bookwrm account is already linked to a different IdentitySubject"
				);
		}
}

function defaultLinks(): IdentityAccountLinkRepository {
		return configuration.getIdentityRegistryDriver() === "memory"
				? inMemoryIdentityAccountLinkRepository
				: new PostgresIdentityAccountLinkRepository();
}

export type AccountLinkRequest = {
		externalUserId: string;
		oidcSubject: string;
		email?: string;
		emailVerified?: boolean;
};

export type AccountLinkResult = {
		link: IdentityAccountLink;
		subject: IdentitySubject;
		created: boolean;
};

// Provider-neutral boundary: a trusted Bookwrm account supplies its canonical externalUserId plus
// verified claims here. PrivateID never calls this path and is never the source of email (Release C5.1).
export class IdentityAccountLinkService {
		constructor(private readonly links: IdentityAccountLinkRepository = defaultLinks()) {}

		async linkAccount(request: AccountLinkRequest): Promise<AccountLinkResult> {
				const subject = await identityRegistry.findByOidcSubject(request.oidcSubject);
				if (!subject) {
						throw new IdentityAccountLinkError("UNKNOWN_OIDC_SUBJECT");
				}

				const existing = await this.links.findByExternalUserId("bookwrm", request.externalUserId);
				let link: IdentityAccountLink;
				let created = false;

				if (existing) {
						if (existing.identitySubjectId !== subject.id) {
								throw new IdentityAccountLinkError("ACCOUNT_LINK_CONFLICT");
						}

						link = existing;
				} else {
						link = await this.links.create({
								id: randomUUID(),
								source: "bookwrm",
								externalUserId: request.externalUserId,
								identitySubjectId: subject.id,
								status: "active"
						});
						created = true;
				}

				// Reuses the existing governed claim mechanism -- never duplicates IdentityClaimResolver/IdentityRegistry logic.
				const { subject: reconciled } = await identityClaimResolver.resolve(subject.oidcSubject, "BOOKWRM", {
						email: request.email,
						emailVerified: request.emailVerified
				});

				return { link, subject: reconciled, created };
		}
}

export const identityAccountLinkService = new IdentityAccountLinkService();
