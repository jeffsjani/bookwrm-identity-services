import type { IdentityAccountLink, IdentityAccountLinkSource } from "../models/IdentityAccountLink.js";
import type { CreateIdentityAccountLinkInput, IdentityAccountLinkRepository } from "./IdentityAccountLinkRepository.js";

function key(source: IdentityAccountLinkSource, externalUserId: string): string {
		return `${source}:${externalUserId}`;
}

// Test-only stand-in for PostgresIdentityAccountLinkRepository; never used in production.
export class InMemoryIdentityAccountLinkRepository implements IdentityAccountLinkRepository {
		private readonly linksByKey = new Map<string, IdentityAccountLink>();

		async findByExternalUserId(source: IdentityAccountLinkSource, externalUserId: string): Promise<IdentityAccountLink | undefined> {
				const link = this.linksByKey.get(key(source, externalUserId));
				return link ? { ...link } : undefined;
		}

		async create(input: CreateIdentityAccountLinkInput): Promise<IdentityAccountLink> {
				const linkKey = key(input.source, input.externalUserId);
				if (this.linksByKey.has(linkKey)) {
						throw new Error(`IdentityAccountLink already exists for ${linkKey}`);
				}

				const now = new Date().toISOString();
				const link: IdentityAccountLink = { ...input, linkedAt: now, updatedAt: now };
				this.linksByKey.set(linkKey, link);
				return { ...link };
		}
}

export const inMemoryIdentityAccountLinkRepository = new InMemoryIdentityAccountLinkRepository();
