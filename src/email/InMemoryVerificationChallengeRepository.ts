import type { VerificationContext } from "./VerificationChallenge.js";
import type { VerificationChallengeRepository, VerificationSnapshot } from "./VerificationChallengeRepository.js";

export class InMemoryVerificationChallengeRepository implements VerificationChallengeRepository {
	private readonly snapshots = new Map<string, VerificationSnapshot>();
	private readonly locks = new Map<string, Promise<void>>();
	async findById(id: string) {
		for (const snapshot of this.snapshots.values()) {
			const challenge = snapshot.challenges.find(item => item.id === id);
			if (challenge) return structuredClone(challenge);
		}
		return undefined;
	}
	async findByProviderMessageId(id: string) {
		for (const snapshot of this.snapshots.values()) {
			const event = snapshot.delivery.find(item => item.providerMessageId === id && item.state === "PROVIDER_ACCEPTED");
			if (event) return structuredClone(event);
		}
		return undefined;
	}

	async transaction<Result>(context: VerificationContext, destinationHash: string,
		work: (snapshot: VerificationSnapshot) => Result): Promise<Result> {
		const key = JSON.stringify([context.tenantId, destinationHash]);
		const previous = this.locks.get(key) ?? Promise.resolve();
		let release!: () => void;
		const current = new Promise<void>(resolve => { release = resolve; });
		const tail = previous.then(() => current);
		this.locks.set(key, tail);
		await previous;
		try {
			const snapshot = structuredClone(this.snapshots.get(key) ?? { challenges: [], delivery: [], audit: [] });
			const result = work(snapshot);
			this.snapshots.set(key, snapshot);
			return structuredClone(result);
		} finally {
			release();
			if (this.locks.get(key) === tail) this.locks.delete(key);
		}
	}

	inspect(): VerificationSnapshot {
		return structuredClone({
			challenges: [...this.snapshots.values()].flatMap(item => item.challenges),
			delivery: [...this.snapshots.values()].flatMap(item => item.delivery),
			audit: [...this.snapshots.values()].flatMap(item => item.audit)
		});
	}
}