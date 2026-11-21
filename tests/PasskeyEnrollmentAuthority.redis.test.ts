import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import { afterAll, describe, expect, it } from "vitest";
import { AuthorizationInteractionStore } from "../src/oidc/AuthorizationInteractionStore.js";
import { oidcRedisKey } from "../src/oidc/infrastructure/RedisInfrastructure.js";

const port = process.env.HAPI_PASSKEY_TEST_REDIS_PORT;

describe.skipIf(!port)("passkey enrollment authority (isolated Redis)", () => {
	const redis = new Redis({ host: "127.0.0.1", port: Number(port), lazyConnect: true });
	const store = new AuthorizationInteractionStore(redis);
	const principal = () => ({ id: randomUUID(), sub: randomUUID(), authenticationMethod: "HAPI_EMAIL" as const });
	const base = () => ({
		clientId: "test",
		authorization: { clientId: "test", redirectUri: "https://rp.example/callback", scope: "openid",
			nonce: "n", codeChallenge: "challenge" },
		request: { client_id: "test", redirect_uri: "https://rp.example/callback", response_type: "code", scope: "openid" }
	});

	afterAll(async () => { await redis.quit(); });

	it("claims a browser-bound authentication challenge once under concurrency and rejects stale interactions", async () => {
		for (let iteration = 0; iteration < 20; iteration++) {
			const { handle, interaction } = await store.create(base());
			const challenge = randomBytes(32).toString("base64url");
			expect(await store.beginPasskeyAuthentication(handle, interaction, challenge, "manage")).toBe(true);
			const claims = await Promise.all(Array.from({ length: 20 }, () => store.claimPasskeyAuthentication(handle, interaction)));
			expect(claims.filter(Boolean)).toHaveLength(1);
			expect(claims.find(Boolean)).toMatchObject({ challenge, purpose: "manage" });
			expect(await store.claimPasskeyAuthentication(handle, interaction)).toBeNull();
			expect((await Promise.all(Array.from({ length: 20 }, () => store.consumeExpected(handle, interaction)))).filter(Boolean)).toHaveLength(1);
		}
		const { handle, interaction } = await store.create(base());
		expect(await store.beginPasskeyAuthentication(handle, interaction, randomBytes(32).toString("base64url"))).toBe(true);
		expect(await store.save(handle, { ...interaction, email: { challengeId: "changed", mode: "AUTHENTICATION" } })).toBe(true);
		expect(await store.claimPasskeyAuthentication(handle, interaction)).toBeNull();
		expect(await store.claimPasskeyAuthentication(handle, (await store.find(handle))!)).toBeNull();
	});

	it("invalidates old management forms and claims a confirmation only once", async () => {
		const { handle, interaction } = await store.create(base());
		const user = principal();
		const proof = (await store.offerPasskeyEnrollment(handle, interaction, user))!.browserProof;
		const old = (await store.issuePasskeyManagement(handle, proof, interaction.csrf, user.id, "list"))!;
		const current = (await store.issuePasskeyManagement(handle, proof, interaction.csrf, user.id, "list"))!;
		expect(await store.claimPasskeyManagement(handle, proof, interaction.csrf, user.id, old, "list")).toBeNull();
		expect(await store.claimPasskeyManagement(handle, randomBytes(32).toString("base64url"),
			interaction.csrf, user.id, current, "list")).toBeNull();
		const claims = await Promise.all(Array.from({ length: 10 }, () =>
			store.claimPasskeyManagement(handle, proof, interaction.csrf, user.id, current, "list")));
		expect(claims.filter(Boolean)).toHaveLength(1);
		const confirmation = (await store.issuePasskeyManagement(handle, proof, interaction.csrf, user.id, "confirm",
			{ credentialId: "test-credential", name: "Test device" }))!;
		expect(await store.claimPasskeyManagement(handle, proof, interaction.csrf, user.id, confirmation, "list")).toBeNull();
		const results = await Promise.all(Array.from({ length: 10 }, () =>
			store.claimPasskeyManagement(handle, proof, interaction.csrf, user.id, confirmation, "confirm")));
		expect(results.filter(Boolean)).toEqual([{ credentialId: "test-credential", name: "Test device" }]);
	});

	it("rejects authentication challenges after their short-lived authority expires", async () => {
		let now = Date.now();
		const timedStore = new AuthorizationInteractionStore(redis, 600_000, () => now);
		const { handle, interaction } = await timedStore.create(base());
		expect(await timedStore.beginPasskeyAuthentication(handle, interaction, randomBytes(32).toString("base64url"))).toBe(true);
		now += 120_001;
		expect(await timedStore.claimPasskeyAuthentication(handle, interaction)).toBeNull();
	});

	it("allows only one offer, skip-or-enroll claim, and authorization completion under concurrency", async () => {
		for (let iteration = 0; iteration < 20; iteration++) {
			const { handle, interaction } = await store.create(base());
			const user = principal();
			const offers = await Promise.all(Array.from({ length: 10 }, () =>
				store.offerPasskeyEnrollment(handle, interaction, user)));
			expect(offers.filter(Boolean)).toHaveLength(1);
			const proof = offers.find(Boolean)!.browserProof;
			const claims = await Promise.all(Array.from({ length: 20 }, (_, index) =>
				store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, user.id,
					"OFFERED", index % 2 ? "SKIPPED" : "ENROLLING")));
			expect(claims.filter(Boolean)).toHaveLength(1);
			expect(await store.save(handle, interaction)).toBe(false);
			expect(await store.consume(handle)).toBeNull();
			if (claims.findIndex(Boolean) % 2 === 0) {
				expect(await store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, user.id,
					"ENROLLING", "ENROLLED")).toBe(true);
			}
			const results = await Promise.all(Array.from({ length: 20 }, () =>
				store.finishPasskeyEnrollment(handle, proof, interaction.csrf, user.id)));
			expect(results.filter(Boolean)).toHaveLength(1);
			expect(results.find(Boolean)?.principal).toEqual(user);
			expect(await store.save(handle, interaction)).toBe(false);
		}
	});

	it("rejects a stale offer, wrong browser, subject, CSRF, interaction and expired authority", async () => {
		let now = Date.now();
		const timedStore = new AuthorizationInteractionStore(redis, 600_000, () => now);
		const { handle, interaction } = await timedStore.create(base());
		const other = await timedStore.create(base());
		const user = principal();
		expect(await timedStore.save(handle, { ...interaction, email: { challengeId: "new", mode: "AUTHENTICATION" } })).toBe(true);
		expect(await timedStore.offerPasskeyEnrollment(handle, interaction, user)).toBeNull();
		const current = (await timedStore.find(handle))!;
		const proof = (await timedStore.offerPasskeyEnrollment(handle, current, user))!.browserProof;
		expect(await timedStore.transitionPasskeyEnrollment(handle, randomBytes(32).toString("base64url"),
			current.csrf, user.id, "OFFERED", "SKIPPED")).toBe(false);
		expect(await timedStore.transitionPasskeyEnrollment(handle, proof, "wrong",
			user.id, "OFFERED", "SKIPPED")).toBe(false);
		expect(await timedStore.transitionPasskeyEnrollment(handle, proof, current.csrf,
			randomUUID(), "OFFERED", "SKIPPED")).toBe(false);
		expect(await timedStore.transitionPasskeyEnrollment(other.handle, proof, other.interaction.csrf,
			user.id, "OFFERED", "SKIPPED")).toBe(false);
		now += 300_001;
		expect(await timedStore.transitionPasskeyEnrollment(handle, proof, current.csrf,
			user.id, "OFFERED", "SKIPPED")).toBe(false);
		expect(await timedStore.transitionPasskeyEnrollment(handle, proof, current.csrf,
			user.id, "OFFERED", "ENROLLING")).toBe(false);
		expect(await timedStore.consume(handle)).toBeNull();
		expect(await timedStore.expirePasskeyEnrollment(handle, proof, current.csrf, user.id)).toBe(true);
		expect((await timedStore.finishPasskeyEnrollment(handle, proof, current.csrf, user.id))?.principal).toEqual(user);
	});

	it("allows only an offer or ordinary interaction consumption to win concurrently", async () => {
		for (let iteration = 0; iteration < 20; iteration++) {
			const { handle, interaction } = await store.create(base());
			const user = principal();
			const [offered, consumed] = await Promise.all([
				store.offerPasskeyEnrollment(handle, interaction, user),
				store.consume(handle)
			]);
			expect(Number(Boolean(offered)) + Number(Boolean(consumed))).toBe(1);
			if (offered) {
				expect(await store.transitionPasskeyEnrollment(handle, offered.browserProof, interaction.csrf,
					user.id, "OFFERED", "SKIPPED")).toBe(true);
				expect((await store.finishPasskeyEnrollment(handle, offered.browserProof, interaction.csrf, user.id))?.principal).toEqual(user);
			}
			expect(await store.consume(handle)).toBeNull();
			expect(await store.save(handle, interaction)).toBe(false);
		}
	});

	it("does not enroll or finish an enrollment after authority expiry", async () => {
		let now = Date.now();
		const timedStore = new AuthorizationInteractionStore(redis, 600_000, () => now);
		const user = principal();
		const first = await timedStore.create(base());
		const proof = (await timedStore.offerPasskeyEnrollment(first.handle, first.interaction, user))!.browserProof;
		expect(await timedStore.transitionPasskeyEnrollment(first.handle, proof, first.interaction.csrf, user.id,
			"OFFERED", "ENROLLING")).toBe(true);
		now += 300_001;
		expect(await timedStore.transitionPasskeyEnrollment(first.handle, proof, first.interaction.csrf, user.id,
			"ENROLLING", "ENROLLED")).toBe(false);
		expect(await timedStore.transitionPasskeyEnrollment(first.handle, proof, first.interaction.csrf, user.id,
			"ENROLLING", "FAILED")).toBe(true);
		expect(await timedStore.finishPasskeyEnrollment(first.handle, proof, first.interaction.csrf, user.id)).not.toBeNull();

		const second = await timedStore.create(base());
		const secondProof = (await timedStore.offerPasskeyEnrollment(second.handle, second.interaction, user))!.browserProof;
		expect(await timedStore.transitionPasskeyEnrollment(second.handle, secondProof, second.interaction.csrf, user.id,
			"OFFERED", "ENROLLING")).toBe(true);
		expect(await timedStore.transitionPasskeyEnrollment(second.handle, secondProof, second.interaction.csrf, user.id,
			"ENROLLING", "ENROLLED")).toBe(true);
		now += 300_001;
		expect(await timedStore.finishPasskeyEnrollment(second.handle, secondProof, second.interaction.csrf, user.id)).toBeNull();
	});

	it("checks the live authority atomically in Redis when enrolling and completing", async () => {
		const user = principal();
		const { handle, interaction } = await store.create(base());
		const proof = (await store.offerPasskeyEnrollment(handle, interaction, user))!.browserProof;
		expect(await store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, user.id,
			"OFFERED", "ENROLLING")).toBe(true);
		const hash = createHash("sha256").update(handle).digest("base64url");
		const liveKey = oidcRedisKey(`interaction_passkey_enrollment_live:${hash}`);
		expect(await redis.pexpire(liveKey, 1)).toBe(1);
		await new Promise(resolve => setTimeout(resolve, 20));
		expect(await store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, user.id,
			"ENROLLING", "ENROLLED")).toBe(false);
		expect(await store.transitionPasskeyEnrollment(handle, proof, interaction.csrf, user.id,
			"ENROLLING", "FAILED")).toBe(true);
		expect(await store.finishPasskeyEnrollment(handle, proof, interaction.csrf, user.id)).not.toBeNull();

		const second = await store.create(base());
		const secondProof = (await store.offerPasskeyEnrollment(second.handle, second.interaction, user))!.browserProof;
		expect(await store.transitionPasskeyEnrollment(second.handle, secondProof, second.interaction.csrf, user.id,
			"OFFERED", "ENROLLING")).toBe(true);
		expect(await store.transitionPasskeyEnrollment(second.handle, secondProof, second.interaction.csrf, user.id,
			"ENROLLING", "ENROLLED")).toBe(true);
		const secondHash = createHash("sha256").update(second.handle).digest("base64url");
		expect(await redis.pexpire(oidcRedisKey(`interaction_passkey_enrollment_live:${secondHash}`), 1)).toBe(1);
		await new Promise(resolve => setTimeout(resolve, 20));
		expect(await store.finishPasskeyEnrollment(second.handle, secondProof, second.interaction.csrf, user.id)).toBeNull();
	});
});
