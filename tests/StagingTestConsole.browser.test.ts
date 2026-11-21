import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, rmdirSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { exportJWK, importPKCS8, SignJWT } from "jose";
import { chromium } from "playwright";
import { describe, expect, it } from "vitest";
import { registerStagingTestConsole, STAGING_ISSUER } from "../src/oidc/StagingTestConsole.js";

describe("staging console browser authentication", () => {
	it("re-challenges and completes the callback when credentials are not forwarded", async () => {
		const directory = mkdtempSync(join(tmpdir(), "hapi-console-browser-"));
		const keyFile = join(directory, "key.pem");
		const certFile = join(directory, "cert.pem");
		let proxy: Server | undefined;
		const browser = await chromium.launch();
		try {
			execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile,
				"-out", certFile, "-subj", "/CN=id-staging.hapiinc.com", "-days", "1"], { stdio: "ignore" });
			const app = Fastify({ https: { key: readFileSync(keyFile), cert: readFileSync(certFile) } });
			await app.register(formbody);
			const password = "browser-fixture-password-".padEnd(40, "x");
			const secret = "browser-fixture-client-".padEnd(40, "y");
			const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
			const privateKey = await importPKCS8(keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "RS256");
			const jwk = { ...await exportJWK(keys.publicKey), kid: "test", alg: "RS256" };
			let nonce = "";
			let challenge = "";
			let callbackAttempts = 0;
			let startEvidence = "";
			app.addHook("onRequest", async request => {
				if (request.url === "/staging-console/start") {
					startEvidence = `cookie=${Boolean(request.headers.cookie)} origin=${request.headers.origin ?? "<missing>"}`;
				}
				if (request.url.startsWith("/staging-console/callback?") && ++callbackAttempts === 1) {
					delete request.headers.authorization;
				}
			});
			app.get("/authorize", async (request, reply) => {
				const query = request.query as Record<string, string>;
				nonce = query.nonce;
				challenge = query.code_challenge;
				return reply.redirect(`/staging-console/callback?code=synthetic-code&state=${encodeURIComponent(query.state)}`, 303);
			});
			app.post("/token", async (request, reply) => {
				const body = request.body as Record<string, string>;
				if (createHash("sha256").update(body.code_verifier).digest("base64url") !== challenge) {
					return reply.code(400).send({ error: "invalid_grant" });
				}
				const token = await new SignJWT({ nonce, amr: ["email"] }).setProtectedHeader({ alg: "RS256", kid: "test" })
					.setIssuer(STAGING_ISSUER).setAudience("staging-web").setSubject("synthetic-subject")
					.setIssuedAt().setExpirationTime("5 minutes").sign(privateKey);
				return { id_token: token, access_token: "synthetic-access-token" };
			});
			app.get("/jwks", async () => ({ keys: [jwk] }));
			app.get("/userinfo", async () => ({ sub: "synthetic-subject", email: "jeff@hapiinc.com", email_verified: true }));
			await registerStagingTestConsole(app, { issuer: STAGING_ISSUER, env: {
				STAGING_TEST_CONSOLE_ENABLED: "true", STAGING_TEST_CONSOLE_USERNAME: "operator",
				STAGING_TEST_CONSOLE_PASSWORD: password, STAGING_WEB_CLIENT_SECRET: secret,
				HAPI_EMAIL_PROVIDER: "resend", HAPI_EMAIL_AUTHENTICATION_ENABLED: "true", HAPI_UNIVERSAL_LOGIN_ENABLED: "true"
			} });
			const address = await app.listen({ host: "127.0.0.1", port: 0 });
			const port = Number(new URL(address).port);
			proxy = createServer();
			proxy.on("connect", (request, client, head) => {
				if (request.url !== "id-staging.hapiinc.com:443") return client.destroy();
				const upstream = connect(port, "127.0.0.1", () => {
					client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
					if (head.length) upstream.write(head);
					client.pipe(upstream);
					upstream.pipe(client);
				});
				upstream.on("error", () => client.destroy());
				client.on("error", () => upstream.destroy());
			});
			await new Promise<void>(resolve => proxy!.listen(0, "127.0.0.1", resolve));
			const proxyPort = (proxy.address() as AddressInfo).port;
			const context = await browser.newContext({ ignoreHTTPSErrors: true,
				proxy: { server: `http://127.0.0.1:${proxyPort}` }, httpCredentials: { username: "operator", password } });
			try {
				const page = await context.newPage();
				page.setDefaultTimeout(5000);
				page.setDefaultNavigationTimeout(5000);
				const responses: string[] = [];
				page.on("response", response => responses.push(`${new URL(response.url()).pathname}: ${response.status()}`));
				await page.goto(`${STAGING_ISSUER}/staging-console/`);
				const session = (await context.cookies()).find(cookie => cookie.name === "__Host-hapi_staging_test");
				expect(session).toMatchObject({ secure: true, httpOnly: true, sameSite: "Lax", path: "/" });
				expect(session!.expires - Date.now() / 1000).toBeGreaterThan(590);
				expect(session!.expires - Date.now() / 1000).toBeLessThanOrEqual(600);
				await page.getByRole("button", { name: "Start test" }).click();
				try {
					await page.getByRole("heading", { name: "Test passed" }).waitFor({ timeout: 5000 });
				} catch {
					throw new Error(`Browser did not finish: ${responses.join(", ")}; callback attempts ${callbackAttempts}; ${startEvidence}`);
				}
				expect(callbackAttempts).toBeGreaterThanOrEqual(2);
				expect(page.url()).toBe(`${STAGING_ISSUER}/staging-console/results`);
			} finally {
				await context.close();
				await app.close();
			}
		} finally {
			await browser.close();
			if (proxy) await new Promise<void>((resolve, reject) => proxy!.close(error => error ? reject(error) : resolve()));
			rmSync(keyFile, { force: true });
			rmSync(certFile, { force: true });
			rmdirSync(directory);
		}
	}, 30_000);
});
