import Fastify from "fastify";
import formbody from "@fastify/formbody";
import { JSDOM } from "jsdom";
import { afterEach, describe, expect, it } from "vitest";
import { chooserPage, codePage, emailPage, messagePage } from "../src/oidc/UniversalLoginPages.js";

const instances: JSDOM[] = [];
const CSRF = "csrf+/=&";
const CODE = "123456";

function page(input: { error?: string; notice?: string } = {}) {
	const rendered = codePage({ csrf: CSRF, ...input });
	const dom = new JSDOM(rendered.html, { url: "https://hapi.example.test/login/email/code", runScripts: "dangerously" });
	instances.push(dom);
	const { document } = dom.window;
	const otp = document.querySelector<HTMLFormElement>("#otp-form")!;
	const resend = document.querySelector<HTMLFormElement>("#resend-form")!;
	const continueButton = document.querySelector<HTMLButtonElement>("#otp-submit")!;
	const resendButton = document.querySelector<HTMLButtonElement>("#resend-submit")!;
	const code = document.querySelector<HTMLInputElement>("#code")!;
	const csrf = otp.querySelector<HTMLInputElement>('[name="csrf"]')!;
	const status = document.querySelector<HTMLParagraphElement>("#otp-status")!;
	code.value = CODE;
	const body = (form: HTMLFormElement) => {
		const payload = new URLSearchParams();
		new dom.window.FormData(form).forEach((value, name) => {
			if (typeof value !== "string") throw new Error("Unexpected file field");
			payload.append(name, value);
		});
		return payload.toString();
	};
	const events: Array<{ form: HTMLFormElement; prevented: boolean }> = [];
	for (const form of [otp, resend]) {
		form.addEventListener("submit", event => events.push({ form, prevented: event.defaultPrevented }));
	}
	const submissions: Array<{ action: string; method: string; body: string }> = [];
	// Observe the native default-action boundary, then cancel navigation in this DOM-only test.
	dom.window.addEventListener("submit", event => {
		const form = event.target as HTMLFormElement;
		if (!event.defaultPrevented) {
			submissions.push({ action: form.action, method: form.method, body: body(form) });
		}
		event.preventDefault();
	});
	const submitEvent = (form = otp) => {
		const event = new dom.window.SubmitEvent("submit", { bubbles: true, cancelable: true });
		form.dispatchEvent(event);
		return event;
	};
	return { rendered, dom, document, otp, resend, continueButton, resendButton, code, csrf, status,
		body, events, submissions, submitEvent };
}

afterEach(() => {
	for (const dom of instances.splice(0)) dom.window.close();
});

describe("Universal Login OTP page submit-once guard", () => {
	it("preserves the first native POST, its exact encoded fields, and only one submission", async () => {
		const f = page();
		const certifiedBody = new URLSearchParams({ csrf: CSRF, code: CODE }).toString();
		expect(f.otp.getAttribute("action")).toBe("/login/email/code");
		expect(f.otp.getAttribute("method")).toBe("post");
		expect(f.document.forms).toHaveLength(2);
		expect(f.otp.querySelectorAll('button[type="submit"]')).toHaveLength(1);
		expect(f.body(f.otp)).toBe(certifiedBody);
		f.continueButton.click();
		f.continueButton.click();
		f.submitEvent();
		expect(f.events.map(event => event.prevented)).toEqual([false, true]);
		expect(f.submissions).toEqual([{
			action: "https://hapi.example.test/login/email/code", method: "post", body: certifiedBody
		}]);
		expect(f.code.disabled).toBe(false);
		expect(f.csrf.disabled).toBe(false);
		expect(f.body(f.otp)).toBe(certifiedBody);

		const app = Fastify();
		await app.register(formbody);
		let requests = 0;
		app.post("/login/email/code", async request => {
			requests++;
			return request.body;
		});
		try {
			for (const submission of f.submissions) {
				const response = await app.inject({ method: "POST", url: new URL(submission.action).pathname,
					headers: { "content-type": "application/x-www-form-urlencoded" }, payload: submission.body });
				expect(response.json()).toEqual({ csrf: CSRF, code: CODE });
			}
			expect(requests).toBe(1);
		} finally { await app.close(); }
	});

	it("keeps every hidden payload field enabled and byte-equivalent after locking the UI", () => {
		const f = page();
		const hidden = f.document.createElement("input");
		hidden.type = "hidden";
		hidden.name = "additional";
		hidden.value = "value +/&=";
		f.otp.append(hidden);
		const before = f.body(f.otp);
		f.continueButton.click();
		expect(f.submissions[0].body).toBe(before);
		expect(f.body(f.otp)).toBe(before);
		expect(hidden.disabled).toBe(false);
		expect(f.otp.querySelectorAll("input:disabled")).toHaveLength(0);
		expect(f.continueButton.hasAttribute("name")).toBe(false);
	});

	it.each(["Enter", "OTP autofill", "accidental double activation"])(
		"allows the first %s submit event and suppresses all repeated submit events", () => {
			const f = page();
			f.submitEvent();
			const second = f.submitEvent();
			const third = f.submitEvent();
			expect(f.events.map(event => event.prevented)).toEqual([false, true, true]);
			expect(second.defaultPrevented).toBe(true);
			expect(third.defaultPrevented).toBe(true);
			expect(f.submissions).toHaveLength(1);
		}
	);

	it("disables both submit buttons, exposes accessible busy status, and leaves focus unchanged", () => {
		const f = page();
		f.code.focus();
		f.continueButton.click();
		expect(f.continueButton.disabled).toBe(true);
		expect(f.resendButton.disabled).toBe(true);
		expect(f.continueButton.textContent).toBe("Signing in\u2026");
		expect(f.otp.getAttribute("aria-busy")).toBe("true");
		expect(f.status.getAttribute("role")).toBe("status");
		expect(f.status.getAttribute("aria-live")).toBe("polite");
		expect(f.status.textContent).toBe("Signing in\u2026");
		expect(f.document.activeElement).toBe(f.code);
	});

	it("blocks resend clicks and competing resend events after OTP submission", () => {
		const f = page();
		f.continueButton.click();
		f.resendButton.click();
		const resend = f.submitEvent(f.resend);
		expect(resend.defaultPrevented).toBe(true);
		expect(f.submissions).toHaveLength(1);
		expect(f.submissions[0].action).toBe(f.otp.action);
	});

	it("preserves the first native resend POST and blocks competing OTP and resend submissions", () => {
		const f = page();
		const before = f.body(f.resend);
		f.resendButton.click();
		f.continueButton.click();
		f.resendButton.click();
		f.submitEvent(f.otp);
		f.submitEvent(f.resend);
		expect(f.events.map(event => event.prevented)).toEqual([false, true, true]);
		expect(f.submissions).toEqual([{
			action: "https://hapi.example.test/login/email/resend", method: "post", body: before
		}]);
		expect(before).toBe(new URLSearchParams({ csrf: CSRF }).toString());
		expect(f.resend.querySelector<HTMLInputElement>('[name="csrf"]')!.disabled).toBe(false);
		expect(f.continueButton.disabled).toBe(true);
		expect(f.resendButton.disabled).toBe(true);
		expect(f.resend.getAttribute("aria-busy")).toBe("true");
		expect(f.status.textContent).toBe("Sending a new code\u2026");
	});

	it("does not lock the page when native constraint validation rejects the OTP", () => {
		const f = page();
		for (const invalid of ["", "123", "not-a-code"]) {
			f.code.value = invalid;
			f.continueButton.click();
		}
		expect(f.events).toHaveLength(0);
		expect(f.submissions).toHaveLength(0);
		expect(f.continueButton.disabled).toBe(false);
		expect(f.resendButton.disabled).toBe(false);
		f.code.value = CODE;
		f.continueButton.click();
		expect(f.submissions).toHaveLength(1);
	});

	it.each([{ error: "Check the code and try again." }, { notice: "We sent a new code." }])(
		"a newly rendered response starts unlocked and permits a legitimate retry: %j", input => {
			const previous = page();
			previous.continueButton.click();
			const fresh = page(input);
			expect(fresh.continueButton.disabled).toBe(false);
			expect(fresh.resendButton.disabled).toBe(false);
			expect(fresh.continueButton.textContent).toBe("Continue");
			expect(fresh.otp.getAttribute("aria-busy")).toBe("false");
			expect(fresh.status.textContent).toBe("");
			expect(fresh.document.querySelector(input.error ? '[role="alert"]' : ".notice")!.textContent)
				.toBe(input.error ?? input.notice);
			fresh.continueButton.click();
			expect(fresh.events[0].prevented).toBe(false);
			expect(fresh.submissions).toHaveLength(1);
		}
	);

	it("uses a separate unpredictable response-local script nonce and strict nonce-only CSP", () => {
		const first = page();
		const second = page();
		const script = first.document.querySelector("script")!;
		const nonce = script.getAttribute("nonce")!;
		expect(Buffer.from(nonce, "base64")).toHaveLength(16);
		expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
		expect(nonce).not.toBe(second.document.querySelector("script")!.getAttribute("nonce"));
		expect(nonce).not.toBe(first.document.querySelector("style")!.getAttribute("nonce"));
		expect(first.rendered.html.split(nonce)).toHaveLength(2);
		expect(first.rendered.contentSecurityPolicy).toContain(`script-src 'nonce-${nonce}'`);
		expect(first.rendered.contentSecurityPolicy).toContain("default-src 'none'");
		expect(first.rendered.contentSecurityPolicy).toContain("base-uri 'none'");
		expect(first.rendered.contentSecurityPolicy).toContain("frame-ancestors 'none'");
		expect(first.rendered.contentSecurityPolicy).not.toMatch(/unsafe-inline|unsafe-eval|https:|\*/);
		expect(first.document.scripts).toHaveLength(1);
		expect(script.hasAttribute("src")).toBe(false);
		expect(script.textContent).not.toMatch(/fetch|XMLHttpRequest|requestSubmit|\.submit\(|location/);
	});

	it("keeps scripts disabled on non-OTP pages", () => {
		for (const rendered of [
			chooserPage({ csrf: CSRF, emailAvailable: true }),
			emailPage({ csrf: CSRF }),
			messagePage({ title: "Sign-in unavailable", message: "Try again later." })
		]) {
			expect(rendered.html).not.toContain("<script");
			expect(rendered.contentSecurityPolicy).not.toContain("script-src");
			expect(rendered.contentSecurityPolicy).toContain("default-src 'none'");
		}
	});
});
