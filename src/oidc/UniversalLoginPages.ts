import { randomBytes } from "node:crypto";

export type RenderedLoginPage = { html: string; contentSecurityPolicy: string };

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, character => ({
	"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
})[character]!);

type ClientBrand = {
	clientId: string;
	brandName: string;
	logo: "bookwrm-sprouting-books";
	tokens: { primary: string; background: string; foreground: string; surface: string; border: string; focus: string };
	welcomeCopy: string;
	supportCopy: string;
};

const CLIENT_BRANDS: Readonly<Record<string, ClientBrand>> = {
	"bookwrm-base44-production": {
		clientId: "bookwrm-base44-production",
		brandName: "Bookwrm",
		logo: "bookwrm-sprouting-books",
		tokens: {
			primary: "#176b4d", background: "#fbfaf6", foreground: "#172321",
			surface: "#ffffff", border: "#dce5df", focus: "#176b4d"
		},
		welcomeCopy: "Let's secure your account.",
		supportCopy: "Secure identity powered by HAPI ID"
	}
};

const STYLE = `
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f4f5f7;color:#1c1e21}
main{width:100%;max-width:400px;margin:24px;padding:32px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:1.4rem;margin:0 0 8px}p{line-height:1.45;margin:0 0 16px;color:#44474c}
form{margin:0 0 12px}label{display:block;font-weight:600;margin:0 0 6px}
input[type=email],input[type=text]{width:100%;padding:12px;font-size:1rem;border:1px solid #c4c7cc;border-radius:8px;margin:0 0 12px}
button{width:100%;padding:12px;font-size:1rem;font-weight:600;border-radius:8px;border:1px solid #1b4dd6;background:#1b4dd6;color:#fff;cursor:pointer}
button.secondary{background:#fff;color:#1b4dd6}a{color:#1b4dd6}
.error{color:#a4161a;background:#fdecec;border-radius:8px;padding:10px 12px}.notice{color:#0c5132;background:#e6f4ea;border-radius:8px;padding:10px 12px}
footer{margin-top:24px;font-size:.8rem;color:#6b6f76;text-align:center}
.visually-hidden{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
`;

const BOOKWRM_STYLE = `
body.bookwrm{background:var(--brand-background);color:var(--brand-foreground);padding:16px}
.bookwrm main{max-width:460px;margin:16px;padding:clamp(26px,7vw,44px);background:var(--brand-surface);border:1px solid var(--brand-border);
border-radius:20px;box-shadow:0 12px 40px rgba(24,55,42,.08)}
.bookwrm h1{font-size:clamp(1.8rem,7vw,2.35rem);line-height:1.12;letter-spacing:-.035em;margin:0 0 12px;color:var(--brand-foreground)}
.bookwrm .step-heading{font-size:1.15rem;font-weight:700;margin:22px 0 8px;color:var(--brand-foreground)}
.bookwrm p{color:#46534e}
.bookwrm .brand-logo{display:block;width:58px;height:58px;margin:0 0 22px}
.bookwrm .welcome-copy{font-size:1.08rem;margin-bottom:24px}
.bookwrm .progress{margin:0 0 10px;color:var(--brand-primary);font-weight:700;font-size:.75rem;letter-spacing:.09em}
.bookwrm label{color:var(--brand-foreground)}
.bookwrm input[type=email],.bookwrm input[type=text]{border-color:var(--brand-border);padding:14px;border-radius:10px;color:var(--brand-foreground)}
.bookwrm input[type=text].otp-code{height:58px;border:0;border-radius:10px;
background-color:#f7faf8;background-image:linear-gradient(90deg,var(--brand-border) 1px,transparent 1px);
background-size:calc(100% / 6) 100%;box-shadow:inset 0 0 0 1px var(--brand-border);text-align:center;
font-size:1.5rem;font-weight:650;letter-spacing:.42em;font-variant-numeric:tabular-nums;padding-left:.42em}
.bookwrm button{background:var(--brand-primary);border-color:var(--brand-primary);border-radius:10px;padding:14px}
.bookwrm button.secondary{background:var(--brand-surface);color:var(--brand-primary)}
.bookwrm a{color:var(--brand-primary)}
.bookwrm button:focus-visible,.bookwrm input:focus-visible,.bookwrm a:focus-visible{outline:3px solid var(--brand-focus);outline-offset:3px}
.bookwrm footer{color:#52615a}`;

function brandForClient(clientId?: string): ClientBrand | undefined {
	return clientId ? CLIENT_BRANDS[clientId] : undefined;
}

function brandLogo(brand: ClientBrand): string {
	switch (brand.logo) {
		case "bookwrm-sprouting-books":
			return `<svg class="brand-logo" viewBox="0 0 64 64" role="img" aria-label="${escapeHtml(brand.brandName)}">
<path d="M8 24c8-3 16-1 24 5v25c-8-6-16-8-24-5V24Zm48 0c-8-3-16-1-24 5v25c8-6 16-8 24-5V24Z" fill="none" stroke="${brand.tokens.primary}" stroke-width="3" stroke-linejoin="round"/>
<path d="M32 28c-2-8 1-15 7-20 1 7-1 12-7 16m1 1c2-7 8-10 15-10-3 6-8 9-15 10" fill="none" stroke="${brand.tokens.primary}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
	}
}

function brandTheme(brand: ClientBrand, nonce: string): string {
	const entries = Object.entries(brand.tokens);
	if (entries.some(([, color]) => !/^#[0-9a-f]{6}$/i.test(color))) {
		throw new Error(`Invalid presentation color configured for ${brand.clientId}`);
	}
	const variables = entries.map(([token, color]) => `--brand-${token}:${color}`).join(";");
	return `<style nonce="${nonce}">.bookwrm{${variables}}${BOOKWRM_STYLE}</style>`;
}

const OTP_SUBMIT_SCRIPT = `
(() => {
	const otpForm = document.getElementById("otp-form");
	const resendForm = document.getElementById("resend-form");
	const continueButton = document.getElementById("otp-submit");
	const resendButton = document.getElementById("resend-submit");
	const status = document.getElementById("otp-status");
	let submitting = false;
	function submitOnce(event) {
		if (submitting) {
			event.preventDefault();
			event.stopPropagation();
			return;
		}
		submitting = true;
		continueButton.disabled = true;
		resendButton.disabled = true;
		event.currentTarget.setAttribute("aria-busy", "true");
		if (event.currentTarget === otpForm) {
			continueButton.textContent = "Signing in\\u2026";
			status.textContent = "Signing in\\u2026";
		} else {
			resendButton.textContent = "Sending a new code\\u2026";
			status.textContent = "Sending a new code\\u2026";
		}
	}
	otpForm.addEventListener("submit", submitOnce);
	resendForm.addEventListener("submit", submitOnce);
})();`;

function render(title: string, heading: string, body: string, script?: string, brand?: ClientBrand): RenderedLoginPage {
	const nonce = randomBytes(16).toString("base64");
	const scriptNonce = script ? randomBytes(16).toString("base64") : undefined;
	const theme = brand ? brandTheme(brand, nonce) : "";
	const pageClass = brand ? "bookwrm" : "";
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)}</title><style nonce="${nonce}">${STYLE}</style>${theme}</head>
<body class="${pageClass}"><main class="${pageClass}">${brand ? brandLogo(brand) : ""}<h1>${escapeHtml(heading)}</h1>${body}
<footer>${escapeHtml(brand?.supportCopy ?? "Secured by HAPI ID")}</footer></main>${script ? `<script nonce="${scriptNonce}">${script}</script>` : ""}</body></html>`;
	return {
		html,
		contentSecurityPolicy: `default-src 'none'; style-src 'nonce-${nonce}';${scriptNonce ? ` script-src 'nonce-${scriptNonce}';` : ""} base-uri 'none'; frame-ancestors 'none'`
	};
}

const heading = (tenantName?: string) => tenantName ? `Sign in to ${tenantName}` : "Sign in";
const alert = (message?: string, kind: "error" | "notice" = "error") =>
	message ? `<p class="${kind}" role="${kind === "error" ? "alert" : "status"}">${escapeHtml(message)}</p>` : "";
const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">`;

export function chooserPage(input: { tenantName?: string; clientId?: string; csrf: string; emailAvailable: boolean; error?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	const email = input.emailAvailable
		? `<form method="get" action="/login/email"><button type="submit">${brand ? "Continue with email" : "Continue with Email"}</button></form>` : "";
	return render(heading(input.tenantName), brand ? `Welcome to ${brand.brandName}` : heading(input.tenantName), `${alert(input.error)}
<p>${brand ? "Let's get you securely into your account." : "Choose how you want to sign in."}</p>${email}
<form method="post" action="/login/face">${csrfField(input.csrf)}<button type="submit" class="secondary">Continue with Face</button></form>`,
		undefined, brand);
}

export function emailPage(input: { tenantName?: string; clientId?: string; csrf: string; error?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	const content = brand
		? `<p class="welcome-copy">${escapeHtml(brand.welcomeCopy)}</p>${alert(input.error)}
<p class="progress">STEP 1 OF 2</p><div class="step-heading">Confirm your email</div>
<p>We'll send you a one-time verification code.</p>
<form method="post" action="/login/email">${csrfField(input.csrf)}
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="email" maxlength="320" required autofocus>
<button type="submit">Send My Code</button></form>`
		: `${alert(input.error)}
<form method="post" action="/login/email">${csrfField(input.csrf)}
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email" maxlength="320" required autofocus>
<button type="submit">Send code</button></form>
<p><a href="/login">Choose another way to sign in</a></p>`;
	return render(heading(input.tenantName), brand ? `Welcome to ${brand.brandName}` : heading(input.tenantName), content, undefined, brand);
}

export function codePage(input: { tenantName?: string; clientId?: string; csrf: string; error?: string; notice?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	const content = brand
		? `${alert(input.error)}${alert(input.notice, "notice")}
<p class="progress">STEP 2 OF 2</p><p>We sent a verification code to the email address you entered.</p>
<form id="otp-form" method="post" action="/login/email/code" aria-busy="false">${csrfField(input.csrf)}
<label class="visually-hidden" for="code">Six-digit verification code</label>
<input class="otp-code" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,9}" maxlength="9" aria-label="Six-digit verification code" required autofocus>
<button id="otp-submit" type="submit">Verify &amp; Continue</button></form>
<p>Didn't receive it?</p>
<form id="resend-form" method="post" action="/login/email/resend" aria-busy="false">${csrfField(input.csrf)}<button id="resend-submit" type="submit" class="secondary">Resend code</button></form>
<p id="otp-status" role="status" aria-live="polite"></p><p><a href="/login/email">Use a different email</a></p>`
		: `${alert(input.error)}${alert(input.notice, "notice")}
<p>We sent a verification code to the email address you entered. Enter it below.</p>
<form id="otp-form" method="post" action="/login/email/code" aria-busy="false">${csrfField(input.csrf)}
<label for="code">Verification code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,9}" maxlength="9" required autofocus>
<button id="otp-submit" type="submit">Continue</button></form>
<form id="resend-form" method="post" action="/login/email/resend" aria-busy="false">${csrfField(input.csrf)}<button id="resend-submit" type="submit" class="secondary">Send a new code</button></form>
<p id="otp-status" role="status" aria-live="polite"></p>
<p><a href="/login/email">Use a different email</a></p>`;
	return render(brand ? "Check your inbox" : heading(input.tenantName), brand ? "Check your inbox" : heading(input.tenantName),
		content, OTP_SUBMIT_SCRIPT, brand);
}

export function messagePage(input: { tenantName?: string; title: string; message: string }): RenderedLoginPage {
	return render(input.title, input.title, `<p>${escapeHtml(input.message)}</p>`);
}
