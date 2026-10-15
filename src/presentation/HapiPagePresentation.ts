import { randomBytes } from "node:crypto";

// Shared HAPI hosted-page visual system, extracted unchanged from Universal Login so Face Setup and
// Universal Login render with one design language (logo, tokens, typography, OTP control, busy state).
export type RenderedHapiPage = { html: string; contentSecurityPolicy: string };

export const escapeHtml = (value: string) => value.replace(/[&<>"']/g, character => ({
	"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
})[character]!);

export type ClientBrand = {
	clientId: string;
	brandName: string;
	logo: "bookwrm-sprouting-books";
	tokens: { primary: string; background: string; foreground: string; surface: string; border: string; focus: string };
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

export function brandForClient(clientId?: string): ClientBrand | undefined {
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

export const otpSubmitScript = (verifyingLabel = "Signing in") => `
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
			continueButton.textContent = "${verifyingLabel}\\u2026";
			status.textContent = "${verifyingLabel}\\u2026";
		} else {
			resendButton.textContent = "Sending a new code\\u2026";
			status.textContent = "Sending a new code\\u2026";
		}
	}
	otpForm.addEventListener("submit", submitOnce);
	resendForm.addEventListener("submit", submitOnce);
})();`;

export type HapiPageInput = {
	title: string;
	heading: string;
	body: string;
	script?: string;
	brand?: ClientBrand;
	// Optional small step label rendered above the heading (e.g. "STEP 2 OF 2").
	eyebrow?: string;
	fallbackFooter?: string;
	formActionSelf?: boolean;
};

// Shared HAPI hosted-page shell (Universal Login and Face Setup). Inline styles/scripts are nonce-bound.
export function renderHapiPage(input: HapiPageInput): RenderedHapiPage {
	const { title, heading, body, script, brand } = input;
	const nonce = randomBytes(16).toString("base64");
	const scriptNonce = script ? randomBytes(16).toString("base64") : undefined;
	const theme = brand ? brandTheme(brand, nonce) : "";
	const pageClass = brand ? "bookwrm" : "";
	const eyebrow = input.eyebrow ? `<p class="progress">${escapeHtml(input.eyebrow)}</p>` : "";
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)}</title><style nonce="${nonce}">${STYLE}</style>${theme}</head>
<body class="${pageClass}"><main class="${pageClass}">${brand ? brandLogo(brand) : ""}${eyebrow}<h1>${escapeHtml(heading)}</h1>${body}
<footer>${escapeHtml(brand?.supportCopy ?? input.fallbackFooter ?? "Secured by HAPI ID")}</footer></main>${script ? `<script nonce="${scriptNonce}">${script}</script>` : ""}</body></html>`;
	return {
		html,
		contentSecurityPolicy: `default-src 'none'; style-src 'nonce-${nonce}';${scriptNonce ? ` script-src 'nonce-${scriptNonce}';` : ""} base-uri 'none';${input.formActionSelf ? " form-action 'self';" : ""} frame-ancestors 'none'`
	};
}

export const alert = (message?: string, kind: "error" | "notice" = "error") =>
	message ? `<p class="${kind}" role="${kind === "error" ? "alert" : "status"}">${escapeHtml(message)}</p>` : "";
export const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">`;
