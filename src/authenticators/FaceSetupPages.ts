import { randomBytes } from "node:crypto";
import { FACE_AUTH_CONSENT_TEXT } from "./FaceEnrollmentTypes.js";

export type RenderedFaceSetupPage = { html: string; contentSecurityPolicy: string };

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, character => ({
	"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
})[character]!);

const STYLE = `
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f4f5f7;color:#1c1e21}
main{width:100%;max-width:420px;margin:24px;padding:32px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:1.4rem;margin:0 0 8px}p{line-height:1.45;margin:0 0 16px;color:#44474c}
form{margin:0 0 12px}label{display:block;font-weight:600;margin:0 0 6px}
input[type=email],input[type=text]{width:100%;padding:12px;font-size:1rem;border:1px solid #c4c7cc;border-radius:8px;margin:0 0 12px}
button{width:100%;padding:12px;font-size:1rem;font-weight:600;border-radius:8px;border:1px solid #176b4d;background:#176b4d;color:#fff;cursor:pointer;margin:0 0 10px}
button.secondary{background:#fff;color:#176b4d}
.error{color:#a4161a;background:#fdecec;border-radius:8px;padding:10px 12px;margin:0 0 16px}
footer{margin-top:20px;font-size:.8rem;color:#6b6f76;text-align:center}
`;

function page(nonce: string, title: string, body: string): RenderedFaceSetupPage {
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title><style nonce="${nonce}">${STYLE}</style></head>
<body><main>${body}<footer>Secure identity powered by HAPI ID</footer></main></body></html>`;
	return {
		html,
		contentSecurityPolicy: `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
	};
}

export function faceSetupMessagePage(input: { title: string; message: string }): RenderedFaceSetupPage {
	const nonce = randomBytes(16).toString("base64");
	return page(nonce, input.title, `<h1>${escapeHtml(input.title)}</h1><p>${escapeHtml(input.message)}</p>`);
}

export function faceSetupProcessingPage(refreshUrl: string): RenderedFaceSetupPage {
	const nonce = randomBytes(16).toString("base64");
	const rendered = page(nonce, "Finishing Face setup",
		`<h1>Finishing Face setup</h1><p>Please wait while we confirm your enrollment. This page will refresh automatically.</p>`);
	return {
		html: rendered.html.replace("<head>", `<head><meta http-equiv="refresh" content="3;url=${escapeHtml(refreshUrl)}">`),
		contentSecurityPolicy: rendered.contentSecurityPolicy
	};
}

export function faceSetupEmailPage(input: { csrf: string; error?: string }): RenderedFaceSetupPage {
	const nonce = randomBytes(16).toString("base64");
	return page(nonce, "Set up Face Login", `<h1>Set up Face Login</h1>
<p>Confirm it's you by signing in again with your Bookwrm email.</p>
${input.error ? `<div class="error">${escapeHtml(input.error)}</div>` : ""}
<form method="POST" action="/face-setup/email">
<input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="email" required>
<button type="submit">Continue</button>
</form>
<form method="GET" action="/face-setup/cancel"><input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
<button type="submit" class="secondary">Not Now</button></form>`);
}

export function faceSetupCodePage(input: { csrf: string; error?: string }): RenderedFaceSetupPage {
	const nonce = randomBytes(16).toString("base64");
	return page(nonce, "Enter your code", `<h1>Enter your code</h1>
<p>We sent a one-time code to your email. Enter it below to continue setting up Face Login.</p>
${input.error ? `<div class="error">${escapeHtml(input.error)}</div>` : ""}
<form method="POST" action="/face-setup/email/code">
<input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
<label for="code">Code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" required>
<button type="submit">Verify</button>
</form>`);
}

export function faceSetupConsentPage(input: { csrf: string }): RenderedFaceSetupPage {
	const nonce = randomBytes(16).toString("base64");
	return page(nonce, "Set up Face Login", `<h1>Set up Face Login</h1>
<p>${escapeHtml(FACE_AUTH_CONSENT_TEXT)}</p>
<form method="POST" action="/face-setup/consent">
<input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
<input type="hidden" name="decision" value="agree">
<button type="submit">Agree &amp; Continue</button>
</form>
<form method="POST" action="/face-setup/consent">
<input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
<input type="hidden" name="decision" value="not_now">
<button type="submit" class="secondary">Not Now</button>
</form>`);
}
