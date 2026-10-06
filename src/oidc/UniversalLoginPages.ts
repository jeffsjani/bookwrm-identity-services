import { randomBytes } from "node:crypto";

export type RenderedLoginPage = { html: string; contentSecurityPolicy: string };

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, character => ({
	"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
})[character]!);

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
footer{margin-top:24px;font-size:.8rem;color:#6b6f76;text-align:center}`;

function render(title: string, heading: string, body: string): RenderedLoginPage {
	const nonce = randomBytes(16).toString("base64");
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)}</title><style nonce="${nonce}">${STYLE}</style></head>
<body><main><h1>${escapeHtml(heading)}</h1>${body}<footer>Secured by HAPI ID</footer></main></body></html>`;
	return {
		html,
		contentSecurityPolicy: `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`
	};
}

const heading = (tenantName?: string) => tenantName ? `Sign in to ${tenantName}` : "Sign in";
const alert = (message?: string, kind: "error" | "notice" = "error") =>
	message ? `<p class="${kind}" role="${kind === "error" ? "alert" : "status"}">${escapeHtml(message)}</p>` : "";
const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">`;

export function chooserPage(input: { tenantName?: string; csrf: string; emailAvailable: boolean; error?: string }): RenderedLoginPage {
	const email = input.emailAvailable
		? `<form method="get" action="/login/email"><button type="submit">Continue with Email</button></form>` : "";
	return render(heading(input.tenantName), heading(input.tenantName), `${alert(input.error)}
<p>Choose how you want to sign in.</p>${email}
<form method="post" action="/login/face">${csrfField(input.csrf)}<button type="submit" class="secondary">Continue with Face</button></form>`);
}

export function emailPage(input: { tenantName?: string; csrf: string; error?: string }): RenderedLoginPage {
	return render(heading(input.tenantName), heading(input.tenantName), `${alert(input.error)}
<form method="post" action="/login/email">${csrfField(input.csrf)}
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email" maxlength="320" required autofocus>
<button type="submit">Send code</button></form>
<p><a href="/login">Choose another way to sign in</a></p>`);
}

export function codePage(input: { tenantName?: string; csrf: string; error?: string; notice?: string }): RenderedLoginPage {
	return render(heading(input.tenantName), heading(input.tenantName), `${alert(input.error)}${alert(input.notice, "notice")}
<p>We sent a verification code to the email address you entered. Enter it below.</p>
<form method="post" action="/login/email/code">${csrfField(input.csrf)}
<label for="code">Verification code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,9}" maxlength="9" required autofocus>
<button type="submit">Continue</button></form>
<form method="post" action="/login/email/resend">${csrfField(input.csrf)}<button type="submit" class="secondary">Send a new code</button></form>
<p><a href="/login/email">Use a different email</a></p>`);
}

export function messagePage(input: { tenantName?: string; title: string; message: string }): RenderedLoginPage {
	return render(input.title, input.title, `<p>${escapeHtml(input.message)}</p>`);
}
