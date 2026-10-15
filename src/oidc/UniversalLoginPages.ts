import {
	alert, brandForClient, csrfField, escapeHtml, otpSubmitScript, renderHapiPage, type ClientBrand, type RenderedHapiPage
} from "../presentation/HapiPagePresentation.js";

export type RenderedLoginPage = RenderedHapiPage;

const OTP_SUBMIT_SCRIPT = otpSubmitScript();

function render(title: string, heading: string, body: string, script?: string, brand?: ClientBrand): RenderedLoginPage {
	return renderHapiPage({ title, heading, body, script, brand });
}

const heading = (tenantName?: string) => tenantName ? `Sign in to ${tenantName}` : "Sign in";

export function chooserPage(input: { tenantName?: string; clientId?: string; csrf: string; emailAvailable: boolean; faceAvailable?: boolean; error?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	// Bookwrm Face is not certified for this release. A future caller must establish
	// client/release capability and returning-user enrollment before opting in.
	const faceAvailable = input.faceAvailable ?? !brand;
	const email = input.emailAvailable
		? `<form method="get" action="/login/email"><button type="submit">${brand && !faceAvailable ? "Continue" : "Continue with Email"}</button></form>` : "";
	const face = faceAvailable
		? `<form method="post" action="/login/face">${csrfField(input.csrf)}<button type="submit" class="secondary">Continue with Face</button></form>` : "";
	return render(heading(input.tenantName), brand ? `Welcome to ${brand.brandName}` : heading(input.tenantName), `${alert(input.error)}
<p>${brand ? "Let's get you securely into your account." : "Choose how you want to sign in."}</p>${email}${face}`,
		undefined, brand);
}

export function emailPage(input: { tenantName?: string; clientId?: string; csrf: string; error?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	const content = brand
		? `${alert(input.error)}
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
