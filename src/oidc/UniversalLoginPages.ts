import {
	alert, brandForClient, csrfField, escapeHtml, otpSubmitScript, renderHapiPage, type ClientBrand, type RenderedHapiPage
} from "../presentation/HapiPagePresentation.js";

export type RenderedLoginPage = RenderedHapiPage;

const OTP_SUBMIT_SCRIPT = otpSubmitScript();

function render(title: string, heading: string, body: string, script?: string, brand?: ClientBrand): RenderedLoginPage {
	return renderHapiPage({ title, heading, body, script, brand });
}

const heading = (tenantName?: string) => tenantName ? `Sign in to ${tenantName}` : "Sign in";

export function chooserPage(input: { tenantName?: string; clientId?: string; csrf: string; emailAvailable: boolean; faceAvailable?: boolean; appleAvailable?: boolean; googleAvailable?: boolean; continueAs?: string; error?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	// Bookwrm Face is not certified for this release. A future caller must establish
	// client/release capability and returning-user enrollment before opting in.
	const faceAvailable = input.faceAvailable ?? !brand;
	// V2-D: an existing valid HAPI session lets the returning user continue without re-authenticating.
	const continueAs = input.continueAs
		? `<form method="post" action="/login/continue">${csrfField(input.csrf)}<button type="submit">Continue as ${escapeHtml(input.continueAs)}</button></form>` : "";
	const email = input.emailAvailable
		? `<form method="get" action="/login/email"><button type="submit"${continueAs ? ' class="secondary"' : ""}>${brand && !faceAvailable && !input.appleAvailable && !input.googleAvailable && !continueAs ? "Continue" : "Continue with Email"}</button></form>` : "";
	// V2-D federated sign-in launches: server-side POSTs that mint the provider transaction; the
	// browser never sees or chooses state/nonce values.
	const apple = input.appleAvailable
		? `<form method="post" action="/login/federated/apple">${csrfField(input.csrf)}<button type="submit" class="secondary">Continue with Apple</button></form>` : "";
	const google = input.googleAvailable
		? `<form method="post" action="/login/federated/google">${csrfField(input.csrf)}<button type="submit" class="secondary">Continue with Google</button></form>` : "";
	const face = faceAvailable
		? `<form method="post" action="/login/face">${csrfField(input.csrf)}<button type="submit" class="secondary">Continue with Face</button></form>` : "";
	return render(heading(input.tenantName), brand ? `Welcome to ${brand.brandName}` : heading(input.tenantName), `${alert(input.error)}
<p>${brand ? "Let's get you securely into your account." : "Choose how you want to sign in."}</p>${continueAs}${email}${apple}${google}${face}`,
		undefined, brand);
}

// V2-D: explicit account resolution after a server-verified Apple/Google authentication whose
// provider identity is not linked to any HAPI account. Creating a new account and signing in with
// email are both explicit user choices -- there is no automatic email-based resolution.
export function federatedAccountChoicePage(input: { tenantName?: string; clientId?: string; csrf: string; provider: "APPLE" | "GOOGLE"; email?: string; error?: string }): RenderedLoginPage {
	const brand = brandForClient(input.clientId);
	const providerName = input.provider === "APPLE" ? "Apple" : "Google";
	const contact = input.email ? ` (${escapeHtml(input.email)})` : "";
	return render(heading(input.tenantName), "Finish setting up your account", `${alert(input.error)}
<p>Your ${providerName} sign-in${contact} isn't connected to an account here yet.</p>
<form method="post" action="/login/federated/complete">${csrfField(input.csrf)}<input type="hidden" name="choice" value="create">
<button type="submit">Create a new account</button></form>
<form method="post" action="/login/federated/complete">${csrfField(input.csrf)}<input type="hidden" name="choice" value="email">
<button type="submit" class="secondary">I already have an account — sign in with email</button></form>
<p>After signing in with email you can connect ${providerName} from your account's sign-in settings.</p>`,
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
