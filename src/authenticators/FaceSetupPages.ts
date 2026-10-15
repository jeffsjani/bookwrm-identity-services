import { FACE_AUTH_CONSENT_TEXT } from "./FaceEnrollmentTypes.js";
import {
	alert, brandForClient, csrfField, escapeHtml, otpSubmitScript, renderHapiPage, type RenderedHapiPage
} from "../presentation/HapiPagePresentation.js";

export type RenderedFaceSetupPage = RenderedHapiPage;

// Face Setup renders with the shared HAPI/Universal Login visual system; only the copy is Face-specific.
const FOOTER = "Secure identity powered by HAPI ID";

function page(input: { title: string; body: string; clientId?: string; heading?: string; eyebrow?: string; script?: string }): RenderedFaceSetupPage {
	return renderHapiPage({
		title: input.title, heading: input.heading ?? input.title, body: input.body, script: input.script,
		brand: brandForClient(input.clientId), eyebrow: input.eyebrow, fallbackFooter: FOOTER, formActionSelf: true
	});
}

function withRefresh(rendered: RenderedFaceSetupPage, seconds: number, destination: string): RenderedFaceSetupPage {
	return { ...rendered, html: rendered.html.replace("<head>", `<head><meta http-equiv="refresh" content="${seconds};url=${escapeHtml(destination)}">`) };
}

export function faceSetupMessagePage(input: { title: string; message: string; clientId?: string }): RenderedFaceSetupPage {
	return page({ title: input.title, clientId: input.clientId, body: `<p>${escapeHtml(input.message)}</p>` });
}

export function faceSetupNavigationPage(destination: string, clientId?: string): RenderedFaceSetupPage {
	// End the form navigation before a separate document navigation can leave this origin.
	return withRefresh(page({ title: "Continue Face setup", clientId,
		body: `<p>Continuing Face Login setup. If you are not redirected, <a href="${escapeHtml(destination)}">continue here</a>.</p>` }), 0, destination);
}

export function faceSetupProcessingPage(refreshUrl: string, clientId?: string): RenderedFaceSetupPage {
	return withRefresh(page({ title: "Finishing Face setup", clientId,
		body: `<p role="status">Please wait while we confirm your enrollment. This page will refresh automatically.</p>` }), 3, refreshUrl);
}

export function faceSetupEmailPage(input: { csrf: string; error?: string; clientId?: string }): RenderedFaceSetupPage {
	return page({ title: "Set up Face Login", clientId: input.clientId, eyebrow: "STEP 1 OF 2", body: `${alert(input.error)}
<p>Confirm it's you by signing in again with your Bookwrm email.</p>
<form method="POST" action="/face-setup/email">${csrfField(input.csrf)}
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="email" maxlength="320" required autofocus>
<button type="submit">Continue</button>
</form>
<form method="GET" action="/face-setup/cancel">${csrfField(input.csrf)}
<button type="submit" class="secondary">Not Now</button></form>` });
}

// Same H4 OTP control, busy state and resend affordance as Universal Login; authentication semantics are
// unchanged (verify and resend post to the existing Face Setup H4 endpoints within the same ceremony).
export function faceSetupCodePage(input: { csrf: string; error?: string; notice?: string; clientId?: string; emailHint?: string }): RenderedFaceSetupPage {
	const destination = input.emailHint
		? `<br><strong class="email-hint">${escapeHtml(input.emailHint)}</strong>` : " your email.";
	return page({ title: "Check your inbox", clientId: input.clientId, eyebrow: "STEP 2 OF 2", script: otpSubmitScript("Verifying"), body: `${alert(input.error)}${alert(input.notice, "notice")}
<p>Continue setting up Face Login.</p>
<p>Enter the 6-digit code we sent to${destination}</p>
<form id="otp-form" method="POST" action="/face-setup/email/code" aria-busy="false">${csrfField(input.csrf)}
<label class="visually-hidden" for="code">Six-digit verification code</label>
<input class="otp-code" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,9}" maxlength="9" aria-label="Six-digit verification code" required autofocus>
<button id="otp-submit" type="submit">Verify &amp; Continue</button>
</form>
<p>Didn't get it?</p>
<form id="resend-form" method="POST" action="/face-setup/email/resend" aria-busy="false">${csrfField(input.csrf)}
<button id="resend-submit" type="submit" class="secondary">Resend code</button>
</form>
<p id="otp-status" role="status" aria-live="polite"></p>` });
}

export function faceSetupConsentPage(input: { csrf: string; clientId?: string }): RenderedFaceSetupPage {
	return page({ title: "Set up Face Login", clientId: input.clientId, body: `<p>${escapeHtml(FACE_AUTH_CONSENT_TEXT)}</p>
<form method="POST" action="/face-setup/consent">${csrfField(input.csrf)}
<input type="hidden" name="decision" value="agree">
<button type="submit">Agree &amp; Continue</button>
</form>
<form method="POST" action="/face-setup/consent">${csrfField(input.csrf)}
<input type="hidden" name="decision" value="not_now">
<button type="submit" class="secondary">Not Now</button>
</form>
<p id="setup-progress" role="status" hidden>Setting up Face Login...</p>`, script: `
let submitting = false;
for (const form of document.querySelectorAll("form")) {
  form.addEventListener("submit", event => {
    if (submitting) { event.preventDefault(); return; }
    submitting = true;
    for (const button of document.querySelectorAll("button")) button.disabled = true;
    document.getElementById("setup-progress").hidden = false;
  });
}
` });
}
