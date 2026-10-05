import { createHash } from "node:crypto";

export const faceEnrollmentContinuationScript = String.raw`
(() => {
  const message = document.getElementById("enrollment-status");
  let context;
  try { context = JSON.parse(sessionStorage.getItem("hapi.faceEnrollment") || "null"); } catch {}
  const expiresAt = Date.parse(context?.expiresAt || "");
  if (!context || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(context.enrollmentId || "") ||
      !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    message.textContent = "Unable to resume enrollment. Return to your HAPI application.";
    return;
  }
  const deadline = Math.min(expiresAt, Date.now() + 120000);
  const caller = window.opener;
  if (!caller) {
    message.textContent = "Return to your signed-in HAPI application to check enrollment status.";
    return;
  }
  const requestId = crypto.randomUUID();
  let accessToken;
  let attempts = 0;
  let stopped = false;
  let pollTimer;
  const stop = (text, terminal = false) => {
    stopped = true;
    accessToken = undefined;
    clearTimeout(pollTimer);
    window.removeEventListener("message", receiveAuthority);
    message.textContent = text;
    if (terminal) sessionStorage.removeItem("hapi.faceEnrollment");
  };
  const poll = async () => {
    if (stopped) return;
    if (Date.now() >= deadline || attempts >= 60) {
      stop("Enrollment status check expired. Return to your HAPI application.");
      return;
    }
    attempts += 1;
    try {
      const response = await fetch("/v1/authenticators/privateid/enroll/" + context.enrollmentId + "/status", {
        headers: { authorization: "Bearer " + accessToken }, cache: "no-store",
        redirect: "error", signal: AbortSignal.timeout(10000)
      });
      if (stopped) return;
      const result = await response.json();
      if (response.status === 410 && result.status === "EXPIRED") {
        stop("Enrollment expired. Return to your HAPI application.", true);
        return;
      }
      if (!response.ok || !["PENDING", "COMPLETED", "FAILED", "CONFLICT"].includes(result.status)) {
        stop("Unable to read enrollment status. Return to your signed-in HAPI application.");
        return;
      }
      if (result.status !== "PENDING") {
        stop(result.status === "COMPLETED" ? "Face enrollment completed. Return to your HAPI application." :
          "Enrollment could not be completed. Return to your HAPI application.", true);
        return;
      }
      message.textContent = "Waiting for the identity provider.";
      pollTimer = setTimeout(poll, 2000);
    } catch { stop("Unable to read enrollment status. Return to your HAPI application."); }
  };
  const receiveAuthority = event => {
    if (stopped || event.origin !== location.origin || event.source !== caller ||
        event.data?.type !== "hapi.faceEnrollment.authority" || event.data.requestId !== requestId ||
        event.data.enrollmentId !== context.enrollmentId || typeof event.data.accessToken !== "string" ||
        !event.data.accessToken || event.data.accessToken.length > 8192) return;
    clearTimeout(pollTimer);
    window.removeEventListener("message", receiveAuthority);
    accessToken = event.data.accessToken;
    void poll();
  };
  window.addEventListener("message", receiveAuthority);
  message.textContent = "Checking your HAPI enrollment.";
  pollTimer = setTimeout(() => stop("Return to your signed-in HAPI application to check enrollment status."), 10000);
  caller.postMessage({ type: "hapi.faceEnrollment.authority-request", requestId,
    enrollmentId: context.enrollmentId }, location.origin);
})();`;

export function faceEnrollmentContinuation(): { html: string; contentSecurityPolicy: string } {
	const scriptHash = createHash("sha256").update(faceEnrollmentContinuationScript).digest("base64");
	return {
		contentSecurityPolicy: `default-src 'none'; script-src 'sha256-${scriptHash}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
		html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HAPI Face Enrollment</title><style>body{margin:0;background:#f3f6f4;color:#172c23;font:18px Georgia,serif}main{max-width:640px;margin:64px auto;padding:24px}h1{font-size:28px;font-weight:400}p{line-height:1.6}</style></head><body><main><h1>Face enrollment</h1><p id="enrollment-status">Unable to resume enrollment. Return to your HAPI application.</p><noscript>Return to your signed-in HAPI application.</noscript></main><script>${faceEnrollmentContinuationScript}</script></body></html>`
	};
}