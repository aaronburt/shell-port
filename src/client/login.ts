import "./login.css";
import { failureOf, getPasskey, passkeysSupported } from "./webauthn.js";

const MESSAGES: Record<string, string> = {
  denied: "That GitHub account isn't on this server's allowlist.",
  state: "The sign-in link expired or was opened in another browser. Please try again.",
  failed: "GitHub sign-in failed. Please try again.",
  totp: "Too many wrong codes. Sign in again.",
  rate: "Too many sign-in attempts. Wait a few minutes and try again.",
  passkey: "No passkey for this server was found on this device, or the prompt was cancelled. Sign in with GitHub, then add a passkey under Account.",
  passkeyfail: "That passkey didn't work. Try again, or sign in with GitHub.",
  passkeyunsupported: "This browser can't use passkeys on this address. Sign in with GitHub.",
};
const code = new URLSearchParams(location.search).get("error");
const el = document.getElementById("error")!;
if (code && MESSAGES[code]) {
  el.textContent = MESSAGES[code];
  el.hidden = false;
  history.replaceState(null, "", "/");
}

const pkBtn = document.getElementById("pk-signin") as HTMLButtonElement;
const pkLabel = document.getElementById("pk-signin-label")!;
if (passkeysSupported()) {
  pkBtn.hidden = false;
  document.getElementById("pk-or")!.hidden = false;
}
const showError = (message: string) => {
  el.textContent = message;
  el.hidden = false;
};
pkBtn.addEventListener("click", async () => {
  if (pkBtn.disabled) return;
  el.hidden = true;
  pkBtn.disabled = true;
  pkLabel.textContent = "Waiting for your passkey…";
  const json = { "Content-Type": "application/json" };
  try {
    const o = await fetch("/auth/passkey/options", { method: "POST", credentials: "same-origin" });
    if (o.status === 429) return showError(MESSAGES.rate);
    if (!o.ok) return showError(MESSAGES.passkeyfail);
    const { challengeId, options } = await o.json();
    let response;
    try {
      response = await getPasskey(options);
    } catch (e) {
      const why = failureOf(e);
      return showError(MESSAGES[why === "cancelled" ? "passkey" : why === "unsupported" ? "passkeyunsupported" : "passkeyfail"]);
    }
    const v = await fetch("/auth/passkey/verify", { method: "POST", credentials: "same-origin", headers: json, body: JSON.stringify({ challengeId, response }) });
    if (v.status === 204) { location.replace("/"); return; }
    showError(v.status === 429 ? MESSAGES.rate : MESSAGES.passkey);
  } catch {
    showError(MESSAGES.passkeyfail);
  } finally {
    pkBtn.disabled = false;
    pkLabel.textContent = "Sign in with a passkey";
  }
});
