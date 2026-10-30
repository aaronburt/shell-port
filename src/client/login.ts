import "./login.css";

const MESSAGES: Record<string, string> = {
  denied: "That GitHub account isn't on this server's allowlist.",
  state: "The sign-in link expired or was opened in another browser. Please try again.",
  failed: "GitHub sign-in failed. Please try again.",
  totp: "Too many wrong codes. Sign in again.",
  rate: "Too many sign-in attempts. Wait a few minutes and try again.",
};
const code = new URLSearchParams(location.search).get("error");
const el = document.getElementById("error")!;
if (code && MESSAGES[code]) {
  el.textContent = MESSAGES[code];
  el.hidden = false;
  history.replaceState(null, "", "/");
}
