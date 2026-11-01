import "./unseal.css";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const err = $("error");
const input = $<HTMLInputElement>("pass");
const button = $<HTMLButtonElement>("go");
const show = (m: string) => { err.textContent = m; err.hidden = false; };
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

const duration = (seconds: number) =>
  seconds >= 90 ? `${Math.round(seconds / 60)} minutes` : `${seconds} ${seconds === 1 ? "second" : "seconds"}`;

const local = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
if (location.protocol !== "https:" && !local) {
  show("This page is not using HTTPS, so unsealing is disabled. Open it over HTTPS.");
  input.disabled = true;
  button.disabled = true;
}

async function untilUnsealed() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch("/healthz", { cache: "no-store" });
      if (r.ok && !(await r.json()).sealed) break;
    } catch {}
    await wait(400);
  }
  location.replace("/");
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  err.hidden = true;
  button.disabled = true;
  input.disabled = true;
  button.textContent = "Unsealing…";
  let done = false;
  try {
    const r = await fetch("/api/unseal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: input.value }),
    });
    input.value = "";
    if (r.status === 204) {
      done = true;
      button.textContent = "Starting…";
      await untilUnsealed();
      return;
    }
    const j = await r.json().catch(() => ({}));
    if (j.error === "invalid_passphrase") {
      show(j.retryAfter
        ? `That passphrase didn't work. Too many attempts, so unsealing is paused for ${duration(j.retryAfter)}.`
        : `That passphrase didn't work (${j.remaining} ${j.remaining === 1 ? "attempt" : "attempts"} left before a pause).`);
    } else if (j.error === "locked") show(`Too many attempts. Unsealing is paused for ${duration(j.retryAfter)}.`);
    else if (j.error === "https_required") show("Unsealing needs HTTPS. Open this page over HTTPS.");
    else if (j.error === "bad_origin") show("Request blocked. Open this page at the address you normally use for Shellport.");
    else if (j.error === "config_invalid") show(`The vault unlocked, but its configuration is not valid: ${j.message}`);
    else show("The vault could not be read. Check the server log.");
  } catch {
    show("Could not reach the server.");
  } finally {
    if (!done) {
      button.disabled = false;
      input.disabled = false;
      button.textContent = "Unseal";
      input.focus();
    }
  }
});
