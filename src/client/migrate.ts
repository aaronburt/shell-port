import "./migrate.css";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const err = $("error");
const code = $<HTMLInputElement>("code");
const pass = $<HTMLInputElement>("pass");
const pass2 = $<HTMLInputElement>("pass2");
const go = $<HTMLButtonElement>("go");
const skip = $<HTMLButtonElement>("skip");
const show = (m: string) => { err.textContent = m; err.hidden = false; };
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const lock = (on: boolean) => { for (const el of [code, pass, pass2, go, skip]) el.disabled = on; };

fetch("/api/migrate/status").then((r) => r.json()).then((s) => {
  $("cfg-path").textContent = s.configPath;
  if (!s.writable) {
    const dir = String(s.vaultPath).replace(/\/[^/]*$/, "") || "/";
    show(s.reason === "missing"
      ? `The passphrase boxes are locked because ${dir} does not exist in the container, so there is nowhere to save the vault. Add "SHELLPORT_VAULT: /vault/vault.sealed" under environment and "- ./vault:/vault" under volumes in docker-compose.yml, run mkdir vault, then docker compose up -d.`
      : `The passphrase boxes are locked because ${dir} is not writable by the Shellport user, so the vault cannot be saved there. Make the mounted vault folder writable (on Linux, chown it to user 1000), then restart.`);
    for (const el of [pass, pass2, go]) el.disabled = true;
  }
}).catch(() => {});

async function untilRunning() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch("/healthz", { cache: "no-store" });
      if (r.ok && !(await r.json()).migrate) break;
    } catch {}
    await wait(400);
  }
  location.replace("/");
}

async function send(path: string, payload: Record<string, string>, label: HTMLButtonElement, busy: string) {
  err.hidden = true;
  lock(true);
  const idle = label.textContent;
  label.textContent = busy;
  let done = false;
  try {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: code.value.trim(), ...payload }),
    });
    pass.value = "";
    pass2.value = "";
    if (r.status === 204) {
      done = true;
      label.textContent = "Starting…";
      await untilRunning();
      return;
    }
    const j = await r.json().catch(() => ({}));
    if (j.error === "bad_token") show("That migration code is not right. Copy it from the server log.");
    else if (j.error === "locked") show(`Too many wrong codes. Try again in ${j.retryAfter} seconds.`);
    else if (j.error === "weak_passphrase" || j.error === "migrate_failed") show(j.message);
    else if (j.error === "https_required") show(location.protocol === "https:"
      ? "You are on HTTPS, but the server does not see the connection as HTTPS. Set server.trustProxy in config.json (or SHELLPORT_TRUST_PROXY=1) so it trusts your reverse proxy's X-Forwarded-Proto header, then restart."
      : "Setting a passphrase needs HTTPS, or opening this page on localhost.");
    else if (j.error === "bad_origin") show("Request blocked. Open this page at the address you normally use for Shellport.");
    else show("Something went wrong. Check the server log.");
  } catch {
    show("Could not reach the server.");
  } finally {
    if (!done) {
      lock(false);
      label.textContent = idle;
    }
  }
}

$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (pass.value !== pass2.value) return show("The two passphrases do not match.");
  send("/api/migrate", { passphrase: pass.value }, go, "Encrypting…");
});

skip.addEventListener("click", () => {
  if (!code.value.trim()) return show("Enter the migration code from the server log first.");
  send("/api/migrate/skip", {}, skip, "Starting…");
});
