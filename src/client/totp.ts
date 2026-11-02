import "./login.css";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const err = $("error");
const show = (m: string) => { err.textContent = m; err.hidden = false; };

fetch("/auth/totp").then(async (r) => {
  if (!r.ok) { location.replace("/"); return; }
  const login = (await r.json()).login;
  $("who").textContent = login;
  $<HTMLInputElement>("user").value = login;
});

const codeEl = $<HTMLInputElement>("code");
let busy = false;
codeEl.addEventListener("input", () => {
  // Auto-submit once 6 digits are in (typed, pasted or autofilled).
  if (codeEl.value.replace(/\D/g, "").length === 6 && !busy) $<HTMLFormElement>("form").requestSubmit();
});

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (busy) return;
  busy = true;
  const btn = $<HTMLButtonElement>("go");
  btn.disabled = true;
  try {
    const r = await fetch("/auth/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: $<HTMLInputElement>("code").value }),
    });
    if (r.status === 204) { location.replace("/"); return; }
    const j = await r.json().catch(() => ({}));
    if (j.error === "too_many_attempts") { location.replace("/?error=totp"); return; }
    if (r.status === 401) { location.replace("/"); return; }
    if (r.status === 429) show("Too many attempts. Wait a few minutes.");
    else show(`That code didn't work${j.remaining ? ` (${j.remaining} attempts left)` : ""}. Codes change every 30 seconds.`);
    $<HTMLInputElement>("code").select();
  } finally { btn.disabled = false; busy = false; }
});

$("cancel").addEventListener("click", async (e) => {
  e.preventDefault();
  await fetch("/auth/logout", { method: "POST" }).catch(() => {});
  location.replace("/");
});
