import { createPasskey, failureOf, passkeysSupported } from "./webauthn.js";

interface Passkey { id: string; name: string; createdAt: number; lastUsedAt: number | null }

export interface PasskeysOptions {
  section: HTMLElement;
  list: HTMLElement;
  addButton: HTMLButtonElement;
  scrim: HTMLElement;
  reopenAccount: () => void;
  closeAccount: () => void;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const KEY = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-3 3 3 3m-6-1 2 2"/></svg>`;
const day = (ms: number) => new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });

function ago(ms: number): string {
  const m = Math.max(1, Math.round((Date.now() - ms) / 60000));
  if (m < 60) return `${m} min ago`;
  if (m < 2880) return `${Math.round(m / 60)} h ago`;
  return `${Math.round(m / 1440)} days ago`;
}

const MESSAGES: Record<string, string> = {
  storage_unavailable: "This server can't save passkeys (its configuration is read-only).",
  duplicate_name: "You already have a passkey with that name.",
  too_many: "You have the maximum number of passkeys. Remove one first.",
  rate_limited: "Too many attempts. Wait a few minutes.",
  verification_failed: "The passkey could not be verified. Try again.",
  invalid: "Give the passkey a name of up to 40 characters.",
  duplicate: "That passkey is already registered.",
};

async function call(path: string, init?: RequestInit): Promise<Response> {
  const r = await fetch(path, { credentials: "same-origin", ...init });
  if (r.status === 401) { location.reload(); throw new Error("signed out"); }
  return r;
}

const reason = async (r: Response) => {
  const j = await r.json().catch(() => ({}));
  return MESSAGES[j.error] ?? j.message ?? `Something went wrong (${r.status}).`;
};

export function initPasskeys(o: PasskeysOptions) {
  let items: Passkey[] = [];
  let enabled = false;

  const renderList = (notice = "") => {
    o.list.innerHTML = items.length
      ? items.map((k) => `<li><span class="pk-ico">${KEY}</span><span class="pk-main"><b>${esc(k.name)}</b><small>Added ${day(k.createdAt)} · ${k.lastUsedAt ? `last used ${ago(k.lastUsedAt)}` : "never used"}</small></span><button type="button" class="btn ghost danger" data-remove="${esc(k.id)}" aria-label="Remove ${esc(k.name)}">Remove</button></li>`).join("")
      : `<li class="none">${notice || "No passkeys yet. Add one to sign in without GitHub."}</li>`;
  };

  const refresh = async () => {
    try {
      const r = await call("/api/passkeys");
      if (r.ok) items = await r.json();
    } catch {}
    renderList();
  };

  const closeScrim = () => { o.scrim.hidden = true; o.scrim.innerHTML = ""; };

  const askName = (name: string, error = "") => {
    o.scrim.innerHTML = `<form class="modal" id="pk-form" role="dialog" aria-modal="true" aria-labelledby="pk-title" novalidate>
      <h3 id="pk-title">Add a passkey</h3>
      <p>It will be tied to your account. You are already signed in, so nobody else can add one to it.</p>
      <div class="field"><label for="pk-name">Name</label><input id="pk-name" value="${esc(name)}" maxlength="40" autocomplete="off" placeholder="MacBook Touch ID"><span class="hint">So you can tell your passkeys apart later. Only you see it.</span></div>
      <p class="form-err" role="alert" ${error ? "" : "hidden"}>${esc(error)}</p>
      <div class="modal-foot"><button type="button" class="btn ghost" id="pk-cancel">Cancel</button><button type="submit" class="btn">Continue</button></div>
    </form>`;
    o.scrim.hidden = false;
    const input = o.scrim.querySelector<HTMLInputElement>("#pk-name")!;
    input.focus();
    input.select();
    o.scrim.querySelector("#pk-cancel")!.addEventListener("click", () => { closeScrim(); o.reopenAccount(); });
    o.scrim.querySelector("#pk-form")!.addEventListener("submit", (e) => { e.preventDefault(); void register(input.value.trim()); });
  };

  const waiting = () => {
    o.scrim.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-labelledby="pk-title">
      <h3 id="pk-title">Add a passkey</h3>
      <div class="pk-wait"><span class="pk-spin"></span><span>Follow your browser's prompt to create the passkey. Your device will ask for a fingerprint, face or PIN.</span></div>
    </div>`;
  };

  const register = async (name: string) => {
    if (!name) return askName(name, "Give the passkey a name.");
    waiting();
    try {
      const opt = await call("/api/passkeys/register/options", { method: "POST" });
      if (!opt.ok) return askName(name, await reason(opt));
      let response;
      try {
        response = await createPasskey(await opt.json());
      } catch (e) {
        const why = failureOf(e);
        return askName(name, why === "cancelled" ? "The prompt was cancelled or timed out. Try again." : why === "unsupported" ? "This browser can't create passkeys on this address." : "The passkey could not be created. Try again.");
      }
      const v = await call("/api/passkeys/register/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, response }) });
      if (!v.ok) return askName(name, await reason(v));
      await refresh();
      closeScrim();
      o.reopenAccount();
    } catch {
      askName(name, "Could not reach the server. Try again.");
    }
  };

  const askRemove = (id: string) => {
    const k = items.find((x) => x.id === id);
    if (!k) return;
    o.scrim.innerHTML = `<div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="rp-title" aria-describedby="rp-text">
      <h3 id="rp-title">Remove ${esc(k.name)}?</h3>
      <p id="rp-text">It can no longer sign in to Shellport.${items.length === 1 ? " This is your only passkey, so you will sign in with GitHub and your authenticator code again." : ""} Also delete it from your device's passkey list if you want it gone there.</p>
      <p class="form-err" id="rp-err" role="alert" hidden></p>
      <div class="modal-foot"><button type="button" class="btn ghost" id="rp-cancel">Cancel</button><button type="button" class="btn danger" id="rp-confirm">Remove passkey</button></div>
    </div>`;
    o.scrim.hidden = false;
    o.scrim.querySelector<HTMLElement>("#rp-cancel")!.focus();
    o.scrim.querySelector("#rp-cancel")!.addEventListener("click", () => { closeScrim(); o.reopenAccount(); });
    o.scrim.querySelector("#rp-confirm")!.addEventListener("click", async () => {
      const err = o.scrim.querySelector<HTMLElement>("#rp-err")!;
      const r = await call(`/api/passkeys/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => undefined);
      if (r && (r.ok || r.status === 404)) { await refresh(); closeScrim(); o.reopenAccount(); return; }
      err.textContent = r ? await reason(r) : "Could not reach the server.";
      err.hidden = false;
    });
  };

  o.list.addEventListener("click", (e) => {
    const id = (e.target as HTMLElement).closest<HTMLElement>("[data-remove]")?.dataset.remove;
    if (!id) return;
    o.closeAccount();
    askRemove(id);
  });
  o.addButton.addEventListener("click", () => {
    o.closeAccount();
    askName(`Passkey ${items.length + 1}`);
  });
  o.scrim.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !o.scrim.hidden) { closeScrim(); o.reopenAccount(); }
  });

  return {
    enable(on: boolean) {
      enabled = on && passkeysSupported();
      o.section.hidden = !enabled;
      if (enabled) void refresh();
    },
    get enabled() { return enabled; },
  };
}
