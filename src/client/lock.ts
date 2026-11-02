import { failureOf, getPasskey, passkeysSupported } from "./webauthn.js";

export interface LockOptions {
  sessions: () => { name: string; state: string }[];
  beforeLock: () => void;
  afterUnlock: () => void;
  signOut: () => Promise<string | undefined>;
  leave: (url: string) => void;
  scope: () => string;
}

const LOCKED = "sp.locked";
const AUTO = "sp.autoLock";
const IDLE_CHOICES = [1, 5, 15, 30, 60];

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const read = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k: string, v: string | null) => { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch {} };

export function initLock(o: LockOptions) {
  const ws = $("ws");
  const screen = $("lock");
  const codeEl = $<HTMLInputElement>("lock-code");
  const errEl = $("lock-error");
  const pkBtn = $<HTMLButtonElement>("lock-pk");
  const pkLabel = $("lock-pk-label");
  const form = $<HTMLFormElement>("lock-form");
  const autoToggle = $("al-toggle");
  const autoRow = $("al-row");
  const autoMins = $<HTMLSelectElement>("al-mins");
  let locked = false;
  let busy = false;
  let idleTimer = 0;

  const fail = (message: string) => {
    errEl.textContent = message;
    errEl.hidden = false;
  };

  const autoMinutes = () => {
    const n = Number(read(AUTO));
    return IDLE_CHOICES.includes(n) ? n : 0;
  };

  const armIdle = () => {
    clearTimeout(idleTimer);
    const m = autoMinutes();
    if (m && !locked) idleTimer = window.setTimeout(() => void lock(), m * 60_000);
  };

  const renderSessions = () => {
    const ps = o.sessions();
    $("lock-sub").innerHTML = ps.length
      ? `<b>${ps.length}</b> ${ps.length === 1 ? "session is" : "sessions are"} still connected. Terminals are hidden and input is blocked until you unlock.`
      : "No sessions are open. Unlock to continue.";
    $("lock-list").innerHTML = ps
      .map((p) => `<li><span class="dot ${p.state === "connected" ? "" : p.state}"></span><span class="n">${esc(p.name)}</span><span class="s">${esc(p.state)}</span></li>`)
      .join("");
    $("lock-sess").hidden = !ps.length;
  };

  const hasPasskeys = async () => {
    if (!passkeysSupported()) return false;
    try {
      const r = await fetch("/api/passkeys", { credentials: "same-origin" });
      return r.ok && (await r.json()).length > 0;
    } catch {
      return false;
    }
  };

  async function lock() {
    if (locked) return;
    locked = true;
    clearTimeout(idleTimer);
    write(LOCKED, o.scope());
    o.beforeLock();
    document.querySelectorAll<HTMLElement>(".scrim").forEach((s) => { s.hidden = true; });
    ws.inert = true;
    renderSessions();
    errEl.hidden = true;
    codeEl.value = "";
    pkBtn.hidden = true;
    $("lock-or").hidden = true;
    screen.hidden = false;
    codeEl.focus();
    if (await hasPasskeys()) {
      pkBtn.hidden = false;
      $("lock-or").hidden = false;
    }
  }

  function unlock() {
    locked = false;
    write(LOCKED, null);
    screen.hidden = true;
    ws.inert = false;
    armIdle();
    o.afterUnlock();
  }

  const refused = (status: number, body: { error?: string; remaining?: number }, passkey: boolean) => {
    if (status === 401) {
      o.leave(body.error === "too_many_attempts" ? "/?error=totp" : "/");
      return;
    }
    if (status === 429) return fail("Too many attempts. Wait a few minutes.");
    const left = body.remaining ? ` (${body.remaining} ${body.remaining === 1 ? "attempt" : "attempts"} left before you are signed out)` : "";
    fail(passkey ? `That passkey didn't work${left}. Try again or use your authenticator code.` : `That code didn't work${left}. Codes change every 30 seconds.`);
  };

  async function unlockWithCode() {
    if (busy) return;
    busy = true;
    errEl.hidden = true;
    try {
      const r = await fetch("/api/lock/totp", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: codeEl.value }),
      });
      if (r.status === 204) return unlock();
      refused(r.status, await r.json().catch(() => ({})), false);
      codeEl.select();
    } catch {
      fail("Could not reach the server. Try again.");
    } finally {
      busy = false;
    }
  }

  async function unlockWithPasskey() {
    if (busy) return;
    busy = true;
    errEl.hidden = true;
    pkBtn.disabled = true;
    pkLabel.textContent = "Waiting for your passkey…";
    try {
      const json = { "Content-Type": "application/json" };
      const opt = await fetch("/api/lock/passkey/options", { method: "POST", credentials: "same-origin" });
      if (opt.status === 401) return o.leave("/");
      if (opt.status === 429) return fail("Too many attempts. Wait a few minutes.");
      if (!opt.ok) return fail("Could not start the passkey prompt. Use your authenticator code.");
      const options = await opt.json();
      let response;
      try {
        response = await getPasskey(options);
      } catch (e) {
        const why = failureOf(e);
        return fail(why === "cancelled" ? "The passkey prompt was cancelled. Try again or use your authenticator code." : why === "unsupported" ? "This browser can't use passkeys on this address. Use your authenticator code." : "That passkey didn't work. Try again or use your authenticator code.");
      }
      const v = await fetch("/api/lock/passkey/verify", { method: "POST", credentials: "same-origin", headers: json, body: JSON.stringify({ response }) });
      if (v.status === 204) return unlock();
      refused(v.status, await v.json().catch(() => ({})), true);
    } catch {
      fail("Could not reach the server. Try again.");
    } finally {
      busy = false;
      pkBtn.disabled = false;
      pkLabel.textContent = "Unlock with a passkey";
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void unlockWithCode();
  });
  codeEl.addEventListener("input", () => {
    if (codeEl.value.replace(/\D/g, "").length === 6 && !busy) form.requestSubmit();
  });
  pkBtn.addEventListener("click", () => void unlockWithPasskey());
  $("lock-signout").addEventListener("click", async (e) => {
    e.preventDefault();
    const err = await o.signOut();
    if (err) fail(err);
  });
  screen.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      const items = [...screen.querySelectorAll<HTMLElement>("button:not([hidden]):not(:disabled), input, a[href]")].filter((x) => !x.closest("[hidden]"));
      if (!items.length) return;
      const i = items.indexOf(document.activeElement as HTMLElement);
      const next = e.shiftKey ? (i <= 0 ? items.length - 1 : i - 1) : (i === items.length - 1 ? 0 : i + 1);
      e.preventDefault();
      items[next].focus();
    }
  });

  const renderAuto = () => {
    const m = autoMinutes();
    autoToggle.setAttribute("aria-checked", String(m > 0));
    autoRow.hidden = m === 0;
    if (m) autoMins.value = String(m);
  };
  autoToggle.addEventListener("click", () => {
    write(AUTO, autoMinutes() ? null : String(Number(autoMins.value) || 5));
    renderAuto();
    armIdle();
  });
  autoMins.addEventListener("change", () => {
    write(AUTO, autoMins.value);
    armIdle();
  });
  for (const ev of ["keydown", "pointerdown", "pointermove", "wheel"]) document.addEventListener(ev, armIdle, { passive: true, capture: true });
  $("lock-btn").addEventListener("click", () => void lock());
  $("lock-now").addEventListener("click", () => void lock());
  renderAuto();

  return {
    lock: () => void lock(),
    isLocked: () => locked,
    resume() {
      if (read(LOCKED) === o.scope()) void lock();
      else armIdle();
    },
  };
}

