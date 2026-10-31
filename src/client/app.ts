import "./app.css";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { feedPassphrase } from "./passphrase.js";
import { FilesPane } from "./files.js";

interface Host { id: string; name: string; group: string; tag: string; addr: string }
interface Me { login: string; name: string; avatarUrl?: string; expiresAt: number }
interface Signin {
  id: string; kind: "signin" | "totp_failed" | "passphrase_failed"; ip: string; at: number;
  session?: string; current?: boolean; active?: boolean; expiresAt?: number;
}
type State = "connecting" | "connected" | "closed";
interface Info { id?: string; files?: boolean; host: string; user: string; auth: string; cipher: string; hostKey: string; since: string }

interface Tab {
  key: string;
  host: Host;
  title: string;
  term: Terminal;
  fit: FitAddon;
  pane: HTMLDivElement;
  ws?: WebSocket;
  state: State;
  info?: Info;
  reason?: string;
  passphrase?: string;
  mode: "term" | "files";
  files: FilesPane;
}

const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

let hosts: Host[] = [];
let tabs: Tab[] = [];
let active: Tab | undefined;
let seq = 0;
let signins: Signin[] = [];
let othersCount = 0;
let signinsKey = "";
const openActs = new Set<string>();

const THEME = {
  background: "#0b0e13", foreground: "#cfd8e3", cursor: "#f0a640", cursorAccent: "#0b0e13",
  selectionBackground: "#2b3a4d",
  black: "#1b222c", red: "#ff7b7b", green: "#7fd88f", yellow: "#f0a640", blue: "#7cb7ff", magenta: "#d59cf6", cyan: "#6fd3d3", white: "#cfd8e3",
  brightBlack: "#6c7a8c", brightRed: "#ff9a9a", brightGreen: "#9be6a8", brightYellow: "#ffc46b", brightBlue: "#a0cbff", brightMagenta: "#e3b8fa", brightCyan: "#93e2e2", brightWhite: "#ffffff",
};

async function api<T>(path: string): Promise<T> {
  const r = await fetch(path, { credentials: "same-origin" });
  if (r.status === 401) { location.reload(); throw new Error("signed out"); }
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

function renderHosts() {
  const f = $<HTMLInputElement>("host-search").value.trim().toLowerCase();
  const groups = new Map<string, Host[]>();
  for (const h of hosts) {
    if (f && !(h.name + " " + h.addr + " " + h.tag).toLowerCase().includes(f)) continue;
    groups.set(h.group, [...(groups.get(h.group) ?? []), h]);
  }
  const live = new Set(tabs.filter((t) => t.state !== "closed").map((t) => t.host.id));
  $("hosts").innerHTML = groups.size
    ? [...groups].map(([g, items]) => `<div class="group"><h4><span>${esc(g)}</span><span>${items.length}</span></h4>${items.map((h) => `
        <div class="host-row">
          <button class="host ${active?.host.id === h.id ? "active" : ""}" data-host="${esc(h.id)}">
            <span class="dot ${live.has(h.id) ? "live" : ""}"></span>
            <span style="min-width:0"><span class="name">${esc(h.name)}</span><span class="addr">${esc(h.addr)}</span></span>
            ${h.tag ? `<span class="tag">${esc(h.tag)}</span>` : "<span></span>"}
          </button>
          <button class="host-new" data-new="${esc(h.id)}" title="Open another session" aria-label="Open another session to ${esc(h.name)}">+</button>
        </div>`).join("")}</div>`).join("")
    : `<div class="none">${hosts.length ? "No hosts match." : "No hosts are configured for your account."}</div>`;
}

$("hosts").addEventListener("click", (e) => {
  const t = e.target as HTMLElement;
  const n = t.closest<HTMLElement>("[data-new]");
  const b = t.closest<HTMLElement>("[data-host]");
  const id = n?.dataset.new ?? b?.dataset.host;
  const h = hosts.find((x) => x.id === id);
  if (!h) return;
  $("ws").classList.remove("rail-open");
  const existing = !n && tabs.find((x) => x.host.id === h.id);
  existing ? activate(existing) : openTab(h);
});

$<HTMLInputElement>("host-search").addEventListener("input", renderHosts);
$<HTMLInputElement>("host-search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const first = $("hosts").querySelector<HTMLElement>("[data-host]");
    first?.click();
  } else if (e.key === "Escape") {
    (e.target as HTMLInputElement).value = "";
    renderHosts();
    active?.term.focus();
  }
});

function toggleRail() {
  const ws = $("ws");
  if (matchMedia("(max-width: 760px)").matches) { ws.classList.toggle("rail-open"); return; }
  const collapsed = ws.classList.toggle("collapsed");
  $("rail-toggle").setAttribute("aria-expanded", String(!collapsed));
  try { localStorage.setItem("sp.rail", collapsed ? "0" : "1"); } catch {}
  setTimeout(() => active?.fit.fit(), 200);
}
$("rail-toggle").onclick = () => { toggleRail(); active?.term.focus(); };
function showRail() {
  const ws = $("ws");
  if (matchMedia("(max-width: 760px)").matches) ws.classList.add("rail-open");
  else if (ws.classList.contains("collapsed")) toggleRail();
}

function setDrawer(open: boolean, remember = true) {
  $("drawer").classList.toggle("closed", !open);
  $("drawer-toggle").setAttribute("aria-pressed", String(open));
  if (remember) { try { localStorage.setItem("sp.drawer", open ? "1" : "0"); } catch {} }
  active?.fit.fit();
}

function toggleDrawer() {
  setDrawer($("drawer").classList.contains("closed"));
}
$("drawer-toggle").onclick = () => { toggleDrawer(); active?.term.focus(); };

function renderTabs() {
  const el = $("tab-scroll");
  el.innerHTML = tabs.map((t) => `
    <button role="tab" aria-selected="${t === active}" class="tab ${t === active ? "active" : ""}" draggable="true" data-tab="${t.key}" data-state="${t.state}" title="${esc(t.host.addr)}">
      <span class="dot ${t.state === "connected" ? "" : t.state}"></span><span class="name">${esc(t.title)}</span>${canBrowse(t) ? `<span class="tab-files ${t.mode === "files" ? "on" : ""}" role="button" tabindex="0" data-files="${t.key}" aria-label="Files on ${esc(t.host.name)}" aria-pressed="${t.mode === "files"}" title="Files"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg></span>` : ""}
    </button>`).join("");
  el.querySelector(".tab.active")?.scrollIntoView({ inline: "nearest", block: "nearest" });
  $("empty").hidden = tabs.length > 0;
}

const tabOf = (e: Event) => (e.target as HTMLElement).closest<HTMLElement>("[data-tab]");
let dragKey: string | undefined;

const canBrowse = (t: Tab) => t.state === "connected" && !!t.info?.id && t.info.files !== false;

function setMode(tab: Tab, mode: Tab["mode"]) {
  tab.mode = mode;
  if (tab !== active) return activate(tab);
  applyMode();
  renderTabs();
}

function applyMode() {
  for (const t of tabs) {
    const showing = t === active;
    const files = showing && t.mode === "files";
    t.pane.hidden = !showing || files;
    if (files) t.files.show(); else t.files.hide();
  }
  const t = active;
  if (!t) return;
  requestAnimationFrame(() => { if (t.mode === "files") return; t.fit.fit(); t.term.focus(); });
}

function onTabActivate(e: Event) {
  const files = (e.target as HTMLElement).closest<HTMLElement>("[data-files]");
  const tab = tabs.find((x) => x.key === (files?.dataset.files ?? tabOf(e)?.dataset.tab));
  if (!tab) return;
  if (files) {
    e.stopPropagation();
    e.preventDefault();
    setMode(tab, tab.mode === "files" ? "term" : "files");
  } else activate(tab);
}
$("tab-scroll").addEventListener("click", onTabActivate);
$("tab-scroll").addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && (e.target as HTMLElement).closest("[data-files]")) onTabActivate(e);
});
$("tab-scroll").addEventListener("dragstart", (e) => {
  const el = tabOf(e);
  if (!el || !e.dataTransfer) return;
  dragKey = el.dataset.tab;
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", dragKey ?? "");
  el.classList.add("dragging");
});
$("tab-scroll").addEventListener("dragover", (e) => {
  if (!dragKey || !tabOf(e)) return;
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
});
$("tab-scroll").addEventListener("drop", (e) => {
  const target = tabOf(e);
  const from = tabs.findIndex((x) => x.key === dragKey);
  dragKey = undefined;
  if (!target || from < 0) return;
  e.preventDefault();
  const targetKey = target.dataset.tab;
  if (targetKey === tabs[from].key) return;
  const [moved] = tabs.splice(from, 1);
  const to = tabs.findIndex((x) => x.key === targetKey);
  const r = target.getBoundingClientRect();
  tabs.splice(e.clientX > r.left + r.width / 2 ? to + 1 : to, 0, moved);
  renderTabs();
});
$("tab-scroll").addEventListener("dragend", () => {
  dragKey = undefined;
  $("tab-scroll").querySelector(".dragging")?.classList.remove("dragging");
});
$("tab-scroll").addEventListener("auxclick", (e) => {
  if (e.button !== 1) return;
  const tab = tabs.find((x) => x.key === (e.target as HTMLElement).closest<HTMLElement>("[data-tab]")?.dataset.tab);
  if (tab) closeTab(tab);
});

function titleFor(h: Host) {
  const n = tabs.filter((t) => t.host.id === h.id).length;
  return n ? `${h.name} (${n + 1})` : h.name;
}

function openTab(h: Host) {
  const pane = document.createElement("div");
  pane.className = "pane";
  pane.innerHTML = `<div class="xt"></div>`;
  $("terms").appendChild(pane);

  const term = new Terminal({
    fontFamily: '"JetBrains Mono", ui-monospace, Menlo, Consolas, monospace',
    fontSize: 13.5,
    lineHeight: 1.2,
    cursorBlink: true,
    scrollback: 5000,
    theme: THEME,
    macOptionIsMeta: true,
    rightClickSelectsWord: true,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon((_e, uri) => window.open(uri, "_blank", "noopener,noreferrer")));
  term.open(pane.querySelector(".xt")!);

  const tab: Tab = {
    key: String(++seq), host: h, title: titleFor(h), term, fit, pane, state: "connecting", mode: "term",
    files: new FilesPane({
      terminalId: () => (tab.state === "connected" ? tab.info?.id : undefined),
      where: () => `${tab.info?.user ?? tab.host.addr.split("@")[0]}@${tab.host.addr.split("@").slice(1).join("@")}`,
    }),
  };
  $("terms").appendChild(tab.files.el);
  tabs.push(tab);

  term.attachCustomKeyEventHandler((e) => handleTermKey(e, tab));
  term.onData((d) => (tab.passphrase !== undefined ? typePassphrase(tab, d) : send(tab, new TextEncoder().encode(d))));
  term.onBinary((d) => send(tab, Uint8Array.from(d, (c) => c.charCodeAt(0))));
  term.onResize(({ cols, rows }) => {
    if (tab.ws?.readyState === WebSocket.OPEN) tab.ws.send(JSON.stringify({ t: "resize", cols, rows }));
  });
  new ResizeObserver(() => { if (tab === active) fit.fit(); }).observe(pane);

  activate(tab);
  connect(tab);
}

function send(tab: Tab, data: Uint8Array<ArrayBuffer>) {
  if (tab.ws?.readyState === WebSocket.OPEN && tab.state === "connected") tab.ws.send(data);
}

function promptPassphrase(tab: Tab, retry: boolean, remaining: number) {
  tab.passphrase = "";
  const note = retry ? `\r\n\x1b[31mIncorrect passphrase.\x1b[0m ${remaining} ${remaining === 1 ? "try" : "tries"} left.\r\n` : "";
  tab.term.write(`${note}\x1b[33mPassphrase for ${tab.host.addr}:\x1b[0m `);
  tab.term.focus();
}

function typePassphrase(tab: Tab, data: string) {
  if (tab.passphrase === undefined) return;
  const { value, action } = feedPassphrase(tab.passphrase, data);
  if (action === "submit") {
    tab.passphrase = undefined;
    tab.term.write("\r\n");
    if (tab.ws?.readyState === WebSocket.OPEN) tab.ws.send(JSON.stringify({ t: "passphrase", value }));
  } else if (action === "cancel") {
    tab.passphrase = undefined;
    tab.term.write("\r\n\x1b[90mCancelled.\x1b[0m\r\n");
    tab.ws?.close();
  } else {
    tab.passphrase = value;
  }
}

function connect(tab: Tab) {
  tab.pane.querySelector(".banner")?.remove();
  tab.passphrase = undefined;
  tab.state = "connecting";
  tab.info = undefined;
  tab.files.reset();
  tab.reason = undefined;
  tab.term.write(`\x1b[90mConnecting to ${tab.host.addr}…\x1b[0m\r\n`);
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const q = new URLSearchParams({ host: tab.host.id, cols: String(tab.term.cols), rows: String(tab.term.rows) });
  const ws = new WebSocket(`${proto}://${location.host}/ws?${q}`);
  ws.binaryType = "arraybuffer";
  tab.ws = ws;

  ws.onopen = () => {
    ws.send(JSON.stringify({ t: "resize", cols: tab.term.cols, rows: tab.term.rows }));
  };
  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) { tab.term.write(new Uint8Array(ev.data)); return; }
    const msg = JSON.parse(ev.data);
    if (msg.t === "passphrase") {
      promptPassphrase(tab, !!msg.retry, Number(msg.remaining) || 0);
      if (msg.retry && tab === active) loadSignins(tab.host.id);
      return;
    }
    if (msg.t === "error") { tab.term.write(`\r\n\x1b[31m${msg.message}\x1b[0m\r\n`); return; }
    if (msg.t === "status") {
      tab.state = msg.state;
      if (msg.state !== "connected" && tab.mode === "files") { tab.mode = "term"; applyMode(); }
      if (msg.info) tab.info = msg.info;
      if (msg.reason) tab.reason = msg.reason;
      if (msg.state === "connected") tab.fit.fit();
      refresh(tab);
    }
  };
  ws.onclose = (ev) => {
    if (tab.ws !== ws) return;
    tab.passphrase = undefined;
    if (tab.mode === "files") { tab.mode = "term"; applyMode(); }
    if (tab.state !== "closed") {
      tab.state = "closed";
      tab.reason ||= ev.reason || (ev.code === 1006 ? "Could not reach the Shellport server, or you were signed out" : "Disconnected");
    }
    tab.term.write(`\r\n\x1b[90m[${tab.reason}]\x1b[0m\r\n`);
    showBanner(tab);
    refresh(tab);
    if (ev.code === 1006) fetch("/api/me").then((r) => { if (r.status === 401) location.reload(); }).catch(() => {});
  };
}

function showBanner(tab: Tab) {
  if (tab.pane.querySelector(".banner")) return;
  const b = document.createElement("div");
  b.className = "banner";
  b.innerHTML = `<span>Disconnected</span><button class="btn">Reconnect</button>`;
  b.querySelector("button")!.onclick = () => { connect(tab); tab.term.focus(); };
  tab.pane.appendChild(b);
}

function refresh(tab: Tab) {
  renderTabs();
  renderHosts();
  if (tab === active) renderDrawer();
}

function renderAll() {
  renderTabs();
  renderHosts();
  renderDrawer();
}

function activate(tab: Tab) {
  active = tab;
  renderAll();
  applyMode();
}

function closeTab(tab: Tab) {
  const i = tabs.indexOf(tab);
  tabs.splice(i, 1);
  const ws = tab.ws;
  tab.ws = undefined;
  ws?.close();
  tab.term.dispose();
  tab.files.dispose();
  tab.pane.remove();
  if (active === tab) {
    active = tabs[Math.min(i, tabs.length - 1)];
    if (active) return activate(active);
  }
  renderAll();
}

const fmtTime = (ms: number) =>
  new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

function renderSignins() {
  $("signout-others").hidden = othersCount === 0;
  $("signins").innerHTML = signins.length ? signins.map((a) => {
    const open = openActs.has(a.id);
    const label = a.kind === "signin" ? "signed in" : a.kind === "totp_failed" ? "wrong TOTP code" : "wrong passphrase";
    const who = a.kind === "signin" ? (a.current ? "this browser" : a.active ? "other session" : "ended") : "";
    const rows: [string, string][] = [["When", new Date(a.at).toLocaleString()], ["From", a.ip || "unknown"]];
    if (a.kind === "signin") {
      rows.push(["Session", a.session ?? "—"], ["Status", a.current ? "this browser" : a.active ? "active" : "ended"]);
      if (a.active && a.expiresAt) rows.push(["Expires", new Date(a.expiresAt).toLocaleString()]);
    }
    return `<div class="act ${open ? "open" : ""}">
      <button data-act="${esc(a.id)}" aria-expanded="${open}">
        <span class="l"><span><b class="${a.kind === "signin" ? "" : "bad"}">${label}</b>${who ? ` · ${who}` : ""}</span><small>${esc(a.ip)} · ${fmtTime(a.at)}</small></span>
        <span class="chev" aria-hidden="true">⌄</span>
      </button>
      ${open ? `<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : ""}
    </div>`;
  }).join("") : `<div class="none">No activity yet.</div>`;
}

async function loadSignins(host?: string) {
  try {
    const r = await api<{ items: Signin[]; others: number }>(`/api/signins${host ? `?host=${encodeURIComponent(host)}` : ""}`);
    signins = r.items;
    othersCount = r.others;
    renderSignins();
  } catch {}
}

$("signins").addEventListener("click", (e) => {
  const id = (e.target as HTMLElement).closest<HTMLElement>("[data-act]")?.dataset.act;
  if (!id) return;
  openActs.has(id) ? openActs.delete(id) : openActs.add(id);
  renderSignins();
});

let noticeTimer: number | undefined;
function notify(message: string) {
  const el = $("notice");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = window.setTimeout(() => { el.hidden = true; }, 8000);
}

const failure = (r: Response | undefined) => (r ? `status ${r.status}` : "no response from the server");

$("signout-others").onclick = async () => {
  const r = await fetch("/api/signins/signout-others", { method: "POST", credentials: "same-origin" }).catch(() => undefined);
  if (!r?.ok) notify(`Could not sign out the other sessions (${failure(r)}). They are still signed in.`);
  loadSignins(active?.host.id);
};

function renderDrawer() {
  const t = active;
  $("close-session").hidden = !t;
  const key = `${t?.host.id ?? ""}|${t?.state ?? ""}`;
  if (key !== signinsKey) { signinsKey = key; loadSignins(t?.host.id); }
  const i = t?.info;
  const row = (k: string, v: string) => `<dt>${k}</dt><dd>${esc(v)}</dd>`;
  $("kv").innerHTML = !t ? `<dt>—</dt><dd>No session</dd>` :
    row("Host", i?.host ?? t.host.addr) + row("User", i?.user ?? t.host.addr.split("@")[0]) +
    row("Auth", i?.auth ?? "—") + row("Cipher", i?.cipher || "—") + row("Host key", i?.hostKey ?? "—") +
    row("Since", i ? new Date(i.since).toLocaleTimeString() : "—") + row("State", t.state + (t.reason && t.state === "closed" ? ` (${t.reason})` : ""));
}

const TERM_MOD = isMac ? "⌘" : "Ctrl Shift";
$("keys").innerHTML = [
  [`${TERM_MOD} B`, "Toggle sidebar"],
  [`${TERM_MOD} K`, "Search hosts"],
  [isMac ? "⌘ C / ⌘ V" : "Ctrl Shift C / V", "Copy / paste"],
  ["Alt ← / →", "Previous / next tab"],
].map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
$("rail-toggle").title = `Toggle sidebar (${TERM_MOD} B)`;

function handleTermKey(e: KeyboardEvent, tab: Tab): boolean {
  if (e.type !== "keydown") return true;
  const k = e.key.toLowerCase();
  if (!isMac && e.ctrlKey && e.shiftKey && k === "c") {
    const sel = tab.term.getSelection();
    if (sel) navigator.clipboard?.writeText(sel).catch(() => {});
    e.preventDefault();
    return false;
  }
  if (!isMac && e.ctrlKey && e.shiftKey && k === "v") {
    return false;
  }
  return !runShortcut(e, (isMac && e.metaKey) || (e.ctrlKey && e.shiftKey));
}

function runShortcut(e: KeyboardEvent, primary: boolean): boolean {
  const k = e.key.toLowerCase();
  if (primary && k === "b") toggleRail();
  else if (primary && k === "k") focusSearch();
  else if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) cycle(e.key === "ArrowRight" ? 1 : -1);
  else return false;
  e.preventDefault();
  return true;
}

function focusSearch() {
  showRail();
  $<HTMLInputElement>("host-search").select();
}

function cycle(dir: number) {
  if (!tabs.length || !active) return;
  activate(tabs[(tabs.indexOf(active) + dir + tabs.length) % tabs.length]);
}

document.addEventListener("keydown", (e) => {
  if ((e.target as HTMLElement).closest?.(".xterm")) return;
  runShortcut(e, e.ctrlKey || e.metaKey);
});

window.addEventListener("beforeunload", (e) => {
  if (tabs.some((t) => t.state === "connected")) e.preventDefault();
});

const accountBtn = $("account-btn");
const acct = $<HTMLDialogElement>("acct");
const scrim = $("signout-scrim");
const addrToggle = $("addr-toggle");

function setHideAddr(hide: boolean, remember = true) {
  $("ws").classList.toggle("hide-addr", hide);
  addrToggle.setAttribute("aria-checked", String(hide));
  if (remember) { try { localStorage.setItem("sp.hideAddr", hide ? "1" : "0"); } catch {} }
}

const ZOOM_STEPS = [90, 100, 110, 120, 130, 140, 150];

function setZoom(pct: number, remember = true) {
  const i = ZOOM_STEPS.includes(pct) ? ZOOM_STEPS.indexOf(pct) : ZOOM_STEPS.indexOf(100);
  const value = ZOOM_STEPS[i];
  document.documentElement.style.zoom = value === 100 ? "" : String(value / 100);
  $("zoom-reset").textContent = `${value}%`;
  $<HTMLButtonElement>("zoom-out").disabled = i === 0;
  $<HTMLButtonElement>("zoom-in").disabled = i === ZOOM_STEPS.length - 1;
  if (remember) { try { localStorage.setItem("sp.zoom", String(value)); } catch {} }
  requestAnimationFrame(() => { for (const t of tabs) if (t === active && t.mode !== "files") t.fit.fit(); });
}

function stepZoom(dir: number) {
  const cur = ZOOM_STEPS.indexOf(Number($("zoom-reset").textContent!.replace("%", "")));
  setZoom(ZOOM_STEPS[Math.min(ZOOM_STEPS.length - 1, Math.max(0, cur + dir))]);
}

$("zoom-out").onclick = () => stepZoom(-1);
$("zoom-in").onclick = () => stepZoom(1);
$("zoom-reset").onclick = () => setZoom(100);

addrToggle.onclick = () => setHideAddr(addrToggle.getAttribute("aria-checked") !== "true");

accountBtn.onclick = () => acct.showModal();
$("acct-x").onclick = () => acct.close();
$("acct-close").onclick = () => acct.close();
acct.addEventListener("click", (e) => {
  if (e.target === acct) acct.close();
});

function openSignOutDialog() {
  scrim.hidden = false;
  $("signout-cancel").focus();
}

function closeSignOutDialog() {
  if (scrim.hidden) return;
  scrim.hidden = true;
  accountBtn.focus();
}

$("acct-signout").onclick = () => {
  acct.close();
  openSignOutDialog();
};
$("signout-cancel").onclick = closeSignOutDialog;
scrim.addEventListener("pointerdown", (e) => {
  if (e.target === scrim) closeSignOutDialog();
});
scrim.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    closeSignOutDialog();
  } else if (e.key === "Tab") {
    const buttons = [$("signout-cancel"), $("signout-confirm")];
    const i = buttons.indexOf(document.activeElement as HTMLElement);
    e.preventDefault();
    buttons[(i + (e.shiftKey ? -1 : 1) + buttons.length) % buttons.length].focus();
  }
});

$("signout-confirm").onclick = async () => {
  const confirm = $<HTMLButtonElement>("signout-confirm");
  confirm.disabled = true;
  const r = await fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => undefined);
  confirm.disabled = false;
  if (!r?.ok) {
    closeSignOutDialog();
    notify(`Sign out failed (${failure(r)}). You are still signed in.`);
    return;
  }
  for (const t of tabs) t.ws?.close();
  tabs = [];
  location.replace("/");
};

function initialsOf(name: string, login: string): string {
  const words = (name || login).trim().split(/\s+/).filter(Boolean);
  const first = (w: string) => Array.from(w)[0] ?? "";
  const letters = words.length > 1 ? first(words[0]) + first(words[1]) : Array.from(words[0] ?? "?").slice(0, 2).join("");
  return letters.toUpperCase();
}

function renderMe(me: Me) {
  const avatar = me.avatarUrl && me.avatarUrl.startsWith("https://avatars.githubusercontent.com/") ? me.avatarUrl : "";
  for (const [imgId, initialsId] of [["me-avatar", "me-initials"], ["acct-avatar-img", "acct-initials"]]) {
    const img = $<HTMLImageElement>(imgId);
    const initials = $(initialsId);
    initials.textContent = initialsOf(me.name, me.login);
    img.onerror = () => {
      img.hidden = true;
      initials.hidden = false;
    };
    if (avatar) img.src = avatar;
    img.hidden = !avatar;
    initials.hidden = !!avatar;
  }
  $("me-login").textContent = me.login;
  $("acct-title").textContent = me.login;
  setInterval(() => {
    if (me.expiresAt <= Date.now()) location.reload();
  }, 30_000);
}

$("close-session").onclick = () => {
  if (active) closeTab(active);
};

(async () => {
  try {
    if (localStorage.getItem("sp.rail") === "0" && !matchMedia("(max-width: 760px)").matches) toggleRail();
    if (localStorage.getItem("sp.drawer") === "0") setDrawer(false);
    if (localStorage.getItem("sp.hideAddr") === "1") setHideAddr(true, false);
    setZoom(Number(localStorage.getItem("sp.zoom")) || 100, false);
  } catch {}
  if (matchMedia("(max-width: 900px)").matches) setDrawer(false, false);
  const [me, hs] = await Promise.all([api<Me>("/api/me"), api<Host[]>("/api/hosts")]);
  hosts = hs;
  renderMe(me);
  renderAll();
})();
