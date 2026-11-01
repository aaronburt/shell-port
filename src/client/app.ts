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

interface Pane {
  id: string;
  tab: Tab;
  term: Terminal;
  fit: FitAddon;
  el: HTMLDivElement;
  ro: ResizeObserver;
  opened: boolean;
  ws?: WebSocket;
  state: State;
  info?: Info;
  reason?: string;
  passphrase?: string;
}

type Dir = "row" | "col";
type Node = { pane: Pane } | { id: number; dir: Dir; kids: Node[]; w: number[] };

interface Tab {
  key: string;
  host: Host;
  title: string;
  layout: HTMLDivElement;
  root: Node;
  focus: Pane;
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
let paneSeq = 0;
let nodeSeq = 0;
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

const leaves = (n: Node): Pane[] => ("pane" in n ? [n.pane] : n.kids.flatMap(leaves));
const panesOf = (t: Tab) => leaves(t.root);

function tabState(t: Tab): State {
  const ps = panesOf(t);
  return ps.some((p) => p.state === "connected") ? "connected" : ps.some((p) => p.state === "connecting") ? "connecting" : "closed";
}

function filesPane(t: Tab): Pane | undefined {
  return [t.focus, ...panesOf(t)].find((p) => p.state === "connected" && !!p.info?.id);
}

function splitNode(n: Node, target: Pane, dir: Dir, np: Pane): Node {
  if ("pane" in n) return n.pane === target ? { id: ++nodeSeq, dir, kids: [n, { pane: np }], w: [1, 1] } : n;
  const i = n.kids.findIndex((k) => "pane" in k && k.pane === target);
  if (i >= 0 && n.dir === dir) {
    n.w[i] /= 2;
    n.kids.splice(i + 1, 0, { pane: np });
    n.w.splice(i + 1, 0, n.w[i]);
    return n;
  }
  n.kids = n.kids.map((k) => splitNode(k, target, dir, np));
  return n;
}

function dropPane(n: Node, target: Pane): Node | undefined {
  if ("pane" in n) return n.pane === target ? undefined : n;
  const kids: Node[] = [];
  const w: number[] = [];
  n.kids.forEach((k, i) => {
    const r = dropPane(k, target);
    if (r) { kids.push(r); w.push(n.w[i]); }
  });
  if (kids.length <= 1) return kids[0];
  n.kids = kids;
  n.w = w;
  return n;
}

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
  const live = new Set(tabs.filter((t) => tabState(t) !== "closed").map((t) => t.host.id));
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
    active?.focus.term.focus();
  }
});

function toggleRail() {
  const ws = $("ws");
  if (matchMedia("(max-width: 760px)").matches) { ws.classList.toggle("rail-open"); return; }
  const collapsed = ws.classList.toggle("collapsed");
  $("rail-toggle").setAttribute("aria-expanded", String(!collapsed));
  try { localStorage.setItem("sp.rail", collapsed ? "0" : "1"); } catch {}
  setTimeout(fitActive, 200);
}
$("rail-toggle").onclick = () => { toggleRail(); active?.focus.term.focus(); };
function showRail() {
  const ws = $("ws");
  if (matchMedia("(max-width: 760px)").matches) ws.classList.add("rail-open");
  else if (ws.classList.contains("collapsed")) toggleRail();
}

function setDrawer(open: boolean, remember = true) {
  $("drawer").classList.toggle("closed", !open);
  $("drawer-toggle").setAttribute("aria-pressed", String(open));
  if (remember) { try { localStorage.setItem("sp.drawer", open ? "1" : "0"); } catch {} }
  fitActive();
}

function toggleDrawer() {
  setDrawer($("drawer").classList.contains("closed"));
}
$("split-right").onclick = () => splitPane("row");
$("split-down").onclick = () => splitPane("col");
$("drawer-toggle").onclick = () => { toggleDrawer(); active?.focus.term.focus(); };

function renderTabs() {
  const el = $("tab-scroll");
  el.innerHTML = tabs.map((t) => `
    <button role="tab" aria-selected="${t === active}" class="tab ${t === active ? "active" : ""}" draggable="true" data-tab="${t.key}" data-state="${tabState(t)}" title="${esc(t.host.addr)}">
      <span class="dot ${tabState(t) === "connected" ? "" : tabState(t)}"></span><span class="name">${esc(t.title)}</span>${canBrowse(t) ? `<span class="tab-files ${t.mode === "files" ? "on" : ""}" role="button" tabindex="0" data-files="${t.key}" aria-label="Files on ${esc(t.host.name)}" aria-pressed="${t.mode === "files"}" title="Files"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg></span>` : ""}
    </button>`).join("");
  el.querySelector(".tab.active")?.scrollIntoView({ inline: "nearest", block: "nearest" });
  $("empty").hidden = tabs.length > 0;
}

const tabOf = (e: Event) => (e.target as HTMLElement).closest<HTMLElement>("[data-tab]");
let dragKey: string | undefined;

const canBrowse = (t: Tab) => { const p = filesPane(t); return !!p && p.info?.files !== false; };

function setMode(tab: Tab, mode: Tab["mode"]) {
  tab.mode = mode;
  if (tab !== active) return activate(tab);
  applyMode();
  renderTabs();
}

function fitTab(t: Tab) { for (const p of panesOf(t)) p.fit.fit(); }
function fitActive() { if (active && active.mode !== "files") fitTab(active); }

function applyMode() {
  for (const t of tabs) {
    const showing = t === active;
    const files = showing && t.mode === "files";
    t.layout.hidden = !showing || files;
    for (const p of panesOf(t)) p.el.hidden = t.layout.hidden;
    if (files) t.files.show(); else t.files.hide();
  }
  const t = active;
  const noSplit = !t || t.mode === "files";
  $<HTMLButtonElement>("split-right").disabled = noSplit;
  $<HTMLButtonElement>("split-down").disabled = noSplit;
  if (!t) return;
  requestAnimationFrame(() => { if (t.mode === "files") return; fitTab(t); t.focus.term.focus(); });
}

function leaveFilesIfGone(t: Tab) {
  if (t.mode === "files" && !canBrowse(t)) { t.mode = "term"; if (t === active) applyMode(); }
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
  const layout = document.createElement("div");
  layout.className = "layout";
  $("terms").appendChild(layout);

  const tab = { key: String(++seq), host: h, title: titleFor(h), layout, mode: "term" } as Tab;
  tab.files = new FilesPane({
    terminalId: () => filesPane(tab)?.info?.id,
    where: () => {
      const i = filesPane(tab)?.info;
      return `${i?.user ?? tab.host.addr.split("@")[0]}@${tab.host.addr.split("@").slice(1).join("@")}`;
    },
  });
  const pane = makePane(tab);
  tab.root = { pane };
  tab.focus = pane;
  $("terms").appendChild(tab.files.el);
  tabs.push(tab);

  relayout(tab);
  activate(tab);
  pane.fit.fit();
  connect(pane);
}

function makePane(tab: Tab): Pane {
  const el = document.createElement("div");
  el.className = "pane";
  el.innerHTML = `<div class="xt"></div><button class="pane-x" type="button" aria-label="Close pane" title="Close pane (Alt Shift W)">×</button>`;

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

  const pane: Pane = {
    id: `${tab.key}.${++paneSeq}`, tab, term, fit, el, opened: false, state: "connecting",
    ro: new ResizeObserver(() => { if (pane.tab === active && pane.tab.mode === "term") fit.fit(); }),
  };

  term.attachCustomKeyEventHandler((e) => handleTermKey(e, pane));
  // Native copy (context menu, Ctrl+C with a selection in the helper textarea): always copy what xterm has selected.
  el.addEventListener("copy", (e) => {
    const sel = term.getSelection();
    if (!sel || !e.clipboardData) return;
    e.clipboardData.setData("text/plain", sel);
    e.preventDefault();
  });
  el.addEventListener("focusin", () => {
    if (pane.tab.focus === pane) return;
    pane.tab.focus = pane;
    markFocus(pane.tab);
    if (pane.tab === active) renderDrawer();
  });
  el.querySelector<HTMLElement>(".pane-x")!.onclick = () => closePane(pane);
  term.onData((d) => (pane.passphrase !== undefined ? typePassphrase(pane, d) : send(pane, new TextEncoder().encode(d))));
  term.onBinary((d) => send(pane, Uint8Array.from(d, (c) => c.charCodeAt(0))));
  term.onResize(({ cols, rows }) => {
    if (pane.ws?.readyState === WebSocket.OPEN) pane.ws.send(JSON.stringify({ t: "resize", cols, rows }));
  });
  pane.ro.observe(el);
  return pane;
}

function markFocus(t: Tab) {
  for (const p of panesOf(t)) p.el.classList.toggle("focus", p === t.focus);
}

function buildNode(n: Node): HTMLElement {
  if ("pane" in n) return n.pane.el;
  const box = document.createElement("div");
  box.className = `split ${n.dir}`;
  n.kids.forEach((k, i) => {
    if (i) {
      const g = document.createElement("div");
      g.className = "gutter";
      g.setAttribute("role", "separator");
      g.setAttribute("aria-orientation", n.dir === "row" ? "vertical" : "horizontal");
      g.addEventListener("pointerdown", (e) => dragGutter(e, g, n, i));
      box.appendChild(g);
    }
    const cell = document.createElement("div");
    cell.className = "cell";
    cell.style.flex = `${n.w[i]} 1 0px`;
    cell.appendChild(buildNode(k));
    box.appendChild(cell);
  });
  return box;
}

function relayout(t: Tab) {
  t.layout.replaceChildren(buildNode(t.root));
  const ps = panesOf(t);
  t.layout.classList.toggle("multi", ps.length > 1);
  for (const p of ps) {
    if (!p.opened) { p.term.open(p.el.querySelector<HTMLElement>(".xt")!); p.opened = true; }
    p.el.hidden = t.layout.hidden;
  }
  markFocus(t);
  if (t === active && t.mode === "term") requestAnimationFrame(() => fitTab(t));
}

function dragGutter(e: PointerEvent, g: HTMLElement, node: Extract<Node, { kids: Node[] }>, i: number) {
  e.preventDefault();
  const row = node.dir === "row";
  const cells = [...g.parentElement!.children].filter((c) => c.classList.contains("cell")) as HTMLElement[];
  const a = cells[i - 1].getBoundingClientRect();
  const b = cells[i].getBoundingClientRect();
  const start = row ? a.left : a.top;
  const span = row ? b.right - a.left : b.bottom - a.top;
  const total = node.w[i - 1] + node.w[i];
  g.setPointerCapture(e.pointerId);
  g.classList.add("drag");
  const move = (ev: PointerEvent) => {
    const f = Math.min(0.85, Math.max(0.15, ((row ? ev.clientX : ev.clientY) - start) / span));
    node.w[i - 1] = total * f;
    node.w[i] = total * (1 - f);
    cells[i - 1].style.flex = `${node.w[i - 1]} 1 0px`;
    cells[i].style.flex = `${node.w[i]} 1 0px`;
  };
  const up = () => {
    g.classList.remove("drag");
    g.removeEventListener("pointermove", move);
    g.removeEventListener("pointerup", up);
    g.removeEventListener("pointercancel", up);
  };
  g.addEventListener("pointermove", move);
  g.addEventListener("pointerup", up);
  g.addEventListener("pointercancel", up);
}

function splitPane(dir: Dir) {
  const t = active;
  if (!t || t.mode === "files") return;
  const pane = makePane(t);
  t.root = splitNode(t.root, t.focus, dir, pane);
  t.focus = pane;
  relayout(t);
  renderAll();
  pane.fit.fit();
  connect(pane);
  pane.term.focus();
}

function disposePane(p: Pane) {
  const ws = p.ws;
  p.ws = undefined;
  ws?.close();
  p.ro.disconnect();
  p.term.dispose();
  p.el.remove();
}

function closePane(p: Pane) {
  const t = p.tab;
  const ps = panesOf(t);
  if (ps.length === 1) return closeTab(t);
  const i = ps.indexOf(p);
  t.root = dropPane(t.root, p)!;
  disposePane(p);
  const rest = panesOf(t);
  if (t.focus === p) t.focus = rest[Math.min(i, rest.length - 1)];
  relayout(t);
  leaveFilesIfGone(t);
  renderAll();
  if (t === active && t.mode === "term") t.focus.term.focus();
}

function cyclePane(dir: number) {
  const t = active;
  if (!t || t.mode === "files") return;
  const ps = panesOf(t);
  if (ps.length < 2) return;
  t.focus = ps[(ps.indexOf(t.focus) + dir + ps.length) % ps.length];
  markFocus(t);
  renderDrawer();
  t.focus.term.focus();
}

function send(pane: Pane, data: Uint8Array<ArrayBuffer>) {
  if (pane.ws?.readyState === WebSocket.OPEN && pane.state === "connected") pane.ws.send(data);
}

function promptPassphrase(pane: Pane, retry: boolean, remaining: number) {
  pane.passphrase = "";
  const note = retry ? `\r\n\x1b[31mIncorrect passphrase.\x1b[0m ${remaining} ${remaining === 1 ? "try" : "tries"} left.\r\n` : "";
  pane.term.write(`${note}\x1b[33mPassphrase for ${pane.tab.host.addr}:\x1b[0m `);
  pane.term.focus();
}

function typePassphrase(pane: Pane, data: string) {
  if (pane.passphrase === undefined) return;
  const { value, action } = feedPassphrase(pane.passphrase, data);
  if (action === "submit") {
    pane.passphrase = undefined;
    pane.term.write("\r\n");
    if (pane.ws?.readyState === WebSocket.OPEN) pane.ws.send(JSON.stringify({ t: "passphrase", value }));
  } else if (action === "cancel") {
    pane.passphrase = undefined;
    pane.term.write("\r\n\x1b[90mCancelled.\x1b[0m\r\n");
    pane.ws?.close();
  } else {
    pane.passphrase = value;
  }
}

function connect(pane: Pane) {
  pane.el.querySelector(".banner")?.remove();
  pane.passphrase = undefined;
  pane.state = "connecting";
  pane.info = undefined;
  pane.tab.files.reset();
  pane.reason = undefined;
  pane.term.write(`\x1b[90mConnecting to ${pane.tab.host.addr}…\x1b[0m\r\n`);
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const q = new URLSearchParams({ host: pane.tab.host.id, cols: String(pane.term.cols), rows: String(pane.term.rows) });
  const ws = new WebSocket(`${proto}://${location.host}/ws?${q}`);
  ws.binaryType = "arraybuffer";
  pane.ws = ws;

  ws.onopen = () => {
    ws.send(JSON.stringify({ t: "resize", cols: pane.term.cols, rows: pane.term.rows }));
  };
  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) { pane.term.write(new Uint8Array(ev.data)); return; }
    const msg = JSON.parse(ev.data);
    if (msg.t === "passphrase") {
      promptPassphrase(pane, !!msg.retry, Number(msg.remaining) || 0);
      if (msg.retry && pane.tab === active) loadSignins(pane.tab.host.id);
      return;
    }
    if (msg.t === "error") { pane.term.write(`\r\n\x1b[31m${msg.message}\x1b[0m\r\n`); return; }
    if (msg.t === "status") {
      pane.state = msg.state;
      if (msg.info) pane.info = msg.info;
      if (msg.reason) pane.reason = msg.reason;
      if (msg.state === "connected") pane.fit.fit();
      leaveFilesIfGone(pane.tab);
      refresh(pane);
    }
  };
  ws.onclose = (ev) => {
    if (pane.ws !== ws) return;
    pane.passphrase = undefined;
    if (pane.state !== "closed") {
      pane.state = "closed";
      pane.reason ||= ev.reason || (ev.code === 1006 ? "Could not reach the Shellport server, or you were signed out" : "Disconnected");
    }
    pane.term.write(`\r\n\x1b[90m[${pane.reason}]\x1b[0m\r\n`);
    showBanner(pane);
    leaveFilesIfGone(pane.tab);
    refresh(pane);
    if (ev.code === 1006) fetch("/api/me").then((r) => { if (r.status === 401) location.reload(); }).catch(() => {});
  };
}

function showBanner(pane: Pane) {
  if (pane.el.querySelector(".banner")) return;
  const b = document.createElement("div");
  b.className = "banner";
  b.innerHTML = `<span>Disconnected</span><button class="btn">Reconnect</button>`;
  b.querySelector("button")!.onclick = () => { connect(pane); pane.term.focus(); };
  pane.el.appendChild(b);
}

function refresh(p: Pane) {
  renderTabs();
  renderHosts();
  if (p.tab === active) renderDrawer();
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
  for (const p of panesOf(tab)) disposePane(p);
  tab.files.dispose();
  tab.layout.remove();
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
  const tab = active;
  const t = tab?.focus;
  $("close-session").hidden = !tab;
  const key = `${tab?.host.id ?? ""}|${t?.state ?? ""}`;
  if (key !== signinsKey) { signinsKey = key; loadSignins(tab?.host.id); }
  const i = t?.info;
  const row = (k: string, v: string) => `<dt>${k}</dt><dd>${esc(v)}</dd>`;
  $("kv").innerHTML = !tab || !t ? `<dt>—</dt><dd>No session</dd>` :
    row("Host", i?.host ?? tab.host.addr) + row("User", i?.user ?? tab.host.addr.split("@")[0]) +
    row("Auth", i?.auth ?? "—") + row("Cipher", i?.cipher || "—") + row("Host key", i?.hostKey ?? "—") +
    row("Since", i ? new Date(i.since).toLocaleTimeString() : "—") + row("State", t.state + (t.reason && t.state === "closed" ? ` (${t.reason})` : "")) +
    (panesOf(tab).length > 1 ? row("Panes", String(panesOf(tab).length)) : "");
}

const TERM_MOD = isMac ? "⌘" : "Ctrl Shift";
$("keys").innerHTML = [
  [`${TERM_MOD} B`, "Toggle sidebar"],
  [`${TERM_MOD} K`, "Search hosts"],
  [isMac ? "⌘ C / ⌘ V" : "Ctrl Shift C / V", "Copy / paste"],
  ["Alt ← / →", "Previous / next tab"],
  ["Alt Shift D / S", "Split right / down"],
  ["Alt Shift ← / →", "Previous / next pane"],
  ["Alt Shift W", "Close pane"],
].map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
$("rail-toggle").title = `Toggle sidebar (${TERM_MOD} B)`;

function copyText(text: string) {
  const legacy = () => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    const prev = document.activeElement as HTMLElement | null;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch {}
    ta.remove();
    prev?.focus();
  };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).catch(legacy);
  else legacy();
}

function handleTermKey(e: KeyboardEvent, pane: Pane): boolean {
  if (e.type !== "keydown") return true;
  const k = e.key.toLowerCase();
  if (!isMac && e.ctrlKey && e.shiftKey && k === "c") {
    const sel = pane.term.getSelection();
    if (sel) copyText(sel);
    e.preventDefault();
    e.stopPropagation();
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
  else if (e.altKey && e.shiftKey && e.code === "KeyD") splitPane("row");
  else if (e.altKey && e.shiftKey && e.code === "KeyS") splitPane("col");
  else if (e.altKey && e.shiftKey && e.code === "KeyW") { if (active && active.mode === "term") closePane(active.focus); }
  else if (e.altKey && e.shiftKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) cyclePane(e.key === "ArrowRight" ? 1 : -1);
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
  if (e.defaultPrevented || (e.target as HTMLElement).closest?.(".xterm")) return;
  runShortcut(e, e.ctrlKey || e.metaKey);
});

window.addEventListener("beforeunload", (e) => {
  if (tabs.some((t) => tabState(t) === "connected")) e.preventDefault();
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
  requestAnimationFrame(fitActive);
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
  for (const t of tabs) for (const p of panesOf(t)) p.ws?.close();
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
