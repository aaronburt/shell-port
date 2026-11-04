import "./app.css";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { feedPassphrase } from "./passphrase.js";
import { FilesPane } from "./files.js";
import { initAddHost } from "./addhost.js";
import { initPasskeys } from "./passkeys.js";
import { initLock } from "./lock.js";
import { initAudit } from "./audit.js";
import { initRecordingPage, type RecordingMeta } from "./playback.js";
import { autoPassEnabled, countPassphrases, forgetAllPassphrases, forgetPassphrase, loadPassphrase, passSupported, savePassphrase, setAutoPassEnabled } from "./passstore.js";

interface Host { id: string; name: string; group: string; tag: string; addr: string; via?: string }
interface Me { via?: "github" | "passkey"; canManagePasskeys?: boolean; login: string; name: string; avatarUrl?: string; expiresAt: number; sealable?: boolean; admin?: boolean; canAddHosts?: boolean; version: string; releaseNotesUrl: string }
interface Signin {
  id: string; kind: "signin" | "totp_failed" | "passphrase_failed"; ip: string; at: number;
  method?: "github" | "passkey"; session?: string; current?: boolean; active?: boolean; expiresAt?: number;
}
type State = "connecting" | "connected" | "closed";
interface Info { id?: string; files?: boolean; host: string; user: string; auth: string; route?: string; cipher: string; hostKey: string; since: string; recording?: boolean }

type FailureStage = "connection" | "host-key" | "authentication" | "shell" | "configuration" | "passphrase" | "recording";
interface Diagnostic { stage: FailureStage; role: "bastion" | "target"; message: string }

interface Pane {
  id: string;
  tab: Tab;
  host: Host;
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
  usedSaved?: string;
  asking?: string;
  pendingSave?: Map<string, string>;
  diagnostic?: Diagnostic;
  cancelled?: boolean;
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
  filesFor?: string;
  solo?: boolean;
  stash: HTMLDivElement;
  wantPath?: string;
  arr?: Arrangement;
}

type Zone = "left" | "right" | "top" | "bottom";
const MAX_PANES = 8;
const ZONES: Record<Zone, { dir: Dir; before: boolean; label: string }> = {
  left: { dir: "row", before: true, label: "left of" },
  right: { dir: "row", before: false, label: "right of" },
  top: { dir: "col", before: true, label: "above" },
  bottom: { dir: "col", before: false, label: "below" },
};

const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

let hosts: Host[] = [];
let canEdit = false;
let isAdmin = false;
let tabs: Tab[] = [];
let active: Tab | undefined;
type PageKind = "audit" | "account" | "recording";
interface Page { kind: PageKind; title: string; el: HTMLElement }
const pages: Page[] = [];
let activePage: Page | undefined;
const shown = () => (activePage ? undefined : active);
let seq = 0;
let paneSeq = 0;
let nodeSeq = 0;
let signins: Signin[] = [];
let othersCount = 0;
let signinsKey = "";
const openActs = new Set<string>();

const TERM_THEMES = {
  shellport: {
    background: "#0b0e13", foreground: "#cfd8e3", cursor: "#f0a640", cursorAccent: "#0b0e13",
    selectionBackground: "#2b3a4d",
    black: "#1b222c", red: "#ff7b7b", green: "#7fd88f", yellow: "#f0a640", blue: "#7cb7ff", magenta: "#d59cf6", cyan: "#6fd3d3", white: "#cfd8e3",
    brightBlack: "#6c7a8c", brightRed: "#ff9a9a", brightGreen: "#9be6a8", brightYellow: "#ffc46b", brightBlue: "#a0cbff", brightMagenta: "#e3b8fa", brightCyan: "#93e2e2", brightWhite: "#ffffff",
  },
  solarized: {
    background: "#002b36", foreground: "#93a1a1", cursor: "#93a1a1", cursorAccent: "#002b36",
    selectionBackground: "#073642",
    black: "#073642", red: "#dc322f", green: "#859900", yellow: "#b58900", blue: "#268bd2", magenta: "#d33682", cyan: "#2aa198", white: "#eee8d5",
    brightBlack: "#839496", brightRed: "#cb4b16", brightGreen: "#586e75", brightYellow: "#657b83", brightBlue: "#839496", brightMagenta: "#6c71c4", brightCyan: "#93a1a1", brightWhite: "#fdf6e3",
  },
  paper: {
    background: "#fbfaf6", foreground: "#2b2f36", cursor: "#2563c4", cursorAccent: "#fbfaf6",
    selectionBackground: "#d6e2f5",
    black: "#2b2f36", red: "#c0392b", green: "#237a3b", yellow: "#a86400", blue: "#2563c4", magenta: "#8e44ad", cyan: "#14807a", white: "#8a929e",
    brightBlack: "#7c8593", brightRed: "#d9534f", brightGreen: "#2e8f46", brightYellow: "#b97a00", brightBlue: "#3b7de0", brightMagenta: "#a35fc2", brightCyan: "#1c9a92", brightWhite: "#14171c",
  },
};
type TermTheme = keyof typeof TERM_THEMES;
const TERM_KEYS = Object.keys(TERM_THEMES) as TermTheme[];
const UI_THEMES = ["system", "dark", "light"] as const;
type UiTheme = (typeof UI_THEMES)[number];
let termTheme: TermTheme = "shellport";

function savedChoice<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    return allowed.find((v) => v === localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

const leaves = (n: Node): Pane[] => ("pane" in n ? [n.pane] : n.kids.flatMap(leaves));
const panesOf = (t: Tab) => leaves(t.root);

function tabState(t: Tab): State {
  const ps = panesOf(t);
  return ps.some((p) => p.state === "connected") ? "connected" : ps.some((p) => p.state === "connecting") ? "connecting" : "closed";
}

function tabDot(t: Tab): string {
  const s = tabState(t);
  if (s !== "connected") return s;
  return panesOf(t).some((p) => p.state === "connected" && p.info?.recording) ? "rec" : "";
}

function filesPane(t: Tab): Pane | undefined {
  return [t.focus, ...panesOf(t)].find((p) => p.state === "connected" && !!p.info?.id);
}

function insertAt(n: Node, target: Pane, dir: Dir, np: Pane, before: boolean): Node {
  if ("pane" in n) return n.pane === target ? { id: ++nodeSeq, dir, kids: before ? [{ pane: np }, n] : [n, { pane: np }], w: [1, 1] } : n;
  const i = n.kids.findIndex((k) => "pane" in k && k.pane === target);
  if (i >= 0 && n.dir === dir) {
    const half = n.w[i] / 2;
    const at = before ? i : i + 1;
    n.w[i] = half;
    n.kids.splice(at, 0, { pane: np });
    n.w.splice(at, 0, half);
    return n;
  }
  n.kids = n.kids.map((k) => insertAt(k, target, dir, np, before));
  return n;
}

function swapLeaves(n: Node, a: Pane, b: Pane) {
  if ("pane" in n) {
    if (n.pane === a) n.pane = b;
    else if (n.pane === b) n.pane = a;
    return;
  }
  n.kids.forEach((k) => swapLeaves(k, a, b));
}

function equalize(n: Node) {
  if ("pane" in n) return;
  n.w = n.w.map(() => 1);
  n.kids.forEach(equalize);
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
  const live = new Set(tabs.flatMap(panesOf).filter((p) => p.state !== "closed").map((p) => p.host.id));
  $("hosts").innerHTML = groups.size
    ? [...groups].map(([g, items]) => `<div class="group"><h4><span>${esc(g)}</span><span>${items.length}</span></h4>${items.map((h) => `
        <div class="host-row" draggable="true" data-drag-host="${esc(h.id)}">
          <button class="host ${shown()?.focus.host.id === h.id ? "active" : ""}" data-host="${esc(h.id)}">
            <span class="dot ${live.has(h.id) ? "live" : ""}"></span>
            <span style="min-width:0"><span class="name">${esc(h.name)}</span><span class="addr">${esc(h.addr)}</span></span>
            ${h.tag ? `<span class="tag">${esc(h.tag)}</span>` : "<span></span>"}
          </button>
          <button class="host-new" data-new="${esc(h.id)}" title="Open another session" aria-label="Open another session to ${esc(h.name)}">+</button>
          ${canEdit ? `<button class="host-new host-edit" data-edit="${esc(h.id)}" title="Edit host" aria-label="Edit ${esc(h.name)}"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16v4Z"/></svg></button>` : ""}
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
  const existing = n ? undefined : tabs.flatMap(panesOf).find((p) => p.host.id === h.id);
  existing ? focusPane(existing) : openTab(h);
});

function focusPane(p: Pane) {
  const t = p.tab;
  t.focus = p;
  if (t.solo) relayout(t);
  activate(t);
}

$<HTMLInputElement>("host-search").addEventListener("input", renderHosts);
$<HTMLInputElement>("host-search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const first = $("hosts").querySelector<HTMLElement>("[data-host]");
    first?.click();
  } else if (e.key === "Escape") {
    (e.target as HTMLInputElement).value = "";
    renderHosts();
    shown()?.focus.term.focus();
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
$("rail-toggle").onclick = () => { toggleRail(); shown()?.focus.term.focus(); };
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
$("drawer-toggle").onclick = () => { toggleDrawer(); shown()?.focus.term.focus(); };

const X_ICON = `<svg class="x-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>`;
const FOLDER_ICON = `<svg class="f-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`;
const PAGE_ICONS: Record<PageKind, string> = {
  recording: `<svg class="tab-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="7.5"/><circle cx="12" cy="12" r="2.8" fill="currentColor"/></svg>`,
  audit: `<svg class="tab-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M5 4h14M5 9h14M5 14h14M5 19h9"/></svg>`,
  account: `<svg class="tab-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>`,
};

function renderTabs() {
  const el = $("tab-scroll");
  const front = (t: Tab) => t === active && !activePage;
  const closer = (t: Tab) => canBrowse(t)
    ? `<span class="tab-files ${t.mode === "files" ? "on" : ""}" role="button" tabindex="0" data-files="${t.key}" aria-label="Files on ${esc(t.host.name)}" aria-pressed="${t.mode === "files"}" title="Files (hold Shift to close the tab)">${FOLDER_ICON}${X_ICON}</span>`
    : `<span class="tab-files tab-x" role="button" tabindex="0" data-tabclose="${t.key}" aria-label="Close ${esc(t.title)}" title="Close tab (hold Shift)">${X_ICON}</span>`;
  el.innerHTML = tabs.map((t) => `
    <button role="tab" aria-selected="${front(t)}" class="tab ${front(t) ? "active" : ""}" draggable="true" data-tab="${t.key}" data-state="${tabState(t)}" title="${esc(t.host.addr)}">
      <span class="dot ${tabDot(t)}"${tabDot(t) === "rec" ? ` role="img" aria-label="Recording" title="Recording (terminal output only)"` : ""}></span><span class="name">${esc(t.title)}</span>${panesOf(t).length > 1 ? `<span class="tab-n" title="Sessions in this view">${panesOf(t).length}</span>` : ""}${closer(t)}
    </button>`).join("") + pages.map((p) => `
    <button role="tab" aria-selected="${p === activePage}" class="tab ptab ${p === activePage ? "active" : ""}" data-page="${p.kind}" title="${p.title}">
      ${PAGE_ICONS[p.kind]}<span class="name">${p.title}</span><span class="tab-files tab-x" role="button" tabindex="0" data-pageclose="${p.kind}" aria-label="Close ${p.title}" title="Close tab (hold Shift)">${X_ICON}</span>
    </button>`).join("");
  el.querySelector(".tab.active")?.scrollIntoView({ inline: "nearest", block: "nearest" });
  $("empty").hidden = tabs.length > 0 || !!activePage;
}

const tabOf = (e: Event) => (e.target as HTMLElement).closest<HTMLElement>("[data-tab]");
let dragKey: string | undefined;

const canBrowse = (t: Tab) => { const p = filesPane(t); return !!p && p.info?.files !== false; };

const ARRANGEMENTS: Arrangement[] = ["single", "cols", "rows", "grid", "main"];

function syncUrl() {
  const q = new URLSearchParams();
  for (const t of tabs) {
    const ps = panesOf(t);
    const p = t.mode === "files" ? t.files.cwd : t.wantPath;
    const lead = t.mode === "files" ? filesPane(t) : undefined;
    const ids = ps.map((x) => x.host.id);
    if (lead) ids.splice(ids.indexOf(lead.host.id), 1), ids.unshift(lead.host.id);
    const arr = ps.length > 1 ? (t.solo ? "single" : t.arr) : undefined;
    q.append("open", `${arr ? `${arr}!` : ""}${ids.join(",")}${p ? `:${p}` : ""}`);
  }
  for (const p of pages) if (p.kind !== "recording") q.append("page", p.kind);
  const s = q.toString();
  try { history.replaceState(null, "", location.pathname + (s ? `?${s}` : "")); } catch {}
}

function openFromUrl() {
  const params = new URLSearchParams(location.search);
  const kinds = [...new Set(params.getAll("page"))]
    .filter((k): k is PageKind => k === "account" || (k === "audit" && isAdmin));
  for (const v of params.getAll("open")) {
    const c = v.indexOf(":");
    const head = c < 0 ? v : v.slice(0, c);
    const path = c < 0 ? "" : v.slice(c + 1);
    const b = head.indexOf("!");
    const arr = b < 0 ? "" : head.slice(0, b);
    const list = (b < 0 ? head : head.slice(b + 1)).split(",").map((id) => hosts.find((x) => x.id === id)).filter((h): h is Host => !!h).slice(0, MAX_PANES);
    if (!list.length) continue;
    openTab(list[0]);
    const t = tabs[tabs.length - 1];
    if (path.startsWith("/")) t.wantPath = path;
    for (const h of list.slice(1)) addSession(h);
    if (ARRANGEMENTS.includes(arr as Arrangement) && list.length > 1) arrange(arr as Arrangement);
  }
  kinds.forEach(pageFor);
  const first = tabs[0];
  if (first) activate(first);
  if (kinds[0]) openPage(kinds[0]);
  syncUrl();
}

function setMode(tab: Tab, mode: Tab["mode"]) {
  tab.mode = mode;
  syncUrl();
  if (tab !== active) return activate(tab);
  applyMode();
  renderTabs();
}

function fitTab(t: Tab) { for (const p of panesOf(t)) p.fit.fit(); }
function fitActive() { if (active && !activePage && active.mode !== "files") fitTab(active); }

function applyMode() {
  for (const t of tabs) {
    const showing = t === active && !activePage;
    const files = showing && t.mode === "files";
    t.layout.hidden = !showing || files;
    for (const p of panesOf(t)) p.el.hidden = paneHidden(p);
    if (files) {
      const fid = filesPane(t)?.info?.id;
      if (t.filesFor !== fid) { t.files.reset(); t.filesFor = fid; }
      t.files.show();
    } else t.files.hide();
  }
  for (const pg of pages) {
    pg.el.hidden = pg !== activePage;
    if (pg.el.hidden) pg.el.querySelectorAll<HTMLElement>(".info-tip:popover-open").forEach((tip) => tip.hidePopover());
  }
  const t = shown();
  syncLayoutUi();
  if (!t) return;
  requestAnimationFrame(() => { if (t.mode === "files" || activePage) return; fitTab(t); t.focus.term.focus(); });
}

function leaveFilesIfGone(t: Tab) {
  if (t.mode === "files" && !canBrowse(t)) { t.mode = "term"; if (t === active) applyMode(); }
}

function onTabActivate(e: Event) {
  const hit = (sel: string) => (e.target as HTMLElement).closest<HTMLElement>(sel);
  const pageClose = hit("[data-pageclose]");
  const pageTab = hit("[data-page]");
  if (pageClose || pageTab) {
    const page = pages.find((x) => x.kind === (pageClose?.dataset.pageclose ?? pageTab?.dataset.page));
    if (!page) return;
    e.stopPropagation();
    e.preventDefault();
    return pageClose ? closePage(page) : openPage(page.kind);
  }
  const files = hit("[data-files]");
  const closer = hit("[data-tabclose]");
  const tab = tabs.find((x) => x.key === (files?.dataset.files ?? closer?.dataset.tabclose ?? tabOf(e)?.dataset.tab));
  if (!tab) return;
  if (closer) {
    e.stopPropagation();
    e.preventDefault();
    closeTab(tab);
  } else if (files) {
    e.stopPropagation();
    e.preventDefault();
    if ((e as MouseEvent | KeyboardEvent).shiftKey) closeTab(tab);
    else setMode(tab, tab.mode === "files" ? "term" : "files");
  } else activate(tab);
}
$("tab-scroll").addEventListener("click", onTabActivate);
$("tab-scroll").addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && (e.target as HTMLElement).closest("[data-files],[data-tabclose],[data-pageclose]")) onTabActivate(e);
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
  const page = pages.find((x) => x.kind === (e.target as HTMLElement).closest<HTMLElement>("[data-page]")?.dataset.page);
  if (page) return closePage(page);
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
      const fp = filesPane(tab);
      const host = fp?.host ?? tab.host;
      return `${fp?.info?.user ?? host.addr.split("@")[0]}@${host.addr.split("@").slice(1).join("@")}`;
    },
    onPath: syncUrl,
  });
  tab.stash = document.createElement("div");
  tab.stash.className = "stash";
  tab.stash.hidden = true;
  const pane = makePane(tab, h);
  tab.root = { pane };
  tab.focus = pane;
  $("terms").appendChild(tab.files.el);
  tabs.push(tab);

  relayout(tab);
  activate(tab);
  pane.fit.fit();
  connect(pane);
  syncUrl();
}

const GRIP = `<svg class="grip" viewBox="0 0 10 16" width="8" height="12" fill="currentColor" aria-hidden="true"><circle cx="2" cy="3" r="1.2"/><circle cx="8" cy="3" r="1.2"/><circle cx="2" cy="8" r="1.2"/><circle cx="8" cy="8" r="1.2"/><circle cx="2" cy="13" r="1.2"/><circle cx="8" cy="13" r="1.2"/></svg>`;

function makePane(tab: Tab, host: Host): Pane {
  const el = document.createElement("div");
  el.className = "pane";
  el.innerHTML = `<div class="pane-bar" draggable="true" title="Drag to dock or swap">${GRIP}<span class="dot"></span><span class="pname"></span><span class="paddr"></span><button class="pane-x" type="button" aria-label="Close session" title="Close session (Alt Shift W)">×</button></div><div class="xt"></div>`;

  const term = new Terminal({
    fontFamily: '"JetBrains Mono", ui-monospace, Menlo, Consolas, monospace',
    fontSize: 13.5,
    lineHeight: 1.2,
    cursorBlink: true,
    scrollback: 5000,
    theme: TERM_THEMES[termTheme],
    macOptionIsMeta: true,
    rightClickSelectsWord: true,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon((_e, uri) => window.open(uri, "_blank", "noopener,noreferrer")));

  const pane: Pane = {
    id: `${tab.key}.${++paneSeq}`, tab, host, term, fit, el, opened: false, state: "connecting",
    ro: new ResizeObserver(() => { if (pane.tab === active && !activePage && pane.tab.mode === "term") fit.fit(); }),
  };

  term.attachCustomKeyEventHandler((e) => handleTermKey(e, pane));
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
  paintBar(pane);
  return pane;
}

function paintBar(p: Pane) {
  const bar = p.el.querySelector<HTMLElement>(".pane-bar")!;
  bar.querySelector(".dot")!.className = `dot ${p.state === "connected" ? "" : p.state}`;
  bar.querySelector(".pname")!.textContent = p.host.name;
  bar.querySelector(".paddr")!.textContent = p.host.addr;
}

function stashed(p: Pane) {
  const t = p.tab;
  return !!t.solo && t.focus !== p && panesOf(t).length > 1;
}
const paneHidden = (p: Pane) => p.tab.layout.hidden || stashed(p);

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
      g.addEventListener("dblclick", () => resetSizes());
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
  const ps = panesOf(t);
  const solo = !!t.solo && ps.length > 1;
  t.layout.replaceChildren(buildNode(solo ? { pane: t.focus } : t.root), t.stash);
  t.stash.replaceChildren(...(solo ? ps.filter((p) => p !== t.focus).map((p) => p.el) : []));
  t.layout.classList.toggle("multi", !solo && ps.length > 1);
  for (const p of ps) {
    if (!p.opened) { p.term.open(p.el.querySelector<HTMLElement>(".xt")!); p.opened = true; }
    p.el.hidden = paneHidden(p);
  }
  markFocus(t);
  syncLayoutUi();
  syncUrl();
  if (t === active && !activePage && t.mode === "term") requestAnimationFrame(() => fitTab(t));
}

function resetSizes() {
  const t = active;
  if (!t) return;
  equalize(t.root);
  relayout(t);
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

function addSession(h: Host, target?: Pane, zone?: Zone) {
  const t = active;
  if (!t || t.mode === "files") return;
  if (panesOf(t).length >= MAX_PANES) return notify(`A view holds up to ${MAX_PANES} sessions. Close one to open another.`);
  const anchor = target ?? t.focus;
  zone ??= anchor.el.clientWidth < anchor.el.clientHeight * 1.2 ? "bottom" : "right";
  const pane = makePane(t, h);
  const z = ZONES[zone];
  t.solo = false;
  t.arr = undefined;
  t.root = insertAt(t.root, anchor, z.dir, pane, z.before);
  t.focus = pane;
  relayout(t);
  renderAll();
  pane.fit.fit();
  connect(pane);
  pane.term.focus();
}

type Arrangement = "single" | "cols" | "rows" | "grid" | "main";

function arrange(kind: Arrangement) {
  const t = active;
  if (!t || t.mode === "files") return;
  const ps = panesOf(t);
  const n = ps.length;
  if (n < 2) return;
  if (kind === "single") {
    t.solo = true;
  } else {
    t.solo = false;
    t.arr = kind;
    const leaf = (pane: Pane): Node => ({ pane });
    const mk = (dir: Dir, kids: Node[], w?: number[]): Node => ({ id: ++nodeSeq, dir, kids, w: w ?? kids.map(() => 1) });
    if (kind === "cols") t.root = mk("row", ps.map(leaf));
    else if (kind === "rows") t.root = mk("col", ps.map(leaf));
    else if (kind === "main") t.root = n === 2 ? mk("row", ps.map(leaf)) : mk("row", [leaf(ps[0]), mk("col", ps.slice(1).map(leaf))], [3, 2]);
    else {
      const c = n <= 2 ? n : n <= 4 ? 2 : n <= 6 ? 3 : 4;
      const rows: Node[] = [];
      for (let i = 0; i < n; i += c) {
        const chunk = ps.slice(i, i + c);
        rows.push(chunk.length === 1 ? leaf(chunk[0]) : mk("row", chunk.map(leaf)));
      }
      t.root = rows.length === 1 ? rows[0] : mk("col", rows);
    }
  }
  relayout(t);
  renderAll();
  t.focus.term.focus();
}

const ARR_THUMB: Record<Arrangement, string> = {
  single: '<rect x="1" y="1" width="22" height="16" rx="1"/>',
  cols: '<rect x="1" y="1" width="6" height="16" rx="1"/><rect x="9" y="1" width="6" height="16" rx="1"/><rect x="17" y="1" width="6" height="16" rx="1"/>',
  rows: '<rect x="1" y="1" width="22" height="4" rx="1"/><rect x="1" y="7" width="22" height="4" rx="1"/><rect x="1" y="13" width="22" height="4" rx="1"/>',
  grid: '<rect x="1" y="1" width="10" height="7" rx="1"/><rect x="13" y="1" width="10" height="7" rx="1"/><rect x="1" y="10" width="10" height="7" rx="1"/><rect x="13" y="10" width="10" height="7" rx="1"/>',
  main: '<rect x="1" y="1" width="13" height="16" rx="1"/><rect x="16" y="1" width="7" height="7" rx="1"/><rect x="16" y="10" width="7" height="7" rx="1"/>',
};
const ARR_LABEL: Record<Arrangement, string> = { single: "Single", cols: "Columns", rows: "Rows", grid: "Grid", main: "Main" };

const layoutPop = $("layout-pop");
const layoutBtn = $<HTMLButtonElement>("layout-btn");

function renderLayout() {
  const t = active;
  if (!t || t.mode === "files") return;
  const n = panesOf(t).length;
  const full = n >= MAX_PANES;
  const solo = !!t.solo && n > 1;
  const opt = (k: Arrangement) => `<button class="lay-opt" type="button" data-arrange="${k}" aria-pressed="${k === "single" && solo}" ${n < 2 ? "disabled" : ""}><svg viewBox="0 0 24 18" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">${ARR_THUMB[k]}</svg><span>${ARR_LABEL[k]}</span></button>`;
  layoutPop.innerHTML = `
    <div class="lay-head"><b>Layout</b><span class="mono">${n} of ${MAX_PANES} sessions</span></div>
    <div class="lay-grid">${(["single", "cols", "rows", "grid", "main"] as Arrangement[]).map(opt).join("")}</div>
    <button class="btn ghost" type="button" data-reset ${n < 2 ? "disabled" : ""}>Reset pane sizes</button>
    <div class="lay-sec">Add a session</div>
    <div class="lay-hosts">${hosts.length ? hosts.map((h) => `<button type="button" data-add="${esc(h.id)}" ${full ? "disabled" : ""}><span>${esc(h.name)}</span><span class="mono">${esc(h.tag)}</span></button>`).join("") : `<div class="none">No hosts.</div>`}</div>
    <p class="fine">${full ? "This view is full. Close a session to add another. " : ""}Drag a title bar onto the edge of another pane to dock it there, or onto the middle to swap places. Drag a host from the sidebar to open it beside any pane. Drag a divider to resize, and double-click one to reset.</p>`;
}

function setLayoutOpen(open: boolean) {
  if (open) renderLayout();
  layoutPop.hidden = !open;
  layoutBtn.setAttribute("aria-expanded", String(open));
}

layoutBtn.onclick = (e) => {
  e.stopPropagation();
  setLayoutOpen(!!layoutPop.hidden);
};
document.addEventListener("click", (e) => {
  if (!layoutPop.hidden && !e.composedPath().includes(layoutPop)) setLayoutOpen(false);
}, true);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !layoutPop.hidden) setLayoutOpen(false);
}, true);
layoutPop.addEventListener("click", (e) => {
  const el = e.target as HTMLElement;
  const a = el.closest<HTMLElement>("[data-arrange]");
  const add = el.closest<HTMLElement>("[data-add]");
  if (a && !(a as HTMLButtonElement).disabled) arrange(a.dataset.arrange as Arrangement);
  else if (add && !(add as HTMLButtonElement).disabled) {
    const h = hosts.find((x) => x.id === add.dataset.add);
    if (h) addSession(h);
  } else if (el.closest("[data-reset]") && !el.closest<HTMLButtonElement>("[data-reset]")!.disabled) resetSizes();
  if (!layoutPop.hidden) renderLayout();
});

function syncLayoutUi() {
  const t = shown();
  const files = !t || t.mode === "files";
  const n = t && !files ? panesOf(t).length : 0;
  layoutBtn.disabled = files;
  $("pane-count").textContent = `${n || 1}/${MAX_PANES}`;
  const solo = !!t && !files && !!t.solo && n > 1;
  const chip = $("solo-chip");
  chip.hidden = !solo;
  if (solo) chip.textContent = `Showing 1 of ${n} · Show all`;
  if (files && !layoutPop.hidden) setLayoutOpen(false);
  else if (!layoutPop.hidden) renderLayout();
}

$("solo-chip").onclick = () => {
  const t = active;
  if (!t) return;
  t.solo = false;
  relayout(t);
  renderAll();
  t.focus.term.focus();
};

type DragSrc = { kind: "pane"; pane: Pane } | { kind: "host"; host: Host };
let dragSrc: DragSrc | undefined;

function paneAt(e: DragEvent): Pane | undefined {
  const el = (e.target as HTMLElement).closest<HTMLElement>(".pane");
  return el && active ? panesOf(active).find((p) => p.el === el) : undefined;
}

function zoneAt(p: Pane, e: DragEvent, allowCenter: boolean): Zone | "center" {
  const r = p.el.getBoundingClientRect();
  const fx = (e.clientX - r.left) / r.width;
  const fy = (e.clientY - r.top) / r.height;
  if (allowCenter && fx > 0.28 && fx < 0.72 && fy > 0.28 && fy < 0.72) return "center";
  const d: Record<Zone, number> = { left: fx, right: 1 - fx, top: fy, bottom: 1 - fy };
  return (Object.keys(d) as Zone[]).sort((a, b) => d[a] - d[b])[0];
}

function showDrop(p: Pane, zone: Zone | "center", label: string, bad: boolean) {
  const d = $("dropzone");
  const tr = $("terms").getBoundingClientRect();
  const r = p.el.getBoundingClientRect();
  let x = r.left, y = r.top, w = r.width, h = r.height;
  if (zone === "left") w /= 2;
  else if (zone === "right") { x += w / 2; w /= 2; }
  else if (zone === "top") h /= 2;
  else if (zone === "bottom") { y += h / 2; h /= 2; }
  const pct = (v: number, of: number) => `${(v / of) * 100}%`;
  Object.assign(d.style, { left: pct(x - tr.left, tr.width), top: pct(y - tr.top, tr.height), width: pct(w, tr.width), height: pct(h, tr.height) });
  d.classList.toggle("bad", bad);
  $("drop-label").textContent = label;
  d.hidden = false;
}

function endDrag() {
  dragSrc = undefined;
  $("dropzone").hidden = true;
  document.querySelectorAll(".pane.dragging").forEach((x) => x.classList.remove("dragging"));
}

$("terms").addEventListener("dragstart", (e) => {
  const bar = (e.target as HTMLElement).closest?.(".pane-bar");
  const p = bar && active ? panesOf(active).find((x) => x.el === bar.parentElement) : undefined;
  if (!p || !e.dataTransfer) return;
  dragSrc = { kind: "pane", pane: p };
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", p.host.name);
  setTimeout(() => p.el.classList.add("dragging"), 0);
});
$("hosts").addEventListener("dragstart", (e) => {
  const id = (e.target as HTMLElement).closest<HTMLElement>("[data-drag-host]")?.dataset.dragHost;
  const h = hosts.find((x) => x.id === id);
  if (!h || !e.dataTransfer) return;
  dragSrc = { kind: "host", host: h };
  e.dataTransfer.effectAllowed = "copy";
  e.dataTransfer.setData("text/plain", h.name);
});
document.addEventListener("dragend", endDrag);
$("terms").addEventListener("dragover", (e) => {
  const t = active;
  const target = paneAt(e);
  if (!dragSrc || !t || !target || t.mode === "files") { $("dropzone").hidden = true; return; }
  if (dragSrc.kind === "pane" && dragSrc.pane === target) { $("dropzone").hidden = true; return; }
  if (dragSrc.kind === "host" && panesOf(t).length >= MAX_PANES) {
    showDrop(target, "center", `Limit reached: ${MAX_PANES} sessions`, true);
    return;
  }
  const z = zoneAt(target, e, dragSrc.kind === "pane");
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = dragSrc.kind === "host" ? "copy" : "move";
  const verb = dragSrc.kind === "host" ? `Open ${dragSrc.host.name}` : "Dock";
  showDrop(target, z, z === "center" ? `Swap with ${target.host.name}` : `${verb} ${ZONES[z].label} ${target.host.name}`, false);
});
$("terms").addEventListener("dragleave", (e) => {
  if (!e.relatedTarget || !$("terms").contains(e.relatedTarget as HTMLElement)) $("dropzone").hidden = true;
});
$("terms").addEventListener("drop", (e) => {
  const t = active;
  const src = dragSrc;
  const target = paneAt(e);
  endDrag();
  if (!src || !t || !target) return;
  e.preventDefault();
  const z = zoneAt(target, e, src.kind === "pane");
  if (src.kind === "host") return addSession(src.host, target, z === "center" ? "right" : z);
  const p = src.pane;
  if (p === target || p.tab !== t) return;
  if (z === "center") swapLeaves(t.root, p, target);
  else {
    t.root = dropPane(t.root, p)!;
    t.root = insertAt(t.root, target, ZONES[z].dir, p, ZONES[z].before);
  }
  t.focus = p;
  t.solo = false;
  if (z !== "center") t.arr = undefined;
  relayout(t);
  renderAll();
  p.term.focus();
});

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
  t.arr = undefined;
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
  if (t.solo) relayout(t);
  markFocus(t);
  renderDrawer();
  t.focus.term.focus();
}

function send(pane: Pane, data: Uint8Array<ArrayBuffer>) {
  if (pane.ws?.readyState === WebSocket.OPEN && pane.state === "connected") pane.ws.send(data);
}

function promptPassphrase(pane: Pane, retry: boolean, remaining: number, addr: string) {
  pane.passphrase = "";
  const note = retry ? `\r\n\x1b[31mIncorrect passphrase.\x1b[0m ${remaining} ${remaining === 1 ? "try" : "tries"} left.\r\n` : "";
  pane.term.write(`${note}\x1b[33mPassphrase for ${addr}:\x1b[0m `);
  pane.term.focus();
}

interface PassphraseRequest { hostId: string; addr: string; retry: boolean; remaining: number }

async function handlePassphraseRequest(pane: Pane, ws: WebSocket, req: PassphraseRequest) {
  const { hostId, addr, retry, remaining } = req;
  pane.asking = hostId;
  pane.pendingSave?.delete(hostId);
  if (retry && pane.usedSaved === hostId) {
    pane.usedSaved = undefined;
    await forgetPassphrase(scope, hostId).catch(() => {});
    renderAutoPass();
    pane.term.write("\r\n\x1b[90mThe saved passphrase no longer works, so it was forgotten.\x1b[0m");
  } else if (!retry && autoPassEnabled()) {
    const saved = await loadPassphrase(scope, hostId).catch(() => undefined);
    if (saved !== undefined && pane.ws === ws && ws.readyState === WebSocket.OPEN) {
      pane.usedSaved = hostId;
      pane.term.write(`\x1b[90mUsing the passphrase saved in this browser for ${addr}.\x1b[0m\r\n`);
      ws.send(JSON.stringify({ t: "passphrase", value: saved }));
      return;
    }
  }
  if (pane.ws === ws) promptPassphrase(pane, retry, remaining, addr);
}

function typePassphrase(pane: Pane, data: string) {
  if (pane.passphrase === undefined) return;
  const { value, action } = feedPassphrase(pane.passphrase, data);
  if (action === "submit") {
    pane.passphrase = undefined;
    pane.term.write("\r\n");
    if (autoPassEnabled() && pane.asking) (pane.pendingSave ??= new Map()).set(pane.asking, value);
    if (pane.ws?.readyState === WebSocket.OPEN) pane.ws.send(JSON.stringify({ t: "passphrase", value }));
  } else if (action === "cancel") {
    pane.passphrase = undefined;
    pane.term.write("\r\n\x1b[90mCancelled.\x1b[0m\r\n");
    pane.cancelled = true;
    pane.ws?.close();
  } else {
    pane.passphrase = value;
  }
}

function connect(pane: Pane) {
  pane.el.querySelector(".banner")?.remove();
  pane.passphrase = undefined;
  pane.usedSaved = undefined;
  pane.asking = undefined;
  pane.pendingSave = undefined;
  pane.diagnostic = undefined;
  pane.cancelled = false;
  pane.state = "connecting";
  pane.info = undefined;
  if (pane.tab.focus === pane) { pane.tab.files.reset(); pane.tab.filesFor = undefined; }
  pane.reason = undefined;
  paintBar(pane);
  const bastionOf = pane.host.via ? hosts.find((h) => h.id === pane.host.via) : undefined;
  pane.term.write(`\x1b[90m${bastionOf ? `Connecting to ${pane.host.addr} through ${bastionOf.name} (${bastionOf.addr})` : `Connecting to ${pane.host.addr}`}…\x1b[0m\r\n`);
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const q = new URLSearchParams({ host: pane.host.id, cols: String(pane.term.cols), rows: String(pane.term.rows) });
  const ws = new WebSocket(`${proto}://${location.host}/ws?${q}`);
  ws.binaryType = "arraybuffer";
  pane.ws = ws;
  let connected = false;

  ws.onopen = () => {
    ws.send(JSON.stringify({ t: "resize", cols: pane.term.cols, rows: pane.term.rows }));
  };
  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) { pane.term.write(new Uint8Array(ev.data)); return; }
    const msg = JSON.parse(ev.data);
    if (msg.t === "passphrase") {
      void handlePassphraseRequest(pane, ws, { hostId: String(msg.hostId ?? pane.host.id), addr: String(msg.addr ?? pane.host.addr), retry: !!msg.retry, remaining: Number(msg.remaining) || 0 });
      if (msg.retry && pane.tab === active) loadSignins(pane.host.id);
      return;
    }
    if (msg.t === "error") {
      pane.term.write(`\r\n\x1b[31m${msg.message}\x1b[0m\r\n`);
      if (!connected && msg.diagnostic && typeof msg.message === "string") {
        pane.diagnostic = { ...msg.diagnostic, message: msg.message };
      }
      return;
    }
    if (msg.t === "status") {
      pane.state = msg.state;
      if (msg.info) pane.info = msg.info;
      if (msg.reason) pane.reason = msg.reason;
      if (msg.state === "connected") {
        connected = true;
        pane.fit.fit();
        const pending = pane.pendingSave;
        pane.pendingSave = undefined;
        if (pending && autoPassEnabled()) for (const [hostId, v] of pending) savePassphrase(scope, hostId, v).then(renderAutoPass).catch(() => {});
      }
      leaveFilesIfGone(pane.tab);
      const t = pane.tab;
      if (msg.state === "connected" && t.wantPath && canBrowse(t)) {
        t.files.initial = t.wantPath;
        t.wantPath = undefined;
        setMode(t, "files");
      }
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
    showBanner(pane, !connected && !pane.cancelled);
    leaveFilesIfGone(pane.tab);
    refresh(pane);
    if (ev.code === 1006) fetch("/api/me").then((r) => { if (r.status === 401) location.reload(); }).catch(() => {});
  };
}

const DIAGNOSTIC_COPY: Record<FailureStage, { label: string; next: string }> = {
  connection: { label: "Reach the SSH server", next: "Check the address, port, network access and any bastion settings." },
  "host-key": { label: "Check the host key", next: "Ask an administrator to verify the host key independently before updating the pinned fingerprint." },
  authentication: { label: "Authenticate", next: "Check the configured SSH username and credentials with an administrator." },
  shell: { label: "Open a shell", next: "Check that this SSH account is allowed to open an interactive shell." },
  configuration: { label: "Load connection settings", next: "Ask an administrator to check the host's SSH configuration and credentials." },
  passphrase: { label: "Unlock the SSH key", next: "Check the key passphrase and try again. If attempts are throttled, wait before retrying." },
  recording: { label: "Start session recording", next: "Ask an administrator to check recording storage and permissions." },
};

function showBanner(pane: Pane, failed: boolean) {
  if (pane.el.querySelector(".banner")) return;
  const b = document.createElement("div");
  b.className = "banner";
  if (failed) {
    b.classList.add("diagnostic");
    b.setAttribute("role", "alert");
    const d = pane.diagnostic;
    const copy = d && DIAGNOSTIC_COPY[d.stage];
    const hop = d?.role === "bastion" ? "Bastion" : "Host";
    const label = copy ? `${hop} · ${copy.label}` : "Shellport connection";
    const message = d?.message ?? (pane.reason === "Connection closed" || pane.reason === "Bastion connection closed"
      ? "The SSH connection closed before a shell opened."
      : "The connection ended before a shell opened.");
    const next = copy?.next ?? "Check your connection and sign-in, then try again. If it continues, ask an administrator to check the server logs.";
    b.innerHTML = `<div class="diag-heading"><span class="diag-icon" aria-hidden="true">!</span><div><strong>Connection failed</strong><div class="diag-stage"></div></div></div><p class="diag-message"></p><p class="diag-next"></p><div class="diag-actions"><button class="btn" type="button">Reconnect</button><button class="diag-dismiss" type="button">Show terminal</button></div>`;
    b.querySelector(".diag-stage")!.textContent = label;
    b.querySelector(".diag-message")!.textContent = message;
    b.querySelector(".diag-next")!.textContent = next;
    b.querySelector<HTMLButtonElement>(".diag-dismiss")!.onclick = () => {
      b.remove();
      showBanner(pane, false);
      pane.term.focus();
    };
  } else {
    b.innerHTML = `<span>Disconnected</span><button class="btn" type="button">Reconnect</button>`;
  }
  b.querySelector<HTMLButtonElement>(".btn")!.onclick = () => { connect(pane); pane.term.focus(); };
  pane.el.appendChild(b);
}

function refresh(p: Pane) {
  paintBar(p);
  renderTabs();
  renderHosts();
  if (p.tab === active) renderDrawer();
}

function renderAll() {
  renderTabs();
  renderHosts();
  renderDrawer();
  syncLayoutUi();
}

function activate(tab: Tab) {
  activePage = undefined;
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
  syncUrl();
  if (active === tab) {
    active = tabs[Math.min(i, tabs.length - 1)];
    if (active && !activePage) return activate(active);
  }
  renderAll();
}

function leftText(ms: number) {
  const m = Math.max(0, Math.round((ms - Date.now()) / 60000));
  return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`;
}

const fmtTime = (ms: number) =>
  new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

function renderSignins() {
  $("signout-others").hidden = othersCount === 0 || !!activePage;
  $("acct-signout-others").hidden = othersCount === 0;
  const html = signins.length ? signins.map((a) => {
    const open = openActs.has(a.id);
    const label = a.kind === "signin" ? "signed in" : a.kind === "totp_failed" ? "wrong TOTP code" : "wrong passphrase";
    const who = a.kind === "signin" ? (a.current ? "this browser" : a.active ? "other session" : "ended") : "";
    const rows: [string, string][] = [["When", new Date(a.at).toLocaleString()], ["From", a.ip || "unknown"]];
    if (a.kind === "signin") {
      rows.push(["Method", a.method === "passkey" ? "Passkey" : "GitHub + authenticator code"], ["Session", a.session ?? "—"], ["Status", a.current ? "this browser" : a.active ? "active" : "ended"]);
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
  $("signins").innerHTML = html;
  $("acct-signins").innerHTML = html;
}

async function loadSignins(host?: string) {
  try {
    const r = await api<{ items: Signin[]; others: number }>(`/api/signins${host ? `?host=${encodeURIComponent(host)}` : ""}`);
    signins = r.items;
    othersCount = r.others;
    renderSignins();
  } catch {}
}

for (const list of [$("signins"), $("acct-signins")]) list.addEventListener("click", (e) => {
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

$("acct-signout-others").onclick = $("signout-others").onclick = async () => {
  const r = await fetch("/api/signins/signout-others", { method: "POST", credentials: "same-origin" }).catch(() => undefined);
  if (!r?.ok) notify(`Could not sign out the other sessions (${failure(r)}). They are still signed in.`);
  loadSignins(active?.focus.host.id);
};

function renderDrawer() {
  const tab = active;
  const row = (k: string, v: string) => `<dt>${k}</dt><dd>${esc(v)}</dd>`;
  const onAccount = activePage?.kind === "account";
  $("drawer-sig-head").hidden = onAccount;
  $("signins").hidden = onAccount;
  if (activePage) {
    const kind = activePage.kind;
    $("close-session").hidden = false;
    $("close-session").textContent = kind === "audit" ? "Close audit log" : kind === "recording" ? "Close recording" : "Close account";
    $("kv").innerHTML = kind === "audit"
      ? row("View", "Audit log") + row("Access", "Admins only")
      : kind === "recording"
        ? row("View", "Recording") + row("Access", "Admins only") + row("Captured", "Terminal output only")
        : row("View", "Account") + row("User", scope) + row("Signed in", $("acct-via").textContent ?? "");
    if (signinsKey !== "page") { signinsKey = "page"; loadSignins(); }
    return;
  }
  $("close-session").textContent = "Close session";
  const t = tab?.focus;
  $("close-session").hidden = !tab;
  const key = `${t?.host.id ?? ""}|${t?.state ?? ""}`;
  if (key !== signinsKey) { signinsKey = key; loadSignins(t?.host.id); }
  const i = t?.info;
  $("kv").innerHTML = !tab || !t ? `<dt>—</dt><dd>No session</dd>` :
    row("Host", i?.host ?? t.host.addr) + row("User", i?.user ?? t.host.addr.split("@")[0]) +
    row("Auth", i?.auth ?? "—") + row("Route", i?.route ?? "—") + row("Cipher", i?.cipher || "—") + row("Host key", i?.hostKey ?? "—") +
    row("Since", i ? new Date(i.since).toLocaleTimeString() : "—") + row("State", t.state + (t.reason && t.state === "closed" ? ` (${t.reason})` : "")) +
    (panesOf(tab).length > 1 ? row("Panes", String(panesOf(tab).length)) : "");
}

const TERM_MOD = isMac ? "⌘" : "Ctrl Shift";
$("keys").innerHTML = [
  [`${TERM_MOD} B`, "Toggle sidebar"],
  [`${TERM_MOD} K`, "Search hosts"],
  [isMac ? "⌘ C / ⌘ V" : "Ctrl Shift C / V", "Copy / paste"],
  ["Alt ← / →", "Previous / next tab"],
  ["Alt Shift D", "Add another session of this host"],
  ["Alt Shift ← / →", "Previous / next session in the view"],
  ["Alt Shift W", "Close session"],
  ["Alt Shift L", "Lock the screen"],
].map(([k, v]) => `<div class="kb"><kbd>${k}</kbd><span>${v}</span></div>`).join("");
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

let lock: ReturnType<typeof initLock> | undefined;

function runShortcut(e: KeyboardEvent, primary: boolean): boolean {
  const k = e.key.toLowerCase();
  if (lock?.isLocked()) return false;
  if (e.altKey && e.shiftKey && e.code === "KeyL") lock?.lock();
  else if (primary && k === "b") toggleRail();
  else if (primary && k === "k") focusSearch();
  else if (e.altKey && e.shiftKey && e.code === "KeyD") { const t = shown(); if (t) addSession(t.focus.host); }
  else if (e.altKey && e.shiftKey && e.code === "KeyW") { const t = shown(); if (t && t.mode === "term") closePane(t.focus); }
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
  const order: (Tab | Page)[] = [...tabs, ...pages];
  if (!order.length) return;
  const cur = activePage ?? active;
  const next = order[((cur ? order.indexOf(cur) : -1) + dir + order.length) % order.length];
  if ("kind" in next) openPage(next.kind);
  else activate(next);
}

document.addEventListener("keydown", (e) => {
  if (e.defaultPrevented || (e.target as HTMLElement).closest?.(".xterm")) return;
  runShortcut(e, e.ctrlKey || e.metaKey);
});

window.addEventListener("beforeunload", (e) => {
  if (tabs.some((t) => tabState(t) === "connected")) e.preventDefault();
});

const accountBtn = $("account-btn");
const scrim = $("signout-scrim");
const addrToggle = $("addr-toggle");

function setHideAddr(hide: boolean, remember = true) {
  $("ws").classList.toggle("hide-addr", hide);
  addrToggle.setAttribute("aria-checked", String(hide));
  if (remember) { try { localStorage.setItem("sp.hideAddr", hide ? "1" : "0"); } catch {} }
}

function setUiTheme(value: UiTheme, remember = true) {
  if (value === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", value);
  for (const b of document.querySelectorAll<HTMLButtonElement>("[data-ui-theme]")) b.setAttribute("aria-pressed", String(b.dataset.uiTheme === value));
  if (remember) { try { localStorage.setItem("sp.theme", value); } catch {} }
}

function setTermTheme(value: TermTheme, remember = true) {
  termTheme = value;
  if (value === "shellport") document.documentElement.removeAttribute("data-term");
  else document.documentElement.setAttribute("data-term", value);
  for (const b of document.querySelectorAll<HTMLButtonElement>("#term-theme [data-term]")) b.setAttribute("aria-checked", String(b.dataset.term === value));
  for (const t of tabs) for (const p of panesOf(t)) p.term.options.theme = TERM_THEMES[value];
  if (remember) { try { localStorage.setItem("sp.termTheme", value); } catch {} }
}

for (const b of document.querySelectorAll<HTMLButtonElement>("[data-ui-theme]")) b.onclick = () => setUiTheme(b.dataset.uiTheme as UiTheme);
for (const b of document.querySelectorAll<HTMLButtonElement>("#term-theme [data-term]")) b.onclick = () => setTermTheme(b.dataset.term as TermTheme);

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

const auditView = initAudit($("page-audit"), { play: (id) => void openRecording(id) });
const recordingView = initRecordingPage($("page-recording"), {
  theme: () => TERM_THEMES[termTheme],
  deleted: () => {
    const p = pages.find((x) => x.kind === "recording");
    if (p) closePage(p);
    void auditView.refresh();
    notify("Recording deleted.");
  },
});

function pageFor(kind: PageKind): Page {
  let p = pages.find((x) => x.kind === kind);
  if (!p) {
    p = { kind, title: kind === "audit" ? "Audit log" : "Account", el: $(`page-${kind}`) };
    pages.push(p);
  }
  return p;
}

function openPage(kind: PageKind) {
  const p = pageFor(kind);
  $("ws").classList.remove("rail-open");
  activePage = p;
  if (kind === "audit") auditView.show();
  renderAll();
  applyMode();
  syncUrl();
}

function closePage(p: Page) {
  const i = pages.indexOf(p);
  if (i < 0) return;
  pages.splice(i, 1);
  p.el.hidden = true;
  if (p.kind === "recording") recordingView.close();
  if (activePage === p) activePage = pages[i] ?? pages[i - 1];
  syncUrl();
  renderAll();
  applyMode();
  shown()?.focus.term.focus();
}

async function openRecording(id: string) {
  const r = await fetch("/api/recordings", { credentials: "same-origin" }).catch(() => undefined);
  if (!r?.ok) return notify(`Could not open the recording (${failure(r)}).`);
  const meta = ((await r.json()) as { items: RecordingMeta[] }).items.find((m) => m.id === id);
  if (!meta) return notify("That recording has been deleted or has expired.");
  let p = pages.find((x) => x.kind === "recording");
  if (!p) {
    p = { kind: "recording", title: "", el: $("page-recording") };
    pages.push(p);
  }
  p.title = `Recording · ${meta.host}`;
  $("ws").classList.remove("rail-open");
  activePage = p;
  void recordingView.show(meta);
  renderAll();
  applyMode();
}

accountBtn.onclick = () => openPage("account");
for (const a of document.querySelectorAll<HTMLElement>("[data-jump]")) {
  a.onclick = (e) => { e.preventDefault(); document.getElementById(a.dataset.jump!)?.scrollIntoView({ behavior: "smooth", block: "start" }); };
}
$("acct-audit").onclick = () => openPage("audit");

function openSignOutDialog() {
  scrim.hidden = false;
  $("signout-cancel").focus();
}

function closeSignOutDialog() {
  if (scrim.hidden) return;
  scrim.hidden = true;
  accountBtn.focus();
}

$("acct-signout").onclick = openSignOutDialog;
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

function leave(url: string) {
  for (const t of tabs) for (const p of panesOf(t)) p.ws?.close();
  tabs = [];
  try { localStorage.removeItem("sp.locked"); } catch {}
  location.replace(url);
}

async function signOut(): Promise<string | undefined> {
  const r = await fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => undefined);
  if (!r?.ok) return `Sign out failed (${failure(r)}). You are still signed in.`;
  await forgetAllPassphrases().catch(() => {});
  leave("/");
  return undefined;
}

$("signout-confirm").onclick = async () => {
  const confirm = $<HTMLButtonElement>("signout-confirm");
  confirm.disabled = true;
  const err = await signOut();
  confirm.disabled = false;
  if (err) {
    closeSignOutDialog();
    notify(err);
  }
};

const apSection = $("acct-ap-sec");
const apToggle = $("ap-toggle");
const apForget = $<HTMLButtonElement>("ap-forget");

async function renderAutoPass() {
  const on = autoPassEnabled();
  apToggle.setAttribute("aria-checked", String(on));
  const n = scope ? await countPassphrases(scope).catch(() => 0) : 0;
  $("ap-count").textContent = n ? `${n} ${n === 1 ? "passphrase" : "passphrases"} saved.` : "Nothing saved.";
  apForget.disabled = n === 0;
}

apToggle.onclick = async () => {
  const on = !autoPassEnabled();
  setAutoPassEnabled(on);
  if (!on) await forgetAllPassphrases().catch(() => {});
  renderAutoPass();
};
apForget.onclick = async () => {
  await forgetAllPassphrases().catch(() => {});
  renderAutoPass();
};

const sealScrim = $("seal-scrim");

function openSealDialog() {
  sealScrim.hidden = false;
  $("seal-cancel").focus();
}

function closeSealDialog() {
  if (sealScrim.hidden) return;
  sealScrim.hidden = true;
  accountBtn.focus();
}

$("acct-seal").onclick = openSealDialog;
$("seal-cancel").onclick = closeSealDialog;
sealScrim.addEventListener("pointerdown", (e) => {
  if (e.target === sealScrim) closeSealDialog();
});
sealScrim.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    closeSealDialog();
  } else if (e.key === "Tab") {
    const buttons = [$("seal-cancel"), $("seal-confirm")];
    const i = buttons.indexOf(document.activeElement as HTMLElement);
    e.preventDefault();
    buttons[(i + (e.shiftKey ? -1 : 1) + buttons.length) % buttons.length].focus();
  }
});

$("seal-confirm").onclick = async () => {
  const confirm = $<HTMLButtonElement>("seal-confirm");
  confirm.disabled = true;
  const r = await fetch("/api/seal", { method: "POST", credentials: "same-origin" }).catch(() => undefined);
  confirm.disabled = false;
  if (!r?.ok) {
    closeSealDialog();
    notify(`Sealing failed (${failure(r)}). The server is still unsealed.`);
    return;
  }
  for (const t of tabs) for (const p of panesOf(t)) p.ws?.close();
  tabs = [];
  for (let i = 0; i < 40; i++) {
    try {
      const h = await fetch("/healthz", { cache: "no-store" });
      if (h.ok && (await h.json()).sealed) break;
    } catch {}
    await new Promise((res) => setTimeout(res, 400));
  }
  location.replace("/");
};

function initialsOf(name: string, login: string): string {
  const words = (name || login).trim().split(/\s+/).filter(Boolean);
  const first = (w: string) => Array.from(w)[0] ?? "";
  const letters = words.length > 1 ? first(words[0]) + first(words[1]) : Array.from(words[0] ?? "?").slice(0, 2).join("");
  return letters.toUpperCase();
}

let scope = "";
let lockScope = "";

function renderMe(me: Me) {
  scope = me.login;
  lockScope = `${me.login}:${me.expiresAt}`;
  apSection.hidden = !passSupported();
  renderAutoPass();
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
  $("acct-via").textContent = me.via === "passkey" ? "Signed in with a passkey" : "Signed in with GitHub";
  $("acct-version").textContent = me.version;
  $("acct-role").hidden = !me.admin;
  $("acct-expiry").textContent = `Session ends in ${leftText(me.expiresAt)}`;
  $<HTMLAnchorElement>("acct-release-notes").href = me.releaseNotesUrl;
  passkeys.enable(!!me.canManagePasskeys);
  $("acct-seal-sec").hidden = !me.sealable;
  $("acct-server-card").hidden = !me.sealable && !me.admin;
  $("acct-nav-server").hidden = $("acct-server-card").hidden;
  isAdmin = !!me.admin;
  $("acct-audit-sec").hidden = !me.admin;
  $("me-role").hidden = !me.admin;
  $("add-host").hidden = !me.canAddHosts;
  canEdit = !!me.canAddHosts;
  setInterval(() => {
    if (me.expiresAt <= Date.now()) location.reload();
  }, 30_000);
}

const passkeys = initPasskeys({
  section: $("acct-pk-sec"),
  list: $("pk-list"),
  addButton: $<HTMLButtonElement>("pk-add"),
  scrim: $("pk-scrim"),
  reopenAccount: () => {},
  closeAccount: () => {},
});

lock = initLock({
  sessions: () => tabs.flatMap((t) => panesOf(t)).map((p) => ({ name: p.host.name, state: p.state })),
  beforeLock: () => {
    setLayoutOpen(false);
    closeSignOutDialog();
  },
  afterUnlock: () => {
    requestAnimationFrame(fitActive);
    const t = shown(); if (t && t.mode === "term") t.focus.term.focus();
  },
  signOut,
  leave,
  scope: () => lockScope,
});

const hostEditor = initAddHost({
  button: $("add-host"),
  scrim: $("host-scrim"),
  groups: () => [...new Set(hosts.map((h) => h.group))],
  hosts: () => hosts,
  onChanged: async () => {
    hosts = await api<Host[]>("/api/hosts");
    renderAll();
  },
  restoreFocus: () => $("add-host").focus(),
});

$("hosts").addEventListener("click", (e) => {
  const id = (e.target as HTMLElement).closest<HTMLElement>("[data-edit]")?.dataset.edit;
  if (id) void hostEditor.edit(id);
});

$("close-session").onclick = () => {
  if (activePage) closePage(activePage);
  else if (active) closeTab(active);
};

const setShift = (on: boolean) => document.body.classList.toggle("shift-held", on);
document.addEventListener("keydown", (e) => { if (e.key === "Shift") setShift(true); });
document.addEventListener("keyup", (e) => { if (e.key === "Shift") setShift(false); });
window.addEventListener("blur", () => setShift(false));

(async () => {
  try {
    if (localStorage.getItem("sp.rail") === "0" && !matchMedia("(max-width: 760px)").matches) toggleRail();
    if (localStorage.getItem("sp.drawer") === "0") setDrawer(false);
    if (localStorage.getItem("sp.hideAddr") === "1") setHideAddr(true, false);
    setZoom(Number(localStorage.getItem("sp.zoom")) || 100, false);
  } catch {}
  setUiTheme(savedChoice("sp.theme", UI_THEMES, "system"), false);
  setTermTheme(savedChoice("sp.termTheme", TERM_KEYS, "shellport"), false);
  if (matchMedia("(max-width: 900px)").matches) setDrawer(false, false);
  const [me, hs] = await Promise.all([api<Me>("/api/me"), api<Host[]>("/api/hosts")]);
  hosts = hs;
  renderMe(me);
  renderAll();
  openFromUrl();
  lock?.resume();
})();
