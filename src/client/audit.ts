import { fmtLength, fmtSize, type RecordingMeta } from "./playback.js";

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

interface Entry { id: string; at: number; kind: string; user: string; ip: string; host: string; detail: string; ref?: string }
interface Status { stored: boolean; file?: string; encrypted: boolean; error?: string; unreadable: number; retentionDays: number }
interface Listing {
  items: Entry[];
  total: number;
  users: string[];
  hosts: string[];
  groups: string[];
  kinds: Record<string, { group: string; label: string; bad?: true }>;
  status: Status;
}
interface RecStatus { available: boolean; error?: string; encrypted: boolean; retentionDays: number; maxMB: number }
interface RecListing { items: RecordingMeta[]; status: RecStatus }

const PAGE = 50;
const PERIODS: [string, string][] = [["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["0", "All kept events"]];

const fmtTime = (ms: number) =>
  new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

const ALERT_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v5M12 18h.01"/></svg>`;
const alertBox = (html: string) => `<div class="alert">${ALERT_ICON}<div>${html}</div></div>`;

export function initAudit(el: HTMLElement, hooks: { play(id: string): void }) {
  const views = el.querySelector<HTMLElement>("#aud-views")!;
  const filters = el.querySelector<HTMLElement>("#aud-filters")!;
  const table = el.querySelector<HTMLElement>("#aud-table")!;
  const foot = el.querySelector<HTMLElement>("#aud-foot")!;
  const intro = el.querySelector<HTMLElement>("#aud-status")!;
  const warnEl = el.querySelector<HTMLElement>("#aud-warn")!;
  const q = { user: "", host: "", type: "all", days: "7" };
  let view: "events" | "recordings" = "events";
  let data: Listing | undefined;
  let items: Entry[] = [];
  let loading = false;
  let failed = "";
  let serial = 0;
  let recs: RecListing | undefined;
  let recLoading = false;
  let recFailed = "";
  let recSerial = 0;

  const params = (extra: Record<string, string | number> = {}) => {
    const p = new URLSearchParams();
    if (q.user) p.set("user", q.user);
    if (q.host) p.set("host", q.host);
    if (q.type !== "all") p.set("type", q.type);
    if (q.days !== "0") p.set("days", q.days);
    for (const [k, v] of Object.entries(extra)) p.set(k, String(v));
    return p.toString();
  };

  async function load(more = false) {
    const mine = ++serial;
    loading = true;
    failed = "";
    render();
    try {
      const r = await fetch(`/api/audit?${params({ limit: PAGE, offset: more ? items.length : 0 })}`, { credentials: "same-origin" });
      if (r.status === 401) { location.reload(); return; }
      if (!r.ok) throw new Error(`status ${r.status}`);
      const d: Listing = await r.json();
      if (mine !== serial) return;
      data = d;
      items = more ? [...items, ...d.items] : d.items;
    } catch (e) {
      if (mine !== serial) return;
      failed = `Could not load the audit log (${(e as Error).message}).`;
    } finally {
      if (mine === serial) {
        loading = false;
        render();
      }
    }
  }

  async function loadRecordings() {
    const mine = ++recSerial;
    recLoading = true;
    recFailed = "";
    render();
    try {
      const r = await fetch("/api/recordings", { credentials: "same-origin" });
      if (r.status === 401) { location.reload(); return; }
      if (!r.ok) throw new Error(`status ${r.status}`);
      const d: RecListing = await r.json();
      if (mine === recSerial) recs = d;
    } catch (e) {
      if (mine === recSerial) recFailed = `Could not load recordings (${(e as Error).message}).`;
    } finally {
      if (mine === recSerial) {
        recLoading = false;
        render();
      }
    }
  }

  const select = (id: string, label: string, options: [string, string][], value: string) =>
    `<div class="field"><label for="${id}">${label}</label><select id="${id}">${options.map(([v, t]) => `<option value="${esc(v)}"${v === value ? " selected" : ""}>${esc(t)}</option>`).join("")}</select></div>`;

  function renderFilters() {
    if (!data) return;
    filters.innerHTML =
      select("aud-user", "User", [["", "Everyone"], ...data.users.map((u): [string, string] => [u, u])], q.user) +
      select("aud-host", "Host", [["", "All hosts"], ...data.hosts.map((h): [string, string] => [h, h])], q.host) +
      select("aud-type", "Event", [["all", "All events"], ["fail", "Failures only"], ...data.groups.map((g): [string, string] => [g, g])], q.type) +
      select("aud-days", "Period", PERIODS, q.days);
  }

  function syncViews() {
    for (const b of views.querySelectorAll<HTMLElement>("[data-view]")) b.setAttribute("aria-pressed", String(b.dataset.view === view));
    filters.hidden = view !== "events";
  }

  function renderEvents() {
    const d = data;
    if (d) {
      const s = d.status;
      intro.innerHTML = `Admins only. Kept for ${s.retentionDays} days${s.file ? ` in <span class="mono">${esc(s.file)}</span>${s.encrypted ? ", encrypted while the server is sealed" : ""}` : ""}. Passwords, passphrases and keys are never recorded. Session recordings keep terminal output only, not typed keys.`;
      const warn: string[] = [];
      if (!s.stored) warn.push(`The log could not be saved to disk${s.error ? ` (${esc(s.error)})` : ""}, so new events are kept in memory only and are lost when the server restarts. Set <span class="mono">SHELLPORT_AUDIT</span> to a writable file.`);
      if (s.unreadable) warn.push(`${s.unreadable} ${s.unreadable === 1 ? "line" : "lines"} in the log file could not be read and ${s.unreadable === 1 ? "was" : "were"} skipped.`);
      warnEl.innerHTML = warn.map(alertBox).join("");
    }
    const kinds = d?.kinds ?? {};
    table.setAttribute("aria-busy", String(loading));
    table.setAttribute("aria-label", "Audit events");
    if (failed) table.innerHTML = `<p class="none form-err" role="alert">${esc(failed)}</p>`;
    else if (!items.length) table.innerHTML = `<p class="none">${loading || !d ? "Loading…" : "No events match these filters."}</p>`;
    else {
      table.innerHTML = `<div class="aud-head" role="row"><span>When</span><span>User</span><span>Event</span><span>Host</span><span>From</span><span>Details</span></div>` +
        items.map((e) => {
          const k = kinds[e.kind];
          const play = e.ref ? ` · <a href="#" class="rec-link" data-play="${esc(e.ref)}">Play recording</a>` : "";
          return `<div class="aud-row" role="row"><span class="c-when mono" title="${esc(new Date(e.at).toLocaleString())}">${fmtTime(e.at)}</span><span class="c-user">${esc(e.user || "—")}</span><span class="c-ev"><b class="${k?.bad ? "bad" : ""}">${esc(k?.label ?? e.kind)}</b>${play}</span><span class="c-host">${esc(e.host || "—")}</span><span class="c-ip mono">${esc(e.ip || "—")}</span><span class="c-detail" title="${esc(e.detail)}">${esc(e.detail)}</span></div>`;
        }).join("");
    }
    const total = d?.total ?? 0;
    foot.innerHTML = `<p class="fine">${d ? `${items.length} of ${total} ${total === 1 ? "event" : "events"}, newest first. Export includes everything the filters match.` : ""}</p>
      <div class="aud-btns">
        ${d && items.length < total ? `<button class="btn ghost" type="button" data-more${loading ? " disabled" : ""}>Show more</button>` : ""}
        <button class="btn ghost" type="button" data-refresh${loading ? " disabled" : ""}>Refresh</button>
        <a class="btn ghost" href="/api/audit/export?${esc(params())}" download="shellport-audit.csv"${total ? "" : ' aria-disabled="true" tabindex="-1"'}>Export CSV</a>
      </div>`;
  }

  const recStatusLabel = (r: RecordingMeta) => {
    if (r.status === "recording") return `<b class="live">Recording now</b>`;
    if (r.status === "complete") return "Complete";
    if (r.status === "partial") return `<b class="bad" title="The server stopped while recording">Interrupted</b>`;
    return `<b class="bad" title="${esc(r.reason ?? "")}">Stopped early</b>`;
  };

  function renderRecordings() {
    const d = recs;
    if (d) {
      const s = d.status;
      intro.innerHTML = `Admins only. Recordings are kept for ${s.retentionDays} days${s.encrypted ? " and encrypted while the server is sealed" : ""}. They hold terminal output only, not typed keys, but anything a command prints, secrets included, is in the recording.`;
      warnEl.innerHTML = s.available ? "" : alertBox(`Session recording is not working on this server${s.error ? ` (${esc(s.error)})` : ""}. New sessions do not open until it does.`);
    }
    table.setAttribute("aria-busy", String(recLoading));
    table.setAttribute("aria-label", "Session recordings");
    const rows = d?.items ?? [];
    if (recFailed) table.innerHTML = `<p class="none form-err" role="alert">${esc(recFailed)}</p>`;
    else if (!rows.length) table.innerHTML = `<p class="none">${recLoading || !d ? "Loading…" : "No recordings yet. Sessions are recorded from the next time one opens."}</p>`;
    else {
      table.innerHTML = `<div class="rec-head" role="row"><span>Started</span><span>Host</span><span>User</span><span>Length</span><span>Size</span><span>Status</span><span></span></div>` +
        rows.map((r) => `<div class="rec-row" role="row"><span class="c-when mono" title="${esc(new Date(r.startedAt).toLocaleString())}">${fmtTime(r.startedAt)}</span><span class="c-host">${esc(r.host)}</span><span class="c-user">${esc(r.user)}</span><span class="c-len mono">${fmtLength((r.endedAt ?? Date.now()) - r.startedAt)}</span><span class="c-size mono">${fmtSize(r.bytes)}</span><span class="c-status">${recStatusLabel(r)}</span><span><button class="btn ghost" type="button" data-play="${esc(r.id)}">Play</button></span></div>`).join("");
    }
    foot.innerHTML = `<p class="fine">${d ? `${rows.length} ${rows.length === 1 ? "recording" : "recordings"}, newest first.` : ""}</p>
      <div class="aud-btns"><button class="btn ghost" type="button" data-refresh${recLoading ? " disabled" : ""}>Refresh</button></div>`;
  }

  function render() {
    syncViews();
    if (view === "events") renderEvents();
    else renderRecordings();
  }

  views.addEventListener("click", (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>("[data-view]");
    if (!b || b.dataset.view === view) return;
    view = b.dataset.view as typeof view;
    if (view === "events") void load().then(renderFilters);
    else void loadRecordings();
  });

  filters.addEventListener("change", () => {
    q.user = (filters.querySelector("#aud-user") as HTMLSelectElement).value;
    q.host = (filters.querySelector("#aud-host") as HTMLSelectElement).value;
    q.type = (filters.querySelector("#aud-type") as HTMLSelectElement).value;
    q.days = (filters.querySelector("#aud-days") as HTMLSelectElement).value;
    void load();
  });

  const onPlay = (e: Event) => {
    const link = (e.target as HTMLElement).closest<HTMLElement>("[data-play]");
    if (!link) return;
    e.preventDefault();
    hooks.play(link.dataset.play!);
  };
  table.addEventListener("click", onPlay);

  foot.addEventListener("click", (e) => {
    const t = e.target as HTMLElement;
    if (t.closest("[data-more]")) void load(true);
    else if (t.closest("[data-refresh]")) {
      if (view === "events") void load().then(renderFilters);
      else void loadRecordings();
    } else if (t.closest("a[aria-disabled]")) e.preventDefault();
  });

  return {
    show() {
      if (view === "recordings") void loadRecordings();
      else void load().then(renderFilters);
    },
    /** Reloads whichever view is showing, for example after a recording is deleted. */
    refresh() {
      if (view === "recordings") return loadRecordings();
      return load().then(renderFilters);
    },
  };
}
