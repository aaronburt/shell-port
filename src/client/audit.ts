const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

interface Entry { id: string; at: number; kind: string; user: string; ip: string; host: string; detail: string }
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

const PAGE = 50;
const PERIODS: [string, string][] = [["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["0", "All kept events"]];

const fmtTime = (ms: number) =>
  new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

export function initAudit(el: HTMLElement) {
  const filters = el.querySelector<HTMLElement>("#aud-filters")!;
  const table = el.querySelector<HTMLElement>("#aud-table")!;
  const foot = el.querySelector<HTMLElement>("#aud-foot")!;
  const intro = el.querySelector<HTMLElement>("#aud-status")!;
  const q = { user: "", host: "", type: "all", days: "7" };
  let data: Listing | undefined;
  let items: Entry[] = [];
  let loading = false;
  let failed = "";
  let serial = 0;

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

  function render() {
    const d = data;
    if (d) {
      const s = d.status;
      intro.innerHTML = `Admins only. Kept for ${s.retentionDays} days${s.file ? ` in <span class="mono">${esc(s.file)}</span>${s.encrypted ? ", encrypted while the server is sealed" : ""}` : ""}. Passwords, passphrases, keys and terminal content are never recorded.`;
      const warn: string[] = [];
      if (!s.stored) warn.push(`The log could not be saved to disk${s.error ? ` (${esc(s.error)})` : ""}, so new events are kept in memory only and are lost when the server restarts. Set <span class="mono">SHELLPORT_AUDIT</span> to a writable file.`);
      if (s.unreadable) warn.push(`${s.unreadable} ${s.unreadable === 1 ? "line" : "lines"} in the log file could not be read and ${s.unreadable === 1 ? "was" : "were"} skipped.`);
      el.querySelector<HTMLElement>("#aud-warn")!.innerHTML = warn.map((w) => `<div class="alert"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v5M12 18h.01"/></svg><div>${w}</div></div>`).join("");
    }
    const kinds = d?.kinds ?? {};
    table.setAttribute("aria-busy", String(loading));
    if (failed) table.innerHTML = `<p class="none form-err" role="alert">${esc(failed)}</p>`;
    else if (!items.length) table.innerHTML = `<p class="none">${loading || !d ? "Loading…" : "No events match these filters."}</p>`;
    else {
      table.innerHTML = `<div class="aud-head" role="row"><span>When</span><span>User</span><span>Event</span><span>Host</span><span>From</span><span>Details</span></div>` +
        items.map((e) => {
          const k = kinds[e.kind];
          return `<div class="aud-row" role="row"><span class="c-when mono" title="${esc(new Date(e.at).toLocaleString())}">${fmtTime(e.at)}</span><span class="c-user">${esc(e.user || "—")}</span><span class="c-ev"><b class="${k?.bad ? "bad" : ""}">${esc(k?.label ?? e.kind)}</b></span><span class="c-host">${esc(e.host || "—")}</span><span class="c-ip mono">${esc(e.ip || "—")}</span><span class="c-detail" title="${esc(e.detail)}">${esc(e.detail)}</span></div>`;
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

  filters.addEventListener("change", () => {
    q.user = (filters.querySelector("#aud-user") as HTMLSelectElement).value;
    q.host = (filters.querySelector("#aud-host") as HTMLSelectElement).value;
    q.type = (filters.querySelector("#aud-type") as HTMLSelectElement).value;
    q.days = (filters.querySelector("#aud-days") as HTMLSelectElement).value;
    void load();
  });
  foot.addEventListener("click", (e) => {
    const t = e.target as HTMLElement;
    if (t.closest("[data-more]")) void load(true);
    else if (t.closest("[data-refresh]")) void load().then(renderFilters);
    else if (t.closest("a[aria-disabled]")) e.preventDefault();
  });

  return {
    show() {
      void load().then(renderFilters);
    },
  };
}
