const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

type Kind = "dir" | "file" | "link" | "other";
interface Entry { name: string; kind: Kind; size: number; mtime: number; mode: string }
interface Listing { path: string; entries: Entry[]; truncated: boolean; maxDownloadBytes: number }
interface Preview { path: string; size: number; truncated: boolean; binary: boolean; text: string }

export interface FilesOptions {
  terminalId(): string | undefined;
  where(): string;
}

const MESSAGES: Record<string, string> = {
  not_found: "That path no longer exists.",
  permission_denied: "Permission denied on the host.",
  not_connected: "The session is not connected.",
  files_disabled: "File access is turned off for this host.",
  sftp_unavailable: "The host did not allow file access (SFTP).",
  too_large: "That file is larger than the download limit.",
  too_many_downloads: "Too many downloads are running. Wait for one to finish.",
  cannot_remove: "Could not delete it. A folder must be empty first.",
  not_a_file: "That is not a regular file.",
  bad_path: "That path is not allowed.",
  timeout: "The host took too long to answer.",
  rate_limited: "Too many requests. Try again in a moment.",
};

const fmtSize = (n: number) => {
  if (n < 1024) return `${n}B`;
  const units = ["K", "M", "G", "T"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)}${units[i]}`;
};
const fmtTime = (s: number) =>
  s ? new Date(s * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "";
const join = (dir: string, name: string) => (dir === "/" ? "" : dir) + "/" + name;
const parent = (p: string) => p.split("/").slice(0, -1).join("/") || "/";

let confirmEl: HTMLElement | undefined;

export class FilesPane {
  readonly el: HTMLElement;
  private path = "";
  private listing?: Listing;
  private sel: string | undefined;
  private view: { name: string; data: Preview } | undefined;
  private notice = "";
  private loading = false;
  private seq = 0;
  private menu: HTMLElement;
  private started = false;

  constructor(private opts: FilesOptions) {
    this.el = document.createElement("div");
    this.el.className = "files";
    this.el.hidden = true;
    this.menu = document.createElement("div");
    this.menu.className = "ctxmenu";
    this.menu.setAttribute("role", "menu");
    this.menu.hidden = true;
    this.el.addEventListener("click", (e) => this.onClick(e));
    this.el.addEventListener("dblclick", (e) => this.onDblClick(e));
    this.el.addEventListener("contextmenu", (e) => this.onContext(e));
    this.el.addEventListener("keydown", (e) => this.onKey(e));
    this.menu.addEventListener("click", (e) => { this.onClick(e); this.hideMenu(); });
    document.addEventListener("click", (e) => { if (!this.menu.contains(e.target as Node)) this.hideMenu(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") this.hideMenu(); });
    document.body.appendChild(this.menu);
  }

  show() {
    this.el.hidden = false;
    if (!this.started) {
      this.started = true;
      this.go();
    } else this.render();
  }

  reset() {
    this.seq++;
    this.started = false;
    this.listing = undefined;
    this.path = "";
    this.sel = undefined;
    this.view = undefined;
    this.notice = "";
    this.loading = false;
    this.hideMenu();
  }

  hide() {
    this.el.hidden = true;
    this.hideMenu();
  }

  dispose() {
    this.seq++;
    this.menu.remove();
    this.el.remove();
  }

  private api(route: string, query: Record<string, string> = {}, init?: RequestInit) {
    const id = this.opts.terminalId();
    if (!id) return Promise.reject(new Error("not_connected"));
    const q = new URLSearchParams(query).toString();
    return fetch(`/api/terminals/${encodeURIComponent(id)}/files${route}${q ? `?${q}` : ""}`, { credentials: "same-origin", ...init });
  }

  private async json<T>(res: Response): Promise<T> {
    if (res.status === 401) { location.reload(); throw new Error("signed out"); }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(MESSAGES[(body as { error?: string }).error ?? ""] ?? `The host could not do that (status ${res.status}).`);
    return body as T;
  }

  private failure(e: unknown) {
    const m = (e as Error).message;
    return MESSAGES[m] ?? m;
  }

  async go(target?: string) {
    const seq = ++this.seq;
    this.loading = true;
    this.notice = "";
    this.render();
    try {
      const data = await this.json<Listing>(await this.api("", target ? { path: target } : {}));
      if (seq !== this.seq) return;
      this.listing = data;
      this.path = data.path;
      this.view = undefined;
      if (!data.entries.some((x) => x.name === this.sel)) this.sel = undefined;
      if (data.truncated) this.notice = "Only the first entries are shown. This folder is very large.";
    } catch (e) {
      if (seq !== this.seq) return;
      this.notice = this.failure(e);
    } finally {
      if (seq === this.seq) { this.loading = false; this.render(); }
    }
  }

  private async open(name: string) {
    const seq = ++this.seq;
    this.notice = "";
    try {
      const data = await this.json<Preview>(await this.api("/view", { path: join(this.path, name) }));
      if (seq !== this.seq) return;
      this.view = { name, data };
    } catch (e) {
      if (seq !== this.seq) return;
      this.notice = this.failure(e);
    }
    this.render();
  }

  private download(name: string) {
    const entry = this.listing?.entries.find((x) => x.name === name);
    if (entry?.kind === "dir") { this.notice = "Folders cannot be downloaded."; return this.render(); }
    if (entry && this.listing && entry.size > this.listing.maxDownloadBytes) {
      this.notice = MESSAGES.too_large;
      return this.render();
    }
    const id = this.opts.terminalId();
    if (!id) return;
    const a = document.createElement("a");
    a.href = `/api/terminals/${encodeURIComponent(id)}/files/download?${new URLSearchParams({ path: join(this.path, name) })}`;
    a.download = name;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
    this.notice = `Downloading ${name}`;
    this.render();
  }

  private ask(name: string) {
    const dir = this.path;
    const where = this.opts.where();
    confirmEl?.remove();
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    scrim.innerHTML = `<div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="del-title" aria-describedby="del-text">
      <h3 id="del-title">Delete ${esc(name)}?</h3>
      <p id="del-text">It will be removed from ${esc(dir)} on ${esc(where)}. This can't be undone.</p>
      <div class="modal-foot"><button class="btn ghost" type="button" data-cancel>Cancel</button><button class="btn" type="button" data-confirm>Delete</button></div>
    </div>`;
    confirmEl = scrim;
    document.body.appendChild(scrim);
    const cancel = scrim.querySelector<HTMLButtonElement>("[data-cancel]")!;
    const confirm = scrim.querySelector<HTMLButtonElement>("[data-confirm]")!;
    const close = () => { scrim.remove(); if (confirmEl === scrim) confirmEl = undefined; };
    cancel.onclick = close;
    scrim.addEventListener("pointerdown", (e) => { if (e.target === scrim) close(); });
    scrim.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); close(); }
      else if (e.key === "Tab") { e.preventDefault(); (document.activeElement === cancel ? confirm : cancel).focus(); }
    });
    confirm.onclick = async () => {
      confirm.disabled = true;
      try {
        await this.json(await this.api("/delete", {}, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: join(dir, name) }),
        }));
        close();
        this.sel = undefined;
        await this.go(dir);
        this.notice = `Deleted ${name}`;
      } catch (e) {
        close();
        this.notice = this.failure(e);
      }
      this.render();
    };
    cancel.focus();
  }

  private rowName(e: Event) {
    return (e.target as HTMLElement).closest<HTMLElement>(".files-row")?.dataset.name;
  }

  private onClick(e: Event) {
    const t = e.target as HTMLElement;
    const hit = (s: string) => t.closest<HTMLElement>(s);
    if (hit("[data-go]")) return void this.go(hit("[data-go]")!.dataset.go);
    if (hit("[data-up]")) return void this.go(parent(this.path));
    if (hit("[data-refresh]")) return void this.go(this.path);
    if (hit("[data-back]")) { this.view = undefined; this.notice = ""; return this.render(); }
    const name = this.view?.name ?? this.sel;
    if (hit("[data-open]") && name) return this.openEntry(name);
    if (hit("[data-view]") && name) return void this.open(name);
    if (hit("[data-download]") && name) return this.download(name);
    if (hit("[data-delete]") && name) return this.ask(name);
    const row = this.rowName(e);
    if (row && row !== this.sel) { this.sel = row; this.notice = ""; this.render(); }
  }

  private openEntry(name: string) {
    const entry = this.listing?.entries.find((x) => x.name === name);
    if (!entry) return;
    this.sel = name;
    if (entry.kind === "dir") void this.go(join(this.path, name));
    else void this.open(name);
  }

  private onDblClick(e: MouseEvent) {
    const name = this.rowName(e);
    if (name) this.openEntry(name);
  }

  private onContext(e: MouseEvent) {
    const name = this.rowName(e);
    const entry = this.listing?.entries.find((x) => x.name === name);
    if (!name || !entry) return;
    e.preventDefault();
    this.sel = name;
    this.render();
    this.menu.innerHTML = (entry.kind === "dir"
      ? `<button role="menuitem" data-open="1">Open</button>`
      : `<button role="menuitem" data-view="1">View</button>`) +
      `<button role="menuitem" data-download="1">Download</button><hr><button role="menuitem" data-delete="1" class="danger">Delete</button>`;
    this.menu.hidden = false;
    const r = this.menu.getBoundingClientRect();
    this.menu.style.left = `${Math.max(8, Math.min(e.clientX, innerWidth - r.width - 8))}px`;
    this.menu.style.top = `${Math.max(8, Math.min(e.clientY, innerHeight - r.height - 8))}px`;
    this.menu.querySelector<HTMLElement>("button")?.focus();
  }

  private hideMenu() {
    if (!this.menu.hidden) this.menu.hidden = true;
  }

  private onKey(e: KeyboardEvent) {
    const name = this.rowName(e);
    if (e.key === "Enter" && name && e.detail === 0 && (e.target as HTMLElement).classList.contains("files-row")) {
      e.preventDefault();
      this.openEntry(name);
    }
  }

  private crumbs() {
    const parts = this.path.split("/").filter(Boolean);
    return `<button data-go="/">/</button>` +
      parts.map((c, i) => `<button data-go="/${esc(parts.slice(0, i + 1).join("/"))}">${esc(c)}</button>`).join("");
  }

  private render() {
    if (this.el.hidden) return;
    const list = this.el.querySelector<HTMLElement>(".files-list");
    const scroll = list?.scrollTop ?? 0;
    const focused = (document.activeElement as HTMLElement | null)?.closest?.<HTMLElement>(".files-row")?.dataset.name;
    const where = esc(this.opts.where());
    if (this.view) {
      const { name, data } = this.view;
      const body = data.binary
        ? `<p class="files-empty">This looks like a binary file, so there is no preview. Use Download to get it.</p>`
        : `<pre class="files-view">${esc(data.text)}</pre>`;
      this.el.innerHTML = `
        <div class="files-bar">
          <button class="tool" data-back="1">← Back</button>
          <span class="fname-bar">${esc(join(this.path, name))}</span>
          <span class="grow"></span>
          <button class="tool" data-download="1">Download</button>
          <button class="tool" data-delete="1">Delete</button>
        </div>
        ${body}
        <div class="files-foot"><span>SFTP · ${where}</span><span>${esc(this.notice || (data.truncated ? `First ${fmtSize(data.text.length)} of ${fmtSize(data.size)} · read only` : `${fmtSize(data.size)} · read only`))}</span></div>`;
      return;
    }
    const rows = [...(this.listing?.entries ?? [])].sort((a, b) =>
      (a.kind === "dir" ? 0 : 1) - (b.kind === "dir" ? 0 : 1) || a.name.localeCompare(b.name));
    const sel = rows.find((r) => r.name === this.sel);
    const status = this.loading ? "Loading…" : this.notice || `${rows.length} items${sel ? ` · ${sel.name} selected` : ""}`;
    this.el.innerHTML = `
      <div class="files-bar">
        <button class="tool" data-up="1" ${this.path === "/" || !this.path ? "disabled" : ""}>↑ Up</button>
        <nav class="crumbs" aria-label="Path">${this.crumbs()}</nav>
        <span class="grow"></span>
        <button class="tool" data-refresh="1" ${this.path ? "" : "disabled"}>Refresh</button>
        <button class="tool" data-view="1" ${sel && sel.kind !== "dir" ? "" : "disabled"}>View</button>
        <button class="tool" data-download="1" ${sel && sel.kind !== "dir" ? "" : "disabled"}>Download</button>
        <button class="tool" data-delete="1" ${sel ? "" : "disabled"}>Delete</button>
      </div>
      <div class="files-head"><span>Name</span><span>Size</span><span class="opt">Modified</span><span class="opt">Permissions</span></div>
      <div class="files-list">${rows.length
        ? rows.map((r) => `<button class="files-row ${r.name === this.sel ? "sel" : ""}" data-name="${esc(r.name)}" data-kind="${r.kind}"><span class="fname">${esc(r.name)}${r.kind === "dir" ? "/" : ""}</span><span>${r.kind === "dir" ? "" : fmtSize(r.size)}</span><span class="opt">${fmtTime(r.mtime)}</span><span class="opt">${esc(r.mode)}</span></button>`).join("")
        : this.loading || !this.listing ? "" : `<p class="files-empty">This folder is empty.</p>`}</div>
      <div class="files-foot"><span>SFTP · ${where}</span><span role="status">${esc(status)}</span></div>`;
    const next = this.el.querySelector<HTMLElement>(".files-list");
    if (next) next.scrollTop = scroll;
    if (focused) this.el.querySelector<HTMLElement>(`.files-row[data-name="${CSS.escape(focused)}"]`)?.focus();
  }
}
