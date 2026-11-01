interface KeyEntry { id: string; name: string; encrypted: boolean; hosts: number }

interface Form {
  mode: "existing" | "upload";
  name: string;
  group: string;
  host: string;
  port: string;
  user: string;
  keyId: string;
  file?: { name: string; pem: string; encrypted: boolean };
  ack: boolean;
  error: string;
  busy: boolean;
}

export interface AddHostOptions {
  button: HTMLElement;
  scrim: HTMLElement;
  groups: () => string[];
  onAdded: () => Promise<void>;
  restoreFocus: () => void;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const MAX_KEY_BYTES = 16 * 1024;

function looksEncrypted(pem: string): boolean {
  if (/ENCRYPTED/.test(pem)) return true;
  if (!/BEGIN OPENSSH PRIVATE KEY/.test(pem)) return false;
  try {
    const raw = atob(pem.replace(/-----[^-]+-----|\s/g, ""));
    return !(raw.slice(15, 19) === "\0\0\0\x04" && raw.slice(19, 23) === "none");
  } catch {
    return false;
  }
}

export function initAddHost(opts: AddHostOptions) {
  const { scrim } = opts;
  let keys: KeyEntry[] = [];
  let form: Form;

  const selected = (): { encrypted: boolean } | undefined =>
    form.mode === "existing" ? keys.find((k) => k.id === form.keyId) : form.file;

  const sync = () => {
    const v = (id: string) => (scrim.querySelector<HTMLInputElement>(`#ah-${id}`)?.value ?? "");
    if (!scrim.querySelector("#ah-name")) return;
    form.name = v("name");
    form.group = v("group");
    form.host = v("host");
    form.port = v("port");
    form.user = v("user");
    const key = scrim.querySelector<HTMLSelectElement>("#ah-key");
    if (key) form.keyId = key.value;
  };

  const render = () => {
    const k = selected();
    const needAck = !!k && !k.encrypted;
    const existing = keys.find((x) => x.id === form.keyId);
    const keyPart = form.mode === "existing"
      ? keys.length
        ? `<div class="field full"><label for="ah-key">Key</label><select id="ah-key">${keys.map((x) => `<option value="${esc(x.id)}" ${x.id === form.keyId ? "selected" : ""}>${esc(x.name)} · ${x.encrypted ? "passphrase" : "no passphrase"}</option>`).join("")}</select><span class="hint mono">${esc(existing?.id ?? "")}${existing ? ` · used by ${existing.hosts} host${existing.hosts === 1 ? "" : "s"}` : ""}</span></div>`
        : `<p class="fine full">No keys are configured yet. Upload one instead.</p>`
      : `<div class="field full"><label for="ah-file">Private key file</label><input id="ah-file" type="file">${form.file ? `<div class="keypick"><span>${esc(form.file.name)}</span><span class="mono">${form.file.encrypted ? "passphrase" : "no passphrase"}</span></div>` : ""}</div>`;
    const warn = needAck
      ? `<div class="alert full"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v5M12 18h.01"/></svg><div>This key has no passphrase. Anyone who signs in to Shellport can connect to this host without typing one.<label class="check"><input type="checkbox" id="ah-ack" ${form.ack ? "checked" : ""}> I understand, save it without a passphrase</label></div></div>`
      : "";
    const groups = opts.groups().map((g) => `<option value="${esc(g)}"></option>`).join("");
    scrim.innerHTML = `<form class="modal wide" id="ah-form" role="dialog" aria-modal="true" aria-labelledby="ah-title" novalidate>
      <h3 id="ah-title">Add host</h3>
      <p>Only admins can add hosts. Everyone signed in will see it in the sidebar.</p>
      <div class="form-body">
        <div class="field"><label for="ah-name">Name</label><input id="ah-name" value="${esc(form.name)}" placeholder="prod-web-03" autocomplete="off" maxlength="64"></div>
        <div class="field"><label for="ah-group">Group</label><input id="ah-group" list="ah-groups" value="${esc(form.group)}" placeholder="Production" autocomplete="off" maxlength="64"><datalist id="ah-groups">${groups}</datalist></div>
        <div class="field"><label for="ah-host">Host or IP</label><input id="ah-host" value="${esc(form.host)}" placeholder="10.0.1.14" autocomplete="off" autocapitalize="off" spellcheck="false"></div>
        <div class="field"><label for="ah-port">Port</label><input id="ah-port" value="${esc(form.port)}" inputmode="numeric" autocomplete="off"></div>
        <div class="field full"><label for="ah-user">User</label><input id="ah-user" value="${esc(form.user)}" placeholder="deploy" autocomplete="off" autocapitalize="off" spellcheck="false"></div>
        <div class="field full"><label id="ah-src-label">Key</label><div class="seg" role="group" aria-labelledby="ah-src-label"><button type="button" data-mode="existing" aria-pressed="${form.mode === "existing"}">Use existing key</button><button type="button" data-mode="upload" aria-pressed="${form.mode === "upload"}">Upload new key</button></div></div>
        ${keyPart}
        ${warn}
        <p class="fine full">${form.mode === "upload" ? "The key is stored encrypted in the vault, or in the keys folder next to config.json when the server is not sealed. " : ""}A key with a passphrase asks for it in the terminal each time you connect. It is never stored. The host's SSH key is read now and pinned.</p>
        <p class="form-err full" id="ah-err" role="alert" ${form.error ? "" : "hidden"}>${esc(form.error)}</p>
      </div>
      <div class="modal-foot"><button type="button" class="btn ghost" id="ah-cancel">Cancel</button><button type="submit" class="btn" id="ah-save" ${(needAck && !form.ack) || form.busy ? "disabled" : ""}>${form.busy ? "Adding…" : "Add host"}</button></div>
    </form>`;
  };

  const close = () => {
    if (scrim.hidden) return;
    scrim.hidden = true;
    scrim.innerHTML = "";
    opts.restoreFocus();
  };

  const open = async () => {
    form = { mode: "existing", name: "", group: "", host: "", port: "22", user: "", keyId: "", ack: false, error: "", busy: false };
    try {
      const r = await fetch("/api/keys", { credentials: "same-origin" });
      keys = r.ok ? await r.json() : [];
    } catch {
      keys = [];
    }
    form.keyId = keys[0]?.id ?? "";
    if (!keys.length) form.mode = "upload";
    render();
    scrim.hidden = false;
    scrim.querySelector<HTMLInputElement>("#ah-name")?.focus();
  };

  const submit = async () => {
    sync();
    const fail = (m: string) => { form.error = m; render(); };
    const name = form.name.trim(), host = form.host.trim(), user = form.user.trim();
    if (!name || !host || !user) return fail("Name, host and user are required.");
    const port = form.port.trim() || "22";
    if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) return fail("Port must be a number between 1 and 65535.");
    const k = selected();
    if (!k) return fail(form.mode === "existing" ? "Choose a key." : "Choose a key file to upload.");
    if (!k.encrypted && !form.ack) return fail("Confirm that you want to save a key without a passphrase.");
    const key = form.mode === "existing" ? { existing: form.keyId } : { upload: { name: form.file!.name, pem: form.file!.pem } };
    form.error = "";
    form.busy = true;
    render();
    let res: Response | undefined;
    try {
      res = await fetch("/api/hosts", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, group: form.group.trim(), host, port, username: user, key, allowNoPassphrase: form.ack }),
      });
    } catch {}
    form.busy = false;
    if (res?.status === 401) { location.reload(); return; }
    if (!res?.ok) {
      const body = res ? await res.json().catch(() => ({})) : {};
      return fail(typeof body.message === "string" ? body.message : res?.status === 429 ? "Too many attempts. Try again later." : "Could not add the host. Check your connection and try again.");
    }
    close();
    await opts.onAdded();
  };

  opts.button.addEventListener("click", () => { void open(); });

  scrim.addEventListener("click", (e) => {
    const t = e.target as HTMLElement;
    const mode = t.closest<HTMLElement>("[data-mode]")?.dataset.mode;
    if (mode === "existing" || mode === "upload") {
      sync();
      form.mode = mode;
      form.ack = false;
      form.error = "";
      render();
    } else if (t.id === "ah-cancel") close();
  });
  scrim.addEventListener("pointerdown", (e) => { if (e.target === scrim && !form.busy) close(); });
  scrim.addEventListener("keydown", (e) => { if (e.key === "Escape" && !form.busy) { e.preventDefault(); close(); } });
  scrim.addEventListener("submit", (e) => { e.preventDefault(); if (!form.busy) void submit(); });
  scrim.addEventListener("change", (e) => {
    const t = e.target as HTMLInputElement;
    if (t.id === "ah-key") { sync(); form.ack = false; form.error = ""; render(); }
    else if (t.id === "ah-ack") { sync(); form.ack = t.checked; form.error = ""; render(); }
    else if (t.id === "ah-file") {
      const f = t.files?.[0];
      sync();
      if (!f) return;
      if (f.size > MAX_KEY_BYTES) { form.file = undefined; return void (form.error = "That key file is too large.", render()); }
      void f.text().then((pem) => {
        form.file = { name: f.name, pem, encrypted: looksEncrypted(pem) };
        form.ack = false;
        form.error = "";
        render();
      });
    }
  });
}
