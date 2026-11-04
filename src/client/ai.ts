export interface HostContext { os?: string; shell?: string; arch?: string; username?: string }
export interface AiTarget {
  context(): HostContext | undefined;
  output(): string;
  connected(): boolean;
  insert(text: string): void;
  focus(): void;
}

type Answer = { command: string; explanation: string; risks: string[] } | { raw: string };

export function initAi(admin: boolean, target: () => AiTarget | undefined) {
  const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const settings = el<HTMLDialogElement>("ai-settings"), dialog = el<HTMLDialogElement>("ai-dialog");
  const button = el<HTMLButtonElement>("ai-open"), row = el("ai-admin-row");
  const enabled = el<HTMLInputElement>("ai-enabled"), url = el<HTMLInputElement>("ai-url"), model = el<HTMLInputElement>("ai-model"), key = el<HTMLInputElement>("ai-key"), ack = el<HTMLInputElement>("ai-ack");
  const settingsMessage = el("ai-settings-message"), message = el("ai-message");
  const panel = el("ai-panel"), prompt = el<HTMLInputElement>("ai-prompt"), ctx = el<HTMLInputElement>("ai-ctx"), out = el<HTMLInputElement>("ai-out");
  const chip = el("ai-chip"), preview = el("ai-preview"), previewText = el("ai-preview-text");
  const answer = el("ai-answer"), cmd = el("ai-cmd"), explain = el("ai-explain"), risks = el("ai-risks");
  const copy = el<HTMLButtonElement>("ai-copy"), insert = el<HTMLButtonElement>("ai-insert");
  const idle = message.textContent ?? "";
  let available = false;
  row.hidden = !admin;
  async function refresh() {
    try { const r = await fetch("/api/ai/status"); available = r.ok && (await r.json()).enabled === true; }
    catch { available = false; }
    button.hidden = !available;
    if (!available) close();
  }
  void refresh();
  el("ai-settings-open").onclick = async () => {
    settingsMessage.textContent = ""; key.value = ""; ack.checked = false;
    try {
      const r = await fetch("/api/ai/settings");
      if (!r.ok) throw new Error();
      const s = await r.json();
      enabled.checked = s.enabled; url.value = s.baseUrl; model.value = s.model;
      key.placeholder = s.hasKey ? "Leave blank to keep existing key" : "Enter LiteLLM gateway key";
      if (!s.available) settingsMessage.textContent = "Settings are unavailable on this server.";
    } catch { settingsMessage.textContent = "Could not load settings."; }
    settings.showModal();
  };
  el("ai-settings-close").onclick = () => settings.close();
  el<HTMLFormElement>("ai-settings-form").onsubmit = async (e) => {
    e.preventDefault();
    if (enabled.checked && !ack.checked) { settingsMessage.textContent = "Please acknowledge the risks before enabling AI."; return; }
    try {
      const r = await fetch("/api/ai/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: enabled.checked, baseUrl: url.value, model: model.value, apiKey: key.value, acknowledge: ack.checked }) });
      if (!r.ok) { const b = await r.json(); settingsMessage.textContent = `Could not save settings (${b.error}). Check the URL, model and API key.`; return; }
      settings.close(); await refresh();
    } catch { settingsMessage.textContent = "Could not save settings."; }
  };
  const describe = (c: HostContext) => [c.os, c.shell, c.arch, c.username && `user ${c.username}`].filter(Boolean).join(" · ");
  function paintOptions() {
    const t = target();
    const c = t?.context();
    chip.hidden = !ctx.checked;
    chip.textContent = c ? `Sends: ${describe(c)}` : "Host details have not been detected for this session, so nothing will be sent.";
    preview.hidden = !out.checked;
    const o = out.checked ? t?.output() ?? "" : "";
    previewText.textContent = o || "No terminal output to send.";
  }
  function reset() {
    ctx.checked = false; out.checked = false; answer.hidden = true; message.textContent = idle; paintOptions();
  }
  function open() {
    if (!available || !target()) return;
    reset();
    panel.hidden = false; button.setAttribute("aria-expanded", "true"); button.classList.add("on");
    prompt.focus();
  }
  function close() {
    const was = !panel.hidden;
    panel.hidden = true; button.setAttribute("aria-expanded", "false"); button.classList.remove("on");
    if (was) target()?.focus();
  }
  button.onclick = () => (panel.hidden ? open() : close());
  el("ai-close").onclick = close;
  panel.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); } });
  ctx.onchange = out.onchange = paintOptions;
  let current: Answer | undefined;
  function show(a: Answer) {
    current = a;
    answer.hidden = false;
    risks.replaceChildren();
    if ("raw" in a) {
      cmd.textContent = a.raw; explain.textContent = ""; insert.disabled = true;
      insert.title = "The reply was not a single command, so it cannot be inserted";
      message.textContent = "The AI reply was not in the expected format. Review it carefully before using any of it.";
      return;
    }
    cmd.textContent = a.command; explain.textContent = a.explanation;
    for (const r of a.risks) { const li = document.createElement("li"); li.textContent = r; risks.append(li); }
    const multi = /[\r\n]/.test(a.command);
    insert.disabled = multi || !target()?.connected();
    insert.title = multi ? "Multi-line commands cannot be inserted. Copy and review it instead." : "";
    message.textContent = multi ? "This command spans several lines, so it can only be copied." : "Review this suggestion before using it. Nothing has been run.";
  }
  el<HTMLFormElement>("ai-form").onsubmit = async (e) => {
    e.preventDefault();
    const t = target();
    if (!t) return;
    const submit = el<HTMLButtonElement>("ai-submit");
    submit.disabled = true; message.textContent = "Requesting suggestion…"; answer.hidden = true;
    const body: { prompt: string; context?: HostContext; output?: string } = { prompt: prompt.value };
    if (ctx.checked) { const c = t.context(); if (c) body.context = c; }
    if (out.checked) { const o = t.output(); if (o) body.output = o; paintOptions(); }
    try {
      const r = await fetch("/api/ai/suggest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error();
      show(await r.json());
    } catch { message.textContent = "Could not get a suggestion. Check that AI is enabled and the LiteLLM service is available."; }
    finally { submit.disabled = false; }
  };
  copy.onclick = async () => {
    const text = current ? ("raw" in current ? current.raw : current.command) : "";
    try { await navigator.clipboard.writeText(text); message.textContent = "Copied."; } catch { message.textContent = "Copy failed; select the text to copy it."; }
  };
  insert.onclick = () => {
    if (!current || "raw" in current || /[\r\n]/.test(current.command)) return;
    const t = target();
    if (!t?.connected()) return;
    t.insert(current.command);
    message.textContent = "Inserted at the prompt. Press Enter in the terminal to run it.";
    t.focus();
  };
  return { toggle: () => (panel.hidden ? open() : close()), refresh: () => { if (!panel.hidden) paintOptions(); } };
}
