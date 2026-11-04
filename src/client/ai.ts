export interface HostContext { os?: string; shell?: string; arch?: string; username?: string }
export interface AiTarget {
  context(): HostContext | undefined;
  terminalId(): string | undefined;
  output(): string;
  connected(): boolean;
  insert(text: string): void;
  focus(): void;
}

type Answer = { command: string; explanation: string; risks: string[] } | { raw: string };

type StepStatus = "ask" | "running" | "review" | "ran" | "skipped" | "withheld" | "blocked";
interface Step { command: string; why: string; status: StepStatus; reason?: string; output: string; exitCode: number | null; el: HTMLElement }
interface Run { prompt: string; terminalId: string; steps: Step[] }

const post = (url: string, body: object) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

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
  const modes = el("ai-modes"), modeS = el<HTMLButtonElement>("ai-mode-s"), modeI = el<HTMLButtonElement>("ai-mode-i"), opts = document.querySelector<HTMLElement>(".ai-opts")!;
  const inv = el("ai-inv"), invIntro = el("ai-inv-intro"), trail = el("ai-trail"), invCount = el("ai-inv-count"), stopBtn = el<HTMLButtonElement>("ai-inv-stop"), submit = el<HTMLButtonElement>("ai-submit");
  const investigateOn = el<HTMLInputElement>("ai-investigate"), timeoutSel = el<HTMLSelectElement>("ai-timeout"), ackInv = el<HTMLInputElement>("ai-ack-investigate");
  let available = false;
  let canInvestigate = false;
  let timeoutSec = 15;
  let mode: "suggest" | "investigate" = "suggest";
  let run: Run | undefined;
  row.hidden = !admin;
  async function refresh() {
    try {
      const r = await fetch("/api/ai/status");
      const s = r.ok ? await r.json() : {};
      available = s.enabled === true;
      canInvestigate = available && s.investigate === true;
      timeoutSec = Number(s.timeoutSec) || 15;
    } catch { available = false; canInvestigate = false; }
    button.hidden = !available;
    modes.hidden = !canInvestigate;
    if (!canInvestigate && mode === "investigate") setMode("suggest");
    if (!available) close();
  }
  void refresh();
  el("ai-settings-open").onclick = async () => {
    settingsMessage.textContent = ""; key.value = ""; ack.checked = false; ackInv.checked = false;
    try {
      const r = await fetch("/api/ai/settings");
      if (!r.ok) throw new Error();
      const s = await r.json();
      enabled.checked = s.enabled; url.value = s.baseUrl; model.value = s.model;
      investigateOn.checked = s.investigate === true; timeoutSel.value = String(s.timeoutSec);
      key.placeholder = s.hasKey ? "Leave blank to keep existing key" : "Enter LiteLLM gateway key";
      if (!s.available) settingsMessage.textContent = "Settings are unavailable on this server.";
    } catch { settingsMessage.textContent = "Could not load settings."; }
    settings.showModal();
  };
  el("ai-settings-close").onclick = () => settings.close();
  el<HTMLFormElement>("ai-settings-form").onsubmit = async (e) => {
    e.preventDefault();
    if (enabled.checked && !ack.checked) { settingsMessage.textContent = "Please acknowledge the risks before enabling AI."; return; }
    if (enabled.checked && investigateOn.checked && !ackInv.checked) { settingsMessage.textContent = "Please acknowledge that server output will be shared before enabling Investigate."; return; }
    try {
      const r = await fetch("/api/ai/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: enabled.checked, baseUrl: url.value, model: model.value, apiKey: key.value, acknowledge: ack.checked, investigate: investigateOn.checked, timeoutSec: Number(timeoutSel.value), acknowledgeInvestigate: ackInv.checked }) });
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
    endRun();
    setMode("suggest");
    ctx.checked = false; out.checked = false; answer.hidden = true; message.textContent = idle; paintOptions();
  }
  const sharing = "Your question, the host details (operating system, shell and username) and every output you approve are sent to the configured AI service.";
  function setMode(m: "suggest" | "investigate") {
    if (m === "investigate" && !canInvestigate) m = "suggest";
    if (run && m !== mode) return;
    mode = m;
    const i = m === "investigate";
    modeS.setAttribute("aria-pressed", String(!i)); modeI.setAttribute("aria-pressed", String(i));
    opts.hidden = i; inv.hidden = !i; preview.hidden = i || !out.checked; answer.hidden = true;
    submit.textContent = i ? "Investigate" : "Suggest";
    prompt.placeholder = i ? "What should I look into on this machine?" : "Describe what you want to do";
    if (i) {
      invIntro.textContent = `Reads from this machine with read-only commands. You approve every command and see each output before the AI does. Commands run in a separate channel, not in your terminal (${timeoutSec} s limit per command). Press Stop at any time.`;
      message.textContent = sharing;
    } else {
      message.textContent = idle;
      paintOptions();
    }
  }
  modeS.onclick = () => setMode("suggest");
  modeI.onclick = () => setMode("investigate");
  function endRun() {
    run = undefined;
    trail.replaceChildren();
    invCount.textContent = "";
    stopBtn.hidden = true;
    submit.disabled = false; prompt.disabled = false;
  }
  function count() {
    invCount.textContent = run && run.steps.length ? `${run.steps.length} step${run.steps.length === 1 ? "" : "s"}` : "";
  }
  const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = "", cls = "") => {
    const n = document.createElement(tag);
    if (text) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  };
  const button2 = (label: string, fn: () => void, primary = false) => {
    const b = node("button", label, primary ? "btn sm" : "btn ghost sm");
    b.type = "button"; b.onclick = fn;
    return b;
  };
  const TAGS: Record<StepStatus, string> = { ask: "Read-only check passed", running: "Running…", review: "Finished", ran: "Output sent to the AI", skipped: "Skipped by you", withheld: "Output kept private", blocked: "Blocked: not read-only" };
  function paint(r: Run, step: Step) {
    const e = step.el;
    e.className = `ai-step${["ask", "running", "review"].includes(step.status) ? " cur" : ""}${step.status === "blocked" ? " blocked" : ""}`;
    const head = node("div", "", "ai-step-head");
    head.append(node("span", `Step ${r.steps.indexOf(step) + 1}`), node("span", step.status === "review" && step.exitCode !== null ? `Finished · exit ${step.exitCode}` : TAGS[step.status], "ai-step-tag"));
    const kids: HTMLElement[] = [head, node("p", step.why), node("pre", `$ ${step.command}`)];
    if (step.status === "ask") {
      kids.push(node("small", `Runs with a ${timeoutSec} s limit and 4 KB of output. Nothing is typed into your terminal.`));
      const acts = node("div", "", "ai-step-actions");
      acts.append(button2("Run on this machine", () => void runStep(r, step), true), button2("Skip", () => skip(r, step)));
      kids.push(acts);
    } else if (step.status === "review") {
      const ta = node("textarea");
      ta.value = step.output; ta.spellcheck = false; ta.setAttribute("aria-label", "Output to send to the AI");
      kids.push(node("p", "This is what will be sent to the AI"), ta, node("small", "Edit out anything private first. Only this text is sent. Secrets in the output are not detected for you."));
      const acts = node("div", "", "ai-step-actions");
      acts.append(button2("Send to AI", () => { step.output = ta.value; step.status = "ran"; paint(r, step); void next(r); }, true), button2("Don’t send", () => { step.status = "withheld"; step.output = ""; paint(r, step); void next(r); }));
      kids.push(acts);
    } else if (step.status === "ran") {
      const d = node("details");
      d.append(node("summary", `Show what was sent (${step.output.length} characters)`), node("pre", step.output || "(no output)"));
      kids.push(d);
    } else if (step.status === "blocked") kids.push(node("small", `${step.reason ?? "This command is not allowed."} It was not run and the AI was told it is not allowed.`));
    e.replaceChildren(...kids);
    e.scrollIntoView?.({ block: "nearest" });
  }
  function addStep(r: Run, command: string, why: string, status: StepStatus, reason?: string) {
    const step: Step = { command, why, status, reason, output: "", exitCode: null, el: node("div") };
    r.steps.push(step);
    trail.append(step.el);
    paint(r, step);
    count();
    return step;
  }
  function skip(r: Run, step: Step) {
    step.status = "skipped"; paint(r, step); void next(r);
  }
  async function runStep(r: Run, step: Step) {
    step.status = "running"; paint(r, step);
    try {
      const res = await post("/api/ai/investigate/run", { terminalId: r.terminalId, command: step.command });
      if (run !== r) return;
      const body = await res.json().catch(() => ({}));
      if (res.status === 400 && body.error === "not_read_only") { step.status = "blocked"; step.reason = body.reason; paint(r, step); void next(r); return; }
      if (!res.ok) throw new Error();
      step.output = typeof body.output === "string" ? body.output + (body.truncated ? "\n[output truncated]" : "") + (body.timedOut ? "\n[timed out]" : "") : "";
      step.exitCode = typeof body.exitCode === "number" ? body.exitCode : null;
      step.status = "review"; paint(r, step);
    } catch {
      if (run !== r) return;
      step.status = "ask"; paint(r, step);
      message.textContent = "The command could not be run. The session may be busy or disconnected. Try again or skip it.";
    }
  }
  async function next(r: Run) {
    if (run !== r) return;
    message.textContent = "Asking the AI what to check next…";
    stopBtn.hidden = false;
    const t = target();
    const history = r.steps.filter((s) => ["ran", "skipped", "withheld", "blocked"].includes(s.status)).map((s) => ({ command: s.command, why: s.why, status: s.status, output: s.output, exitCode: s.exitCode }));
    const c = t?.context();
    try {
      const res = await post("/api/ai/investigate", { terminalId: r.terminalId, prompt: r.prompt, history, ...(c ? { context: c } : {}) });
      if (run !== r) return;
      if (!res.ok) throw new Error();
      const d = await res.json();
      if (d.type === "command") {
        addStep(r, d.command, d.why, d.allowed ? "ask" : "blocked", d.reason);
        if (d.allowed) { message.textContent = "Review the command, then run or skip it."; return; }
        void next(r);
        return;
      }
      finishRun("Review this suggestion before using it. Nothing has been run for you.", d);
    } catch {
      if (run !== r) return;
      finishRun("Could not reach the AI service. Check that AI is enabled and the LiteLLM service is available.");
    }
  }
  function finishRun(note: string, answerBody?: Answer) {
    stopBtn.hidden = true; submit.disabled = false; prompt.disabled = false;
    run = undefined;
    if (answerBody) show(answerBody);
    message.textContent = note;
  }
  function startRun() {
    const t = target();
    const id = t?.terminalId();
    if (!t || !id) { message.textContent = "Open a connected terminal to investigate that machine."; return; }
    endRun();
    answer.hidden = true;
    const r: Run = { prompt: prompt.value, terminalId: id, steps: [] };
    run = r;
    submit.disabled = true; prompt.disabled = true;
    count();
    void next(r);
  }
  stopBtn.onclick = () => {
    const r = run;
    if (!r) return;
    void post("/api/ai/investigate/stop", { terminalId: r.terminalId, step: r.steps.length }).catch(() => {});
    run = undefined;
    stopBtn.hidden = true; submit.disabled = false; prompt.disabled = false;
    trail.append(node("small", "Stopped. Nothing further was run or sent."));
    message.textContent = "Stopped.";
  };
  function open() {
    if (!available || !target()) return;
    reset();
    panel.hidden = false; button.setAttribute("aria-expanded", "true"); button.classList.add("on");
    prompt.focus();
  }
  function close() {
    const was = !panel.hidden;
    if (run) stopBtn.click();
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
    if (mode === "investigate") { startRun(); return; }
    const t = target();
    if (!t) return;
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
