export interface HostContext { os?: string; shell?: string; arch?: string; username?: string }
export interface AiTarget {
  key: object;
  label: string;
  multi: boolean;
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
interface Run { prompt: string; terminalId: string; target: AiTarget; turn: Turn; steps: Step[]; trail: HTMLElement; count: HTMLElement; stop: HTMLButtonElement }
interface Turn { target: AiTarget; ans: HTMLElement; moved?: HTMLElement; command?: string }

const post = (url: string, body: object) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export function initAi(admin: boolean, target: () => AiTarget | undefined) {
  const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const settings = el<HTMLDialogElement>("ai-settings"), dialog = el<HTMLDialogElement>("ai-dialog");
  const button = el<HTMLButtonElement>("ai-open"), row = el("ai-admin-row");
  const enabled = el<HTMLInputElement>("ai-enabled"), url = el<HTMLInputElement>("ai-url"), model = el<HTMLInputElement>("ai-model"), key = el<HTMLInputElement>("ai-key"), ack = el<HTMLInputElement>("ai-ack");
  const settingsMessage = el("ai-settings-message"), message = el("ai-message");
  const panel = el("ai-panel"), prompt = el<HTMLInputElement>("ai-prompt"), ctx = el<HTMLInputElement>("ai-ctx"), out = el<HTMLInputElement>("ai-out");
  const chip = el("ai-chip"), preview = el("ai-preview"), previewText = el("ai-preview-text");
  const idle = message.textContent ?? "";
  const modes = el("ai-modes"), modeS = el<HTMLButtonElement>("ai-mode-s"), modeI = el<HTMLButtonElement>("ai-mode-i"), opts = el("ai-opts");
  const invIntro = el("ai-inv-intro"), submit = el<HTMLButtonElement>("ai-submit");
  const ctxChip = el<HTMLButtonElement>("ai-ctxchip"), ctxSum = el("ai-ctxsum"), targetLine = el("ai-target");
  const scroller = el("ai-scroll"), thread = el("ai-thread"), empty = el("ai-empty"), clear = el<HTMLButtonElement>("ai-clear"), grip = el("ai-grip");
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
    if (!available) shutdown();
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
  const turns: Turn[] = [];
  const earlier: { prompt: string; mode: "suggest" | "investigate" }[] = [];
  const toBottom = () => { scroller.scrollTop = scroller.scrollHeight; };
  function paintOptions() {
    const t = target();
    const c = t?.context();
    chip.hidden = !ctx.checked;
    chip.textContent = c ? `Sends: ${describe(c)}` : "Host details have not been detected for this session, so nothing will be sent.";
    preview.hidden = !out.checked;
    const o = out.checked ? t?.output() ?? "" : "";
    previewText.textContent = o || "No terminal output to send.";
    ctxSum.textContent = [ctx.checked && "host", out.checked && "last output"].filter(Boolean).join(" · ") || "none";
  }
  function paintTarget() {
    const t = target();
    targetLine.replaceChildren();
    if (!t) { targetLine.textContent = "Open a terminal to ask about it."; return; }
    const who = node("span", "New questions go to ");
    who.append(node("b", t.label));
    if (t.multi) who.append(" · the focused pane");
    targetLine.append(node("span", "", "ai-dot"), who);
  }
  function paintMoved(turn: Turn) {
    if (!turn.moved || !turn.command) return;
    const t = target();
    if (!t || t.key === turn.target.key) { turn.moved.hidden = true; return; }
    turn.moved.hidden = false;
    turn.moved.replaceChildren("Focus is now on ", node("b", t.label), ". Insert still goes to ", node("b", turn.target.label), ", where this was asked.");
  }
  const EXAMPLES: [RegExp, [string, string][]][] = [
    [/freebsd|bsd/i, [["Show ZFS pool health", "zpool status"], ["Which jails are running?", "jls"], ["Which services start at boot?", "rc.conf, service"]]],
    [/alpine/i, [["Which packages are installed?", "apk"], ["Which process is listening on port 443?", "netstat"], ["Free memory by process", "ps, sort"]]],
    [/raspbian|raspberry/i, [["What is the CPU temperature?", "vcgencmd"], ["Is the SD card filling up?", "df"], ["Which USB devices are attached?", "lsusb"]]],
    [/ubuntu|debian|mint/i, [["Which service is listening on port 443?", "ss, systemd"], ["Show the 10 largest files under /var", "du, sort"], ["Which apt upgrades are pending?", "apt"]]],
    [/rhel|red hat|centos|rocky|alma|fedora|amazon/i, [["Which service is listening on port 443?", "ss, systemd"], ["Show the 10 largest files under /var", "du, sort"], ["Which dnf updates are pending?", "dnf"]]],
    [/darwin|mac/i, [["Which process is listening on port 443?", "lsof"], ["Show the 10 largest files in my home folder", "du, sort"], ["How much disk space is free?", "df"]]],
  ];
  const GENERIC: [string, string][] = [["Which process is listening on port 443?", "ss, netstat"], ["Show the 10 largest files under /var", "du, sort"], ["How much disk space is free?", "df"]];
  const INV_EXAMPLES: [string, string][] = [["Why is the disk almost full?", "disk usage"], ["Why is load so high right now?", "processes, I/O"], ["Why did a service fail to start?", "journal, unit status"]];
  function paintEmpty() {
    empty.hidden = turns.length > 0;
    clear.hidden = turns.length === 0 || !!run;
    if (empty.hidden) return;
    const c = target()?.context();
    const i = mode === "investigate";
    const os = c?.os ?? "";
    const list = i ? INV_EXAMPLES : (EXAMPLES.find(([re]) => re.test(os))?.[1] ?? GENERIC);
    const kids: HTMLElement[] = [node("h5", (i ? "Ask about this machine" : "Try asking") + (os ? ` · ${os}` : ""))];
    for (const [q, hint] of list) {
      const b = node("button", q, "ai-ex"); b.type = "button";
      b.append(node("small", hint));
      b.onclick = () => { prompt.value = q; prompt.focus(); };
      kids.push(b);
    }
    if (earlier.length) {
      const d = node("details", "", "ai-earlier");
      d.append(node("summary", `Earlier questions (${earlier.length})`));
      for (const e of earlier) {
        const b = node("button", e.prompt, "ai-ex"); b.type = "button";
        b.append(node("small", e.mode === "investigate" ? "Investigate" : "Suggest"));
        b.onclick = () => { setMode(e.mode); prompt.value = e.prompt; prompt.focus(); };
        d.append(b);
      }
      kids.push(d);
    }
    empty.replaceChildren(...kids);
  }
  function repaint() {
    paintTarget();
    if (mode === "suggest") paintOptions();
    for (const t of turns) paintMoved(t);
    paintEmpty();
  }
  const sharing = "Your question, the host details (operating system, shell and username) and every output you approve are sent to the configured AI service.";
  function setMode(m: "suggest" | "investigate") {
    if (m === "investigate" && !canInvestigate) m = "suggest";
    if (run && m !== mode) return;
    mode = m;
    const i = m === "investigate";
    modeS.setAttribute("aria-pressed", String(!i)); modeI.setAttribute("aria-pressed", String(i));
    ctxChip.hidden = i; if (i) { opts.hidden = true; ctxChip.setAttribute("aria-expanded", "false"); }
    invIntro.hidden = !i;
    submit.textContent = i ? "Investigate" : "Suggest";
    prompt.placeholder = i ? "What should I look into on this machine?" : "Describe what you want to do";
    if (i) {
      invIntro.textContent = `Read-only commands only. You approve each one and see its output before the AI does. They run in a separate channel, not in your terminal (${timeoutSec} s limit each).`;
      message.textContent = sharing;
    } else {
      message.textContent = idle;
      paintOptions();
    }
    paintEmpty();
  }
  modeS.onclick = () => setMode("suggest");
  modeI.onclick = () => setMode("investigate");
  ctxChip.onclick = () => { opts.hidden = !opts.hidden; ctxChip.setAttribute("aria-expanded", String(!opts.hidden)); };
  function syncBadge() {
    const waiting = !!run && panel.hidden && run.steps.some((s) => s.status === "ask" || s.status === "review");
    let b = button.querySelector<HTMLElement>(".ai-badge");
    if (waiting && !b) { b = node("span", "1", "ai-badge"); b.setAttribute("aria-hidden", "true"); button.append(b); }
    if (!waiting && b) b.remove();
    button.title = waiting ? "Ask AI: an Investigate step is waiting for you (Alt Shift A)" : "Ask AI (Alt Shift A)";
    button.setAttribute("aria-label", waiting ? "Ask AI, a step is waiting for your approval" : "Ask AI");
  }
  function addTurn(text: string, t: AiTarget, m: "suggest" | "investigate"): Turn {
    const wrap = node("div", "", "ai-turn");
    const meta = node("div", "", "ai-meta");
    const forWho = node("span", "for ");
    forWho.append(node("b", t.label));
    meta.append(node("span", "", "ai-dot"), forWho, node("span", m === "investigate" ? "Investigate" : "Suggest", "ai-mode-tag"));
    const ans = node("div", "", "ai-ans");
    wrap.append(node("div", text, "ai-q"), meta, ans);
    thread.append(wrap);
    const turn: Turn = { target: t, ans };
    turns.push(turn);
    earlier.unshift({ prompt: text, mode: m });
    if (earlier.length > 10) earlier.pop();
    paintEmpty();
    toBottom();
    return turn;
  }
  function renderAnswer(turn: Turn, a: Answer, into: HTMLElement) {
    const kids: HTMLElement[] = [];
    if ("raw" in a) {
      kids.push(node("pre", a.raw, "ai-cmd"), node("p", "The AI reply was not in the expected format. Review it carefully before using any of it."));
    } else {
      kids.push(node("pre", a.command, "ai-cmd"));
      if (a.explanation) kids.push(node("p", a.explanation));
      const ul = node("ul", "", "ai-risks");
      for (const r of a.risks) ul.append(node("li", r));
      kids.push(ul);
    }
    const command = "raw" in a ? a.raw : a.command;
    const multi = "raw" in a || /[\r\n]/.test(a.command);
    turn.command = command;
    const moved = node("p", "", "ai-moved"); moved.hidden = true; turn.moved = moved;
    const done = node("p", "", "ai-done"); done.hidden = true;
    const ins = button2(`Insert into ${turn.target.label}`, () => {
      if (multi || !turn.target.connected()) return;
      turn.target.insert(command);
      done.hidden = false;
      const here = target()?.key === turn.target.key;
      done.textContent = here ? "Inserted at the prompt. Press Enter in the terminal to run it." : `Inserted at the ${turn.target.label} prompt. Switch to it and press Enter to run it.`;
      if (here) turn.target.focus();
    });
    ins.disabled = multi || !turn.target.connected();
    ins.title = "raw" in a ? "The reply was not a single command, so it cannot be inserted" : multi ? "Multi-line commands cannot be inserted. Copy and review it instead." : "";
    const cp = button2("Copy", async () => {
      done.hidden = false;
      try { await navigator.clipboard.writeText(command); done.textContent = "Copied."; } catch { done.textContent = "Copy failed; select the text to copy it."; }
    });
    const acts = node("div", "", "ai-acts");
    acts.append(ins, cp);
    kids.push(moved, acts, done);
    into.append(...kids);
    paintMoved(turn);
    message.textContent = "raw" in a ? "Review the reply carefully before using any of it." : multi ? "This command spans several lines, so it can only be copied." : "Review this suggestion before using it. Nothing has been run.";
    toBottom();
  }
  const wait = (text: string) => { const w = node("div", "", "ai-wait"); w.append(node("span", "", "ai-spin"), node("span", text)); return w; };
  function count(r: Run) {
    r.count.textContent = r.steps.length ? `${r.steps.length} step${r.steps.length === 1 ? "" : "s"}` : "";
  }
  const TAGS: Record<StepStatus, string> = { ask: "Read-only check passed", running: "Running…", review: "Finished", ran: "Output sent to the AI", skipped: "Skipped by you", withheld: "Output kept private", blocked: "Blocked: not read-only" };
  function paint(r: Run, step: Step) {
    const e = step.el;
    e.className = `ai-step${["ask", "running", "review"].includes(step.status) ? " cur" : ""}${step.status === "blocked" ? " blocked" : ""}`;
    const head = node("div", "", "ai-step-head");
    head.append(node("span", `Step ${r.steps.indexOf(step) + 1}`), node("span", step.status === "review" && step.exitCode !== null ? `Finished · exit ${step.exitCode}` : TAGS[step.status], "ai-step-tag"));
    const kids: HTMLElement[] = [head, node("p", step.why), node("pre", `$ ${step.command}`)];
    if (step.status === "ask") {
      kids.push(node("small", `Runs on ${r.target.label} with a ${timeoutSec} s limit and 4 KB of output. Nothing is typed into your terminal.`));
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
    if (!panel.hidden) toBottom();
    syncBadge();
  }
  function addStep(r: Run, command: string, why: string, status: StepStatus, reason?: string) {
    const step: Step = { command, why, status, reason, output: "", exitCode: null, el: node("div") };
    r.steps.push(step);
    r.trail.append(step.el);
    paint(r, step);
    count(r);
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
    const thinking = wait("Asking the AI what to check next…");
    r.trail.append(thinking);
    toBottom();
    const history = r.steps.filter((s) => ["ran", "skipped", "withheld", "blocked"].includes(s.status)).map((s) => ({ command: s.command, why: s.why, status: s.status, output: s.output, exitCode: s.exitCode }));
    const c = r.target.context();
    try {
      const res = await post("/api/ai/investigate", { terminalId: r.terminalId, prompt: r.prompt, history, ...(c ? { context: c } : {}) });
      thinking.remove();
      if (run !== r) return;
      if (!res.ok) throw new Error();
      const d = await res.json();
      if (d.type === "command") {
        addStep(r, d.command, d.why, d.allowed ? "ask" : "blocked", d.reason);
        if (d.allowed) { message.textContent = "Review the command, then run or skip it."; return; }
        void next(r);
        return;
      }
      finishRun(r, "Review this suggestion before using it. Nothing has been run for you.", d);
    } catch {
      thinking.remove();
      if (run !== r) return;
      finishRun(r, "Could not reach the AI service. Check that AI is enabled and the LiteLLM service is available.");
    }
  }
  function endRun(r: Run, foot: string) {
    r.stop.remove();
    r.count.textContent = [r.count.textContent, foot].filter(Boolean).join(" · ");
    run = undefined;
    submit.disabled = false; prompt.disabled = false; modeS.disabled = false; modeI.disabled = false;
    paintEmpty(); syncBadge();
  }
  function finishRun(r: Run, note: string, answerBody?: Answer) {
    endRun(r, answerBody ? "Done" : "Ended");
    if (answerBody) {
      const box = node("div", "", "ai-final");
      r.turn.ans.append(box);
      renderAnswer(r.turn, answerBody, box);
      if (!("raw" in answerBody)) box.append(node("p", "Not run. Press Enter in the terminal yourself to run it."));
    }
    if (!answerBody || !("raw" in answerBody)) message.textContent = note;
  }
  function stopRun() {
    const r = run;
    if (!r) return;
    void post("/api/ai/investigate/stop", { terminalId: r.terminalId, step: r.steps.length }).catch(() => {});
    r.trail.querySelector(".ai-wait")?.remove();
    r.trail.append(node("small", "Stopped. Nothing further was run or sent."));
    endRun(r, "Stopped");
    message.textContent = "Stopped.";
  }
  function startRun(t: AiTarget) {
    const id = t.terminalId();
    if (!id) { message.textContent = "Open a connected terminal to investigate that machine."; return; }
    const turn = addTurn(prompt.value, t, "investigate");
    const trail = node("div", "", "ai-trail");
    const foot = node("div", "", "ai-inv-foot");
    const cnt = node("span");
    const stop = button2("Stop", stopRun);
    stop.classList.add("ai-stop");
    foot.append(cnt, stop);
    turn.ans.append(trail, foot);
    const r: Run = { prompt: prompt.value, terminalId: id, target: t, turn, steps: [], trail, count: cnt, stop };
    run = r;
    prompt.value = "";
    submit.disabled = true; prompt.disabled = true; modeS.disabled = true; modeI.disabled = true; clear.hidden = true;
    void next(r);
  }
  clear.onclick = () => {
    if (run) return;
    turns.length = 0;
    thread.replaceChildren();
    message.textContent = mode === "investigate" ? sharing : idle;
    paintEmpty();
    prompt.focus();
  };
  const wrap = panel.parentElement!;
  const MIN = 320, MAX = 720, DEF = 380;
  const fit = (w: number) => Math.round(Math.max(MIN, Math.min(MAX, wrap.clientWidth - 240, w)));
  function setWidth(w: number, save = true) {
    panel.style.width = `${fit(w)}px`;
    if (save) { try { localStorage.setItem("sp.aiWidth", String(fit(w))); } catch {} }
  }
  try { const w = Number(localStorage.getItem("sp.aiWidth")); if (w) panel.style.width = `${Math.max(MIN, Math.min(MAX, w))}px`; } catch {}
  grip.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    grip.setPointerCapture(e.pointerId);
    grip.classList.add("drag"); panel.classList.add("resizing");
    const x0 = e.clientX, w0 = panel.offsetWidth;
    const move = (ev: PointerEvent) => setWidth(w0 + (x0 - ev.clientX));
    const up = () => { grip.classList.remove("drag"); panel.classList.remove("resizing"); grip.removeEventListener("pointermove", move); grip.removeEventListener("pointerup", up); grip.removeEventListener("pointercancel", up); };
    grip.addEventListener("pointermove", move); grip.addEventListener("pointerup", up); grip.addEventListener("pointercancel", up);
  });
  grip.addEventListener("dblclick", () => setWidth(DEF));
  grip.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") { e.preventDefault(); setWidth(panel.offsetWidth + (e.key === "ArrowLeft" ? 24 : -24)); }
  });
  function open() {
    if (!available) return;
    if (!target() && !turns.length) return;
    panel.hidden = false; wrap.classList.add("ai-on");
    button.setAttribute("aria-expanded", "true"); button.classList.add("on");
    if (panel.style.width) setWidth(parseInt(panel.style.width, 10), false);
    if (!run) setMode(mode);
    repaint(); syncBadge(); toBottom();
    if (!prompt.disabled) prompt.focus();
  }
  function close() {
    const was = !panel.hidden;
    panel.hidden = true; wrap.classList.remove("ai-on");
    button.setAttribute("aria-expanded", "false"); button.classList.remove("on");
    syncBadge();
    if (was) target()?.focus();
  }
  function shutdown() {
    stopRun();
    close();
  }
  button.onclick = () => (panel.hidden ? open() : close());
  el("ai-close").onclick = close;
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || panel.hidden || e.defaultPrevented) return;
    const f = document.activeElement;
    if (f && f !== document.body && !panel.contains(f)) return;
    e.preventDefault(); close();
  });
  ctx.onchange = out.onchange = paintOptions;
  el<HTMLFormElement>("ai-form").onsubmit = async (e) => {
    e.preventDefault();
    const t = target();
    if (!t) { message.textContent = "Open a terminal first."; return; }
    if (mode === "investigate") { startRun(t); return; }
    const text = prompt.value;
    const body: { prompt: string; context?: HostContext; output?: string } = { prompt: text };
    if (ctx.checked) { const c = t.context(); if (c) body.context = c; }
    if (out.checked) { const o = t.output(); if (o) body.output = o; paintOptions(); }
    const turn = addTurn(text, t, "suggest");
    prompt.value = "";
    submit.disabled = true; message.textContent = "Requesting suggestion…";
    const w = wait("Requesting suggestion…");
    turn.ans.append(w);
    try {
      const r = await fetch("/api/ai/suggest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error();
      const a = await r.json();
      w.remove();
      renderAnswer(turn, a, turn.ans);
    } catch {
      w.remove();
      turn.ans.append(node("p", "Could not get a suggestion."));
      message.textContent = "Could not get a suggestion. Check that AI is enabled and the LiteLLM service is available.";
    }
    finally { submit.disabled = false; }
  };
  setMode("suggest");
  return { toggle: () => (panel.hidden ? open() : close()), refresh: () => { if (!panel.hidden) repaint(); } };
}
