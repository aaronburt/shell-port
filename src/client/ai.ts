export function initAi(admin: boolean) {
  const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const settings = el<HTMLDialogElement>("ai-settings"), dialog = el<HTMLDialogElement>("ai-dialog");
  const button = el<HTMLButtonElement>("ai-open"), row = el("ai-admin-row");
  const enabled = el<HTMLInputElement>("ai-enabled"), url = el<HTMLInputElement>("ai-url"), model = el<HTMLInputElement>("ai-model"), key = el<HTMLInputElement>("ai-key"), ack = el<HTMLInputElement>("ai-ack");
  const settingsMessage = el("ai-settings-message"), message = el("ai-message"), result = el<HTMLPreElement>("ai-result"), copy = el<HTMLButtonElement>("ai-copy");
  row.hidden = !admin;
  async function refresh() {
    try { const r = await fetch("/api/ai/status"); button.hidden = !r.ok || !(await r.json()).enabled; }
    catch { button.hidden = true; }
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
  button.onclick = () => { message.textContent = ""; result.hidden = true; copy.hidden = true; dialog.showModal(); };
  el("ai-close").onclick = () => dialog.close();
  el<HTMLFormElement>("ai-form").onsubmit = async (e) => {
    e.preventDefault();
    const submit = el<HTMLButtonElement>("ai-submit"); submit.disabled = true; message.textContent = "Requesting suggestion…"; result.hidden = true; copy.hidden = true;
    try {
      const r = await fetch("/api/ai/suggest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt: el<HTMLTextAreaElement>("ai-prompt").value }) });
      if (!r.ok) throw new Error();
      result.textContent = (await r.json()).suggestion; result.hidden = false; copy.hidden = false; message.textContent = "Review this suggestion before using it.";
    } catch { message.textContent = "Could not get a suggestion. Check that AI is enabled and the LiteLLM service is available."; }
    finally { submit.disabled = false; }
  };
  copy.onclick = async () => { try { await navigator.clipboard.writeText(result.textContent ?? ""); message.textContent = "Suggestion copied."; } catch { message.textContent = "Copy failed; select the text to copy it."; } };
}
