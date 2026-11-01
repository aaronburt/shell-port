import "./setup.css";

interface SetupUser {
  id: string;
  github: string;
  secretType: "env" | "literal";
  secretValue: string;
  qrData?: string;
}

interface SetupHost {
  id: string;
  hostId: string;
  name: string;
  group: string;
  tag: string;
  host: string;
  port: number;
  username: string;
  authType: "key" | "password";
  keyPath: string;
  keyPassphraseType: "prompt" | "unencrypted" | "env";
  keyPassphraseEnv: string;
  passwordType: "env" | "literal";
  passwordValue: string;
  fingerprints: string;
  allowedUsers: string;
}

let usersState: SetupUser[] = [
  {
    id: "user-1",
    github: "",
    secretType: "literal",
    secretValue: "",
  },
];

let hostsState: SetupHost[] = [
  {
    id: "host-1",
    hostId: "primary-server",
    name: "Primary Server",
    group: "Servers",
    tag: "linux",
    host: "10.0.0.1",
    port: 22,
    username: "deploy",
    authType: "key",
    keyPath: "keys/shellport_ed25519",
    keyPassphraseType: "prompt",
    keyPassphraseEnv: "",
    passwordType: "env",
    passwordValue: "SHELLPORT_HOST_PASSWORD",
    fingerprints: "",
    allowedUsers: "",
  },
];

let targetConfigPath = "config.json";
let isWritable = false;

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function updateCallbackUrlPreview(): void {
  const urlInput = document.getElementById("srv-url") as HTMLInputElement | null;
  const targetCode = document.getElementById("oauth-callback-url");
  if (!urlInput || !targetCode) return;
  const origin = urlInput.value.replace(/\/+$/, "");
  targetCode.textContent = origin ? `${origin}/auth/github/callback` : "/auth/github/callback";
}

function renderUsers(): void {
  const container = document.getElementById("users-list");
  if (!container) return;
  container.innerHTML = "";

  usersState.forEach((user, index) => {
    const item = document.createElement("div");
    item.className = "item-box";
    item.innerHTML = `
      <div class="item-header">
        <span class="item-title">User #${index + 1}</span>
        ${usersState.length > 1 ? `<button type="button" class="btn small danger btn-remove-user" data-id="${user.id}">Remove</button>` : ""}
      </div>
      <div class="form-group">
        <label>GitHub Login or Numeric ID</label>
        <input type="text" class="user-github" data-id="${user.id}" value="${escapeHtml(user.github)}" placeholder="e.g. octocat or 583231" required>
      </div>
      <div class="form-group">
        <label>TOTP Secret Format</label>
        <div class="inline-radios">
          <label><input type="radio" name="user-sec-type-${user.id}" value="literal" ${user.secretType === "literal" ? "checked" : ""}> Generated Base32 Secret</label>
          <label><input type="radio" name="user-sec-type-${user.id}" value="env" ${user.secretType === "env" ? "checked" : ""}> Environment Variable</label>
        </div>
      </div>
      <div class="form-group">
        <label>${user.secretType === "literal" ? "Base32 Key (160-bit)" : "Environment Variable Name"}</label>
        <div class="grid" style="grid-template-columns: 1fr auto; gap: 8px;">
          <input type="${user.secretType === "literal" ? "text" : "text"}" class="user-secret-val" data-id="${user.id}" value="${escapeHtml(user.secretValue)}" placeholder="${user.secretType === "literal" ? "e.g. JBSWY3DPEHPK3PXP..." : "SHELLPORT_TOTP_USER"}">
          ${user.secretType === "literal" ? `<button type="button" class="btn small btn-gen-totp" data-id="${user.id}">Generate Key &amp; QR</button>` : ""}
        </div>
      </div>
      ${user.qrData ? `
        <div class="qr-preview">
          <img src="${user.qrData}" alt="TOTP QR Code" class="qr-img">
          <div class="qr-info">
            <span class="item-title">Scan in Authenticator App</span>
            <span class="hint">Secret key:</span>
            <code>${escapeHtml(user.secretValue)}</code>
          </div>
        </div>
      ` : ""}
    `;

    container.appendChild(item);
  });

  attachUserEvents();
  updateLiveJson();
}

function attachUserEvents(): void {
  document.querySelectorAll<HTMLInputElement>(".user-github").forEach((input) => {
    input.addEventListener("input", (e) => {
      const id = (e.target as HTMLElement).getAttribute("data-id");
      const user = usersState.find((u) => u.id === id);
      if (user) {
        user.github = (e.target as HTMLInputElement).value;
        updateLiveJson();
      }
    });
  });

  document.querySelectorAll<HTMLInputElement>(".user-secret-val").forEach((input) => {
    input.addEventListener("input", (e) => {
      const id = (e.target as HTMLElement).getAttribute("data-id");
      const user = usersState.find((u) => u.id === id);
      if (user) {
        user.secretValue = (e.target as HTMLInputElement).value;
        updateLiveJson();
      }
    });
  });

  document.querySelectorAll<HTMLInputElement>("input[name^='user-sec-type-']").forEach((radio) => {
    radio.addEventListener("change", (e) => {
      const target = e.target as HTMLInputElement;
      const id = target.name.replace("user-sec-type-", "");
      const user = usersState.find((u) => u.id === id);
      if (user && target.checked) {
        user.secretType = target.value as "env" | "literal";
        if (user.secretType === "env" && !user.secretValue) {
          user.secretValue = `SHELLPORT_TOTP_${(user.github || "USER").toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
        }
        renderUsers();
      }
    });
  });

  document.querySelectorAll<HTMLButtonElement>(".btn-remove-user").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-id");
      usersState = usersState.filter((u) => u.id !== id);
      renderUsers();
    });
  });

  document.querySelectorAll<HTMLButtonElement>(".btn-gen-totp").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-id");
      const user = usersState.find((u) => u.id === id);
      if (!user) return;
      btn.textContent = "Generating...";
      btn.disabled = true;
      try {
        const res = await fetch("/api/setup/totp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ account: user.github || "user" }),
        });
        if (res.ok) {
          const data = await res.json();
          user.secretValue = data.secret;
          user.qrData = data.qr;
          renderUsers();
        }
      } catch (err) {
        console.error(err);
      } finally {
        btn.textContent = "Generate Key & QR";
        btn.disabled = false;
      }
    });
  });
}

function renderHosts(): void {
  const container = document.getElementById("hosts-list");
  if (!container) return;
  container.innerHTML = "";

  hostsState.forEach((host, index) => {
    const item = document.createElement("div");
    item.className = "item-box";
    item.innerHTML = `
      <div class="item-header">
        <span class="item-title">Host #${index + 1}: ${escapeHtml(host.name || host.hostId)}</span>
        ${hostsState.length > 1 ? `<button type="button" class="btn small danger btn-remove-host" data-id="${host.id}">Remove</button>` : ""}
      </div>
      <div class="grid grid-2">
        <div class="form-group">
          <label>Host ID</label>
          <input type="text" class="host-id" data-id="${host.id}" value="${escapeHtml(host.hostId)}" placeholder="e.g. prod-server" required>
        </div>
        <div class="form-group">
          <label>Display Name</label>
          <input type="text" class="host-name" data-id="${host.id}" value="${escapeHtml(host.name)}" placeholder="e.g. Production Web">
        </div>
      </div>
      <div class="grid grid-2">
        <div class="form-group">
          <label>Group (Optional)</label>
          <input type="text" class="host-group" data-id="${host.id}" value="${escapeHtml(host.group)}" placeholder="e.g. Production">
        </div>
        <div class="form-group">
          <label>Tag (Optional)</label>
          <input type="text" class="host-tag" data-id="${host.id}" value="${escapeHtml(host.tag)}" placeholder="e.g. ubuntu">
        </div>
      </div>
      <div class="grid grid-2">
        <div class="form-group">
          <label>Host Address / IP</label>
          <input type="text" class="host-addr" data-id="${host.id}" value="${escapeHtml(host.host)}" placeholder="e.g. 10.0.1.10" required>
        </div>
        <div class="form-group">
          <label>SSH Port</label>
          <input type="number" class="host-port" data-id="${host.id}" value="${host.port}" min="1" max="65535" required>
        </div>
      </div>
      <div class="form-group">
        <label>SSH Username</label>
        <input type="text" class="host-user" data-id="${host.id}" value="${escapeHtml(host.username)}" placeholder="e.g. deploy or root" required>
      </div>
      <div class="form-group">
        <label>Authentication Method</label>
        <div class="inline-radios">
          <label><input type="radio" name="host-auth-type-${host.id}" value="key" ${host.authType === "key" ? "checked" : ""}> SSH Private Key</label>
          <label><input type="radio" name="host-auth-type-${host.id}" value="password" ${host.authType === "password" ? "checked" : ""}> Password</label>
        </div>
      </div>
      ${host.authType === "key" ? `
        <div class="form-group">
          <label>Private Key Path</label>
          <input type="text" class="host-key-path" data-id="${host.id}" value="${escapeHtml(host.keyPath)}" placeholder="keys/shellport_ed25519">
          <span class="hint">Relative to config.json or absolute path on container.</span>
        </div>
        <div class="form-group">
          <label>Key Passphrase Mode</label>
          <select class="host-key-pass" data-id="${host.id}">
            <option value="prompt" ${host.keyPassphraseType === "prompt" ? "selected" : ""}>User unlocks in browser upon connecting (Recommended)</option>
            <option value="unencrypted" ${host.keyPassphraseType === "unencrypted" ? "selected" : ""}>Unencrypted private key (passphrase: false)</option>
            <option value="env" ${host.keyPassphraseType === "env" ? "selected" : ""}>Stored in Environment Variable</option>
          </select>
        </div>
        ${host.keyPassphraseType === "env" ? `
          <div class="form-group">
            <label>Passphrase Environment Variable</label>
            <input type="text" class="host-key-pass-env" data-id="${host.id}" value="${escapeHtml(host.keyPassphraseEnv)}" placeholder="SHELLPORT_HOST_PASSPHRASE">
          </div>
        ` : ""}
      ` : `
        <div class="form-group">
          <label>Password Environment Variable</label>
          <input type="text" class="host-password-val" data-id="${host.id}" value="${escapeHtml(host.passwordValue)}" placeholder="SHELLPORT_PI_PASSWORD">
        </div>
      `}
      <div class="form-group">
        <label>Pinned Host Key Fingerprints</label>
        <textarea class="host-fingerprints" data-id="${host.id}" placeholder="SHA256:uN3k0p7bXz2QeV1sR8m4jH6tY9wC5aLd0fG/kE2rTqM">${escapeHtml(host.fingerprints)}</textarea>
        <span class="hint">One per line. Generate with: <code>ssh-keyscan -p ${host.port} ${host.host || "<host>"} | ssh-keygen -lf -</code></span>
      </div>
      <div class="form-group">
        <label>Allowed Users (Optional)</label>
        <input type="text" class="host-allowed-users" data-id="${host.id}" value="${escapeHtml(host.allowedUsers)}" placeholder="Comma-separated logins or IDs (empty allows all users)">
      </div>
    `;

    container.appendChild(item);
  });

  attachHostEvents();
  updateLiveJson();
}

function attachHostEvents(): void {
  const syncHostField = (selector: string, key: keyof SetupHost, isNumber = false) => {
    document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(selector).forEach((el) => {
      el.addEventListener("input", (e) => {
        const id = (e.target as HTMLElement).getAttribute("data-id");
        const host = hostsState.find((h) => h.id === id);
        if (host) {
          const val = (e.target as HTMLInputElement).value;
          (host as any)[key] = isNumber ? Number(val) : val;
          updateLiveJson();
        }
      });
    });
  };

  syncHostField(".host-id", "hostId");
  syncHostField(".host-name", "name");
  syncHostField(".host-group", "group");
  syncHostField(".host-tag", "tag");
  syncHostField(".host-addr", "host");
  syncHostField(".host-port", "port", true);
  syncHostField(".host-user", "username");
  syncHostField(".host-key-path", "keyPath");
  syncHostField(".host-key-pass-env", "keyPassphraseEnv");
  syncHostField(".host-password-val", "passwordValue");
  syncHostField(".host-fingerprints", "fingerprints");
  syncHostField(".host-allowed-users", "allowedUsers");

  document.querySelectorAll<HTMLSelectElement>(".host-key-pass").forEach((sel) => {
    sel.addEventListener("change", (e) => {
      const target = e.target as HTMLSelectElement;
      const id = target.getAttribute("data-id");
      const host = hostsState.find((h) => h.id === id);
      if (host) {
        host.keyPassphraseType = target.value as any;
        renderHosts();
      }
    });
  });

  document.querySelectorAll<HTMLInputElement>("input[name^='host-auth-type-']").forEach((radio) => {
    radio.addEventListener("change", (e) => {
      const target = e.target as HTMLInputElement;
      const id = target.name.replace("host-auth-type-", "");
      const host = hostsState.find((h) => h.id === id);
      if (host && target.checked) {
        host.authType = target.value as "key" | "password";
        renderHosts();
      }
    });
  });

  document.querySelectorAll<HTMLButtonElement>(".btn-remove-host").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-id");
      hostsState = hostsState.filter((h) => h.id !== id);
      renderHosts();
    });
  });
}

function buildConfigObject(): any {
  const srvPort = Number((document.getElementById("srv-port") as HTMLInputElement)?.value || 8080);
  const srvHost = (document.getElementById("srv-host") as HTMLInputElement)?.value || "0.0.0.0";
  const srvUrl = ((document.getElementById("srv-url") as HTMLInputElement)?.value || "").replace(/\/+$/, "");
  const proxyVal = (document.getElementById("srv-proxy") as HTMLSelectElement)?.value;
  const trustProxy = proxyVal === "true" ? true : proxyVal === "false" ? false : Number(proxyVal);

  const ghClientId = (document.getElementById("gh-client-id") as HTMLInputElement)?.value || "";
  const ghSecretType = (document.querySelector("input[name='ghSecretType']:checked") as HTMLInputElement)?.value;
  const ghSecretEnv = (document.getElementById("gh-secret-env") as HTMLInputElement)?.value || "SHELLPORT_GITHUB_SECRET";
  const ghSecretLit = (document.getElementById("gh-secret-lit") as HTMLInputElement)?.value || "";
  const githubSecret = ghSecretType === "literal" ? ghSecretLit : { env: ghSecretEnv };

  const users = usersState.map((u) => {
    const rawGh = u.github.trim();
    const github = /^\d+$/.test(rawGh) ? Number(rawGh) : rawGh;
    const totpSecret = u.secretType === "literal" ? u.secretValue.trim() : { env: u.secretValue.trim() };
    return { github, totpSecret };
  });

  const hosts = hostsState.map((h) => {
    const item: any = {
      id: h.hostId.trim() || "host",
      name: h.name.trim() || h.hostId.trim(),
      host: h.host.trim(),
      port: h.port || 22,
      username: h.username.trim(),
    };
    if (h.group.trim()) item.group = h.group.trim();
    if (h.tag.trim()) item.tag = h.tag.trim();

    if (h.authType === "password") {
      item.auth = {
        type: "password",
        password: { env: h.passwordValue.trim() || "SHELLPORT_PASSWORD" },
      };
    } else {
      const authKey: any = {
        type: "key",
        privateKey: { file: h.keyPath.trim() || "keys/shellport_ed25519" },
      };
      if (h.keyPassphraseType === "unencrypted") {
        authKey.passphrase = false;
      } else if (h.keyPassphraseType === "env") {
        authKey.passphrase = { env: h.keyPassphraseEnv.trim() || "SHELLPORT_PASSPHRASE" };
      }
      item.auth = authKey;
    }

    const fps = h.fingerprints.split("\n").map((f) => f.trim()).filter(Boolean);
    if (fps.length > 0) item.hostKeyFingerprints = fps;

    const allowed = h.allowedUsers.split(",").map((u) => u.trim()).filter(Boolean);
    if (allowed.length > 0) {
      item.allowedUsers = allowed.map((u) => (/^\d+$/.test(u) ? Number(u) : u));
    }

    return item;
  });

  const limTerminals = Number((document.getElementById("lim-terminals") as HTMLInputElement)?.value || 10);
  const limIdle = Number((document.getElementById("lim-idle") as HTMLInputElement)?.value || 30);
  const limAttempts = Number((document.getElementById("lim-attempts") as HTMLInputElement)?.value || 30);
  const limSession = Number((document.getElementById("lim-session") as HTMLInputElement)?.value || 12);
  const allowUnpinned = (document.getElementById("sec-unpinned") as HTMLInputElement)?.checked || false;

  return {
    server: {
      port: srvPort,
      host: srvHost,
      publicUrl: srvUrl,
      trustProxy,
    },
    github: {
      clientId: ghClientId,
      clientSecret: githubSecret,
    },
    users,
    session: {
      ttlHours: limSession,
    },
    limits: {
      maxTerminalsPerUser: limTerminals,
      idleTimeoutMinutes: limIdle,
      loginAttemptsPer15Min: limAttempts,
    },
    security: {
      allowUnpinnedHostKeys: allowUnpinned,
    },
    hosts,
  };
}

function updateLiveJson(): void {
  const preview = document.getElementById("json-preview");
  if (!preview) return;
  const cfg = buildConfigObject();
  preview.textContent = JSON.stringify(cfg, null, 2);
}

async function validateConfig(): Promise<boolean> {
  const errorBox = document.getElementById("validation-errors");
  const statusBox = document.getElementById("action-status");
  if (errorBox) errorBox.hidden = true;
  if (statusBox) statusBox.hidden = true;

  const cfg = buildConfigObject();
  try {
    const res = await fetch("/api/setup/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cfg),
    });
    const data = await res.json();
    if (!data.valid) {
      if (errorBox) {
        errorBox.innerHTML = `<strong>Configuration validation failed:</strong><ul style="margin: 4px 0 0 16px; padding: 0;">${data.errors.map((e: string) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>`;
        errorBox.hidden = false;
      }
      return false;
    }
    if (statusBox) {
      statusBox.textContent = "Configuration schema is valid!";
      statusBox.hidden = false;
    }
    return true;
  } catch (err) {
    if (errorBox) {
      errorBox.textContent = `Validation request error: ${(err as Error).message}`;
      errorBox.hidden = false;
    }
    return false;
  }
}

async function copyConfigJson(): Promise<void> {
  const cfg = buildConfigObject();
  const text = JSON.stringify(cfg, null, 2);
  await navigator.clipboard.writeText(text);
  const btn = document.getElementById("btn-copy") as HTMLButtonElement | null;
  if (btn) {
    const prev = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = prev;
    }, 2000);
  }
}

function downloadConfigJson(): void {
  const cfg = buildConfigObject();
  const blob = new Blob([JSON.stringify(cfg, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "config.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function saveConfig(): Promise<void> {
  const valid = await validateConfig();
  if (!valid) return;

  const errorBox = document.getElementById("validation-errors");
  const statusBox = document.getElementById("action-status");
  const btn = document.getElementById("btn-save") as HTMLButtonElement | null;

  if (btn) {
    btn.disabled = true;
    btn.textContent = "Saving...";
  }

  const cfg = buildConfigObject();
  const sealOn = (document.getElementById("seal-enable") as HTMLInputElement | null)?.checked;
  const pass = (document.getElementById("seal-pass") as HTMLInputElement | null)?.value ?? "";
  const pass2 = (document.getElementById("seal-pass2") as HTMLInputElement | null)?.value ?? "";
  if (sealOn && pass !== pass2) {
    if (errorBox) {
      errorBox.textContent = "The two passphrases do not match.";
      errorBox.hidden = false;
    }
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Save & Start Shellport";
    }
    return;
  }
  try {
    const res = await fetch("/api/setup/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(sealOn ? { config: cfg, passphrase: pass } : cfg),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      if (errorBox) {
        errorBox.innerHTML = `<strong>Save failed:</strong> ${escapeHtml(data.error || "Cannot save file.")}`;
        errorBox.hidden = false;
      }
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Save & Start Shellport";
      }
      return;
    }

    if (statusBox) {
      statusBox.textContent = data.canTransition
        ? "Configuration saved! Launching Shellport..."
        : "Configuration saved successfully!";
      statusBox.hidden = false;
    }

    if (data.canTransition) {
      setTimeout(() => {
        window.location.href = "/";
      }, 1500);
    }
  } catch (err) {
    if (errorBox) {
      errorBox.textContent = `Save error: ${(err as Error).message}`;
      errorBox.hidden = false;
    }
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Save & Start Shellport";
    }
  }
}

async function initSetup(): Promise<void> {
  const srvUrl = document.getElementById("srv-url") as HTMLInputElement | null;
  if (srvUrl && !srvUrl.value) {
    srvUrl.value = window.location.origin;
    updateCallbackUrlPreview();
  }

  srvUrl?.addEventListener("input", () => {
    updateCallbackUrlPreview();
    updateLiveJson();
  });

  try {
    const res = await fetch("/api/setup/status");
    if (res.ok) {
      const data = await res.json();
      targetConfigPath = data.configPath || "config.json";
      isWritable = Boolean(data.writable);

      const targetPathEl = document.getElementById("target-path");
      if (targetPathEl) targetPathEl.textContent = targetConfigPath;

      const notePath = document.getElementById("note-path");
      if (notePath) notePath.textContent = targetConfigPath;

      const saveBtn = document.getElementById("btn-save") as HTMLButtonElement | null;
      if (saveBtn && !isWritable) {
        saveBtn.title = "Target path is read-only. Download config.json instead.";
      }
    }
  } catch {
  }

  document.querySelectorAll("input[name='ghSecretType']").forEach((radio) => {
    radio.addEventListener("change", (e) => {
      const val = (e.target as HTMLInputElement).value;
      const envGrp = document.getElementById("gh-secret-env-group");
      const litGrp = document.getElementById("gh-secret-lit-group");
      if (envGrp && litGrp) {
        envGrp.hidden = val === "literal";
        litGrp.hidden = val !== "literal";
      }
      updateLiveJson();
    });
  });

  const form = document.getElementById("setup-form");
  form?.addEventListener("input", () => updateLiveJson());

  document.getElementById("btn-add-user")?.addEventListener("click", () => {
    usersState.push({
      id: `user-${Date.now()}`,
      github: "",
      secretType: "literal",
      secretValue: "",
    });
    renderUsers();
  });

  document.getElementById("btn-add-host")?.addEventListener("click", () => {
    hostsState.push({
      id: `host-${Date.now()}`,
      hostId: `host-${hostsState.length + 1}`,
      name: `Host ${hostsState.length + 1}`,
      group: "Servers",
      tag: "linux",
      host: "10.0.0.1",
      port: 22,
      username: "deploy",
      authType: "key",
      keyPath: "keys/shellport_ed25519",
      keyPassphraseType: "prompt",
      keyPassphraseEnv: "",
      passwordType: "env",
      passwordValue: "SHELLPORT_HOST_PASSWORD",
      fingerprints: "",
      allowedUsers: "",
    });
    renderHosts();
  });

  document.getElementById("btn-validate")?.addEventListener("click", validateConfig);
  document.getElementById("btn-copy")?.addEventListener("click", copyConfigJson);
  document.getElementById("btn-download")?.addEventListener("click", downloadConfigJson);
  document.getElementById("btn-save")?.addEventListener("click", saveConfig);
  document.getElementById("seal-enable")?.addEventListener("change", (e) => {
    const fields = document.getElementById("seal-fields");
    if (fields) fields.hidden = !(e.target as HTMLInputElement).checked;
  });

  renderUsers();
  renderHosts();
  updateLiveJson();
}

document.addEventListener("DOMContentLoaded", initSetup);
