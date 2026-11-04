import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadSealedConfig, promoteFirstAdmin, type LoadedConfig } from "./config.js";
import { createApp } from "./app.js";
import { createSetupApp } from "./setup.js";
import { createUnsealApp } from "./unseal.js";
import { decideBoot } from "./boot.js";
import { socketPathFor } from "./vaultops.js";
import { vaultIo, vaultStore } from "./hostadmin.js";
import { passkeyStore } from "./passkeys.js";
import crypto from "node:crypto";
import { audit } from "./log.js";
import { AuditLog, fileSink } from "./auditlog.js";
import { RecordingStore } from "./recording.js";

const configPath = process.env.SHELLPORT_CONFIG ?? "config.json";
const vaultPath = process.env.SHELLPORT_VAULT ?? "vault.sealed";
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, "public");

function openAuditLog(cfg: LoadedConfig, vault: string, dek: Buffer): AuditLog {
  const file = process.env.SHELLPORT_AUDIT ?? path.join(path.dirname(path.resolve(vault)), "audit.log");
  const onError = (message: string) => audit("server.warning", { message: `the audit log cannot be saved to ${file} (${message}); it is kept in memory only. Set SHELLPORT_AUDIT to a writable file` });
  const retentionDays = cfg.limits.auditRetentionDays;
  try {
    return new AuditLog({ sink: fileSink(file, dek), retentionDays, onError });
  } catch (e) {
    onError((e as Error).message);
    return new AuditLog({ retentionDays });
  }
}

function openRecordings(cfg: LoadedConfig, vault: string, dek: Buffer): RecordingStore | undefined {
  if (!cfg.recording.enabled) return undefined;
  const dir = process.env.SHELLPORT_RECORDINGS ?? path.join(path.dirname(path.resolve(vault)), "recordings");
  const onError = (message: string) => audit("server.warning", { message: `session recording: ${message}` });
  const base = { dir, retentionDays: cfg.recording.retentionDays, maxBytes: cfg.recording.maxMB * 1024 * 1024, onError };
  // Recordings are only written when they can be encrypted in sealed mode. Otherwise sessions refuse to open.
  try {
    return new RecordingStore({ ...base, key: dek });
  } catch (e) {
    onError((e as Error).message);
    return new RecordingStore({ ...base, unavailable: (e as Error).message });
  }
}

function startApp(cfg: LoadedConfig, vault: string, dek: Buffer, unsealed = false) {
  const auditLog = openAuditLog(cfg, vault, dek);
  const recordings = openRecordings(cfg, vault, dek);
  if (unsealed) auditLog.add({ kind: "vault_unsealed", user: "", ip: "", detail: "Passphrase accepted on the unseal page" });
  const hostStore = vaultStore(vault, dek);
  const signals = ["SIGINT", "SIGTERM"] as const;
  const onSignal = (sig: (typeof signals)[number]) => shutdown(5000, sig).then(() => process.exit(0));
  let sealing = false;
  const { server, shutdown } = createApp(cfg, {
    publicDir,
    auditLog,
    hostStore,
    aiStore: vaultIo(vault, dek),
    recordings,
    passkeyStore: passkeyStore(vaultIo(vault, dek)),
    onSeal: () => {
      if (sealing) return;
      sealing = true;
      for (const sig of signals) process.off(sig, onSignal);
      shutdown(5000, "seal").then(() => {
        recordings?.stop();
        auditLog.stop();
        dek.fill(0);
        startSealed(vault, { port: cfg.server.port, host: cfg.server.host });
      });
    },
  });

  server.listen(cfg.server.port, cfg.server.host, () => {
    if (!cfg.users.some((u) => u.admin)) audit("server.notice", { message: "no user has admin: true; nobody can add hosts from the browser" });
    audit("server.start", { listen: `${cfg.server.host}:${cfg.server.port}`, publicUrl: cfg.server.publicUrl, hosts: cfg.hosts.length });
    if (cfg.security.allowUnpinnedHostKeys) audit("server.warning", { message: "allowUnpinnedHostKeys is on; do not use in production" });
    if (!cfg.server.publicUrl.startsWith("https://")) audit("server.warning", { message: "publicUrl is not https; cookies are not marked Secure" });
  });

  for (const sig of signals) process.on(sig, onSignal);
}

function startSetup() {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || "127.0.0.1";
  const token = crypto.randomBytes(32).toString("hex");

  let appStarted = false;
  const { server, shutdown } = createSetupApp({
    token,
    configPath,
    vaultPath,
    publicDir,
    trustProxy: trustProxyFromEnv(process.env.SHELLPORT_TRUST_PROXY),
    onSaved: (savedCfg, savedVault, savedDek) => {
      if (appStarted) return;
      appStarted = true;
      shutdown(1000, "setup.complete").then(() => startApp(savedCfg, savedVault, savedDek));
    },
  });

  server.listen(port, host, () => {
    audit("server.setup", { listen: `${host}:${port}`, configPath });
    console.log(`No vault found at ${vaultPath}. Starting setup wizard on http://${host === "0.0.0.0" ? "localhost" : host}:${port}`);
    console.log(`Setup code: ${token}`);
  });

  for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => shutdown(5000, sig).then(() => process.exit(0)));
}

function trustProxyFromEnv(value: string | undefined): boolean | number {
  if (!value || value === "false") return false;
  if (value === "true") return true;
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? n : false;
}

function startSealed(file: string, listen?: { port: number; host: string }) {
  const port = listen?.port ?? Number(process.env.PORT || 8080);
  const host = listen?.host ?? (process.env.HOST || "0.0.0.0");
  const signals = ["SIGINT", "SIGTERM"] as const;
  const onSignal = (sig: (typeof signals)[number]) => shutdown(5000, sig).then(() => process.exit(0));
  const { server, shutdown, listenSocket } = createUnsealApp({
    vaultPath: file,
    socketPath: socketPathFor(file),
    publicDir,
    trustProxy: trustProxyFromEnv(process.env.SHELLPORT_TRUST_PROXY),
    onUnsealed: (plaintext, dek) => {
      const cfg = loadSealedConfig(plaintext);
      const promoted = promoteFirstAdmin(cfg);
      return () => {
        if (promoted) audit("server.notice", { message: `the vault has no admin, so ${promoted} (the first user) is treated as admin` });
        for (const sig of signals) process.off(sig, onSignal);
        shutdown(1000, "unseal.complete").then(() => startApp(cfg, file, dek, true));
      };
    },
  });

  server.listen(port, host, () => {
    audit("server.sealed", { listen: `${host}:${port}`, vault: file });
    console.log(`Shellport is sealed. Open http://${host === "0.0.0.0" ? "localhost" : host}:${port} to unseal it.`);
    listenSocket();
  });

  for (const sig of signals) process.on(sig, onSignal);
}

function main() {
  const boot = decideBoot({ vaultPath, forceSetup: process.env.SHELLPORT_SETUP === "1" });
  if (boot.mode === "error") {
    console.error(boot.message);
    process.exit(1);
  } else if (boot.mode === "setup") {
    startSetup();
  } else if (boot.mode === "sealed") {
    startSealed(boot.vaultPath);
  }
}

main();
