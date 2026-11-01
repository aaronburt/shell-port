import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, loadSealedConfig, type LoadedConfig } from "./config.js";
import { createApp } from "./app.js";
import { createSetupApp } from "./setup.js";
import { createUnsealApp } from "./unseal.js";
import { decideBoot } from "./boot.js";
import { socketPathFor } from "./vaultops.js";
import { createMigrateApp } from "./migrate.js";
import crypto from "node:crypto";
import { audit } from "./log.js";

const configPath = process.env.SHELLPORT_CONFIG ?? "config.json";
const vaultPath = process.env.SHELLPORT_VAULT ?? "vault.sealed";
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, "public");

function startApp(cfg: LoadedConfig, vault?: string) {
  const signals = ["SIGINT", "SIGTERM"] as const;
  const onSignal = (sig: (typeof signals)[number]) => shutdown(5000, sig).then(() => process.exit(0));
  let sealing = false;
  const { server, shutdown } = createApp(cfg, {
    publicDir,
    onSeal: vault
      ? () => {
          if (sealing) return;
          sealing = true;
          for (const sig of signals) process.off(sig, onSignal);
          shutdown(5000, "seal").then(() => startSealed(vault, { port: cfg.server.port, host: cfg.server.host }));
        }
      : undefined,
  });

  server.listen(cfg.server.port, cfg.server.host, () => {
    audit("server.start", { listen: `${cfg.server.host}:${cfg.server.port}`, publicUrl: cfg.server.publicUrl, hosts: cfg.hosts.length });
    if (cfg.security.allowUnpinnedHostKeys) audit("server.warning", { message: "allowUnpinnedHostKeys is on; do not use in production" });
    if (!cfg.server.publicUrl.startsWith("https://")) audit("server.warning", { message: "publicUrl is not https; cookies are not marked Secure" });
  });

  for (const sig of signals) process.on(sig, onSignal);
}

function startSetup() {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || "0.0.0.0";

  let appStarted = false;
  const { server, shutdown } = createSetupApp({
    configPath,
    vaultPath,
    publicDir,
    trustProxy: trustProxyFromEnv(process.env.SHELLPORT_TRUST_PROXY),
    onSaved: (savedCfg, savedVault) => {
      if (appStarted) return;
      appStarted = true;
      shutdown(1000, "setup.complete").then(() => startApp(savedCfg, savedVault));
    },
  });

  server.listen(port, host, () => {
    audit("server.setup", { listen: `${host}:${port}`, configPath });
    console.log(`No configuration file found at ${configPath}. Starting setup wizard on http://${host === "0.0.0.0" ? "localhost" : host}:${port}`);
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
    onUnsealed: (plaintext) => {
      const cfg = loadSealedConfig(plaintext);
      return () => {
        for (const sig of signals) process.off(sig, onSignal);
        shutdown(1000, "unseal.complete").then(() => startApp(cfg, file));
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

function startMigrate(cfg: LoadedConfig) {
  const port = Number(process.env.PORT || cfg.server.port);
  const host = process.env.HOST || cfg.server.host;
  const token = crypto.randomBytes(16).toString("hex");
  const signals = ["SIGINT", "SIGTERM"] as const;
  const onSignal = (sig: (typeof signals)[number]) => shutdown(5000, sig).then(() => process.exit(0));
  let handedOver = false;
  const handOver = (next: () => void) => {
    if (handedOver) return;
    handedOver = true;
    for (const sig of signals) process.off(sig, onSignal);
    shutdown(1000, "migrate.complete").then(next);
  };
  const { server, shutdown } = createMigrateApp({
    configPath,
    vaultPath,
    publicDir,
    token,
    trustProxy: process.env.SHELLPORT_TRUST_PROXY ? trustProxyFromEnv(process.env.SHELLPORT_TRUST_PROXY) : cfg.server.trustProxy,
    onMigrated: (sealed) => handOver(() => startApp(sealed, vaultPath)),
    onSkip: () => handOver(() => startApp(cfg)),
  });

  server.listen(port, host, () => {
    audit("server.migrate", { listen: `${host}:${port}`, config: configPath, vault: vaultPath });
    console.log(`Found a plain configuration at ${configPath}. Open http://${host === "0.0.0.0" ? "localhost" : host}:${port} to encrypt it into ${vaultPath}, or to continue without.`);
    console.log(`Migration code: ${token}`);
    console.log("Set SHELLPORT_MIGRATE=off to skip this and start normally.");
  });

  for (const sig of signals) process.on(sig, onSignal);
}

function main() {
  const boot = decideBoot({ configPath, vaultPath, forceSetup: process.env.SHELLPORT_SETUP === "1" });
  if (boot.mode === "error") {
    console.error(boot.message);
    process.exit(1);
  } else if (boot.mode === "setup") {
    startSetup();
  } else if (boot.mode === "sealed") {
    startSealed(boot.vaultPath);
  } else {
    let cfg: LoadedConfig;
    try {
      cfg = loadConfig(configPath);
    } catch (e) {
      console.error((e as Error).message);
      process.exit(1);
    }
    if (process.env.SHELLPORT_MIGRATE === "off") startApp(cfg);
    else startMigrate(cfg);
  }
}

main();
