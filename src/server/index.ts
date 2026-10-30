import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, type LoadedConfig } from "./config.js";
import { createApp } from "./app.js";
import { createSetupApp } from "./setup.js";
import { audit } from "./log.js";

const configPath = process.env.SHELLPORT_CONFIG ?? "config.json";
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, "public");

function startApp(cfg: LoadedConfig) {
  const { server, shutdown } = createApp(cfg, { publicDir });

  server.listen(cfg.server.port, cfg.server.host, () => {
    audit("server.start", { listen: `${cfg.server.host}:${cfg.server.port}`, publicUrl: cfg.server.publicUrl, hosts: cfg.hosts.length });
    if (cfg.security.allowUnpinnedHostKeys) audit("server.warning", { message: "allowUnpinnedHostKeys is on; do not use in production" });
    if (!cfg.server.publicUrl.startsWith("https://")) audit("server.warning", { message: "publicUrl is not https; cookies are not marked Secure" });
  });

  for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => shutdown(5000, sig).then(() => process.exit(0)));
}

function startSetup() {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || "0.0.0.0";

  let appStarted = false;
  const { server, shutdown } = createSetupApp({
    configPath,
    publicDir,
    onSaved: (savedCfg) => {
      if (appStarted) return;
      appStarted = true;
      shutdown(1000, "setup.complete").then(() => startApp(savedCfg));
    },
  });

  server.listen(port, host, () => {
    audit("server.setup", { listen: `${host}:${port}`, configPath });
    console.log(`No configuration file found at ${configPath}. Starting setup wizard on http://${host === "0.0.0.0" ? "localhost" : host}:${port}`);
  });

  for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => shutdown(5000, sig).then(() => process.exit(0)));
}

if (!fs.existsSync(configPath) || process.env.SHELLPORT_SETUP === "1") {
  startSetup();
} else {
  let cfg: LoadedConfig;
  try {
    cfg = loadConfig(configPath);
  } catch (e) {
    console.error((e as Error).message);
    process.exit(1);
  }
  startApp(cfg);
}
