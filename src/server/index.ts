import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { audit } from "./log.js";

const configPath = process.env.SHELLPORT_CONFIG ?? "config.json";
let cfg;
try {
  cfg = loadConfig(configPath);
} catch (e) {
  console.error((e as Error).message);
  process.exit(1);
}

const here = path.dirname(fileURLToPath(import.meta.url));
const { server, shutdown } = createApp(cfg, { publicDir: path.join(here, "public") });

server.listen(cfg.server.port, cfg.server.host, () => {
  audit("server.start", { listen: `${cfg.server.host}:${cfg.server.port}`, publicUrl: cfg.server.publicUrl, hosts: cfg.hosts.length });
  if (cfg.security.allowUnpinnedHostKeys) audit("server.warning", { message: "allowUnpinnedHostKeys is on; do not use in production" });
  if (!cfg.server.publicUrl.startsWith("https://")) audit("server.warning", { message: "publicUrl is not https; cookies are not marked Secure" });
});

for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => shutdown(5000, sig).then(() => process.exit(0)));
