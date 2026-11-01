import fs from "node:fs";
import { readVaultHeader, VaultError } from "./vault.js";

export type BootMode =
  | { mode: "setup" }
  | { mode: "plain" }
  | { mode: "sealed"; vaultPath: string }
  | { mode: "error"; message: string };

export function decideBoot(opts: { configPath: string; vaultPath: string; forceSetup?: boolean }): BootMode {
  const vaultExists = fs.existsSync(opts.vaultPath);
  const configExists = fs.existsSync(opts.configPath);

  if (vaultExists && configExists) {
    return {
      mode: "error",
      message: `Both a vault (${opts.vaultPath}) and a config file (${opts.configPath}) exist. Remove or move one of them: a leftover plain config would defeat sealing.`,
    };
  }
  if (vaultExists) {
    if (opts.forceSetup) return { mode: "error", message: `SHELLPORT_SETUP=1 cannot be used while a vault (${opts.vaultPath}) exists.` };
    try {
      readVaultHeader(fs.readFileSync(opts.vaultPath));
    } catch (e) {
      const why = e instanceof VaultError ? e.message : (e as Error).message;
      return { mode: "error", message: `The vault ${opts.vaultPath} cannot be used: ${why}` };
    }
    return { mode: "sealed", vaultPath: opts.vaultPath };
  }
  if (!configExists || opts.forceSetup) return { mode: "setup" };
  return { mode: "plain" };
}
