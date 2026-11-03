import fs from "node:fs";
import { readVaultHeader, VaultError } from "./vault.js";

export type BootMode =
  | { mode: "setup" }
  | { mode: "sealed"; vaultPath: string }
  | { mode: "error"; message: string };

export function decideBoot(opts: { vaultPath: string; forceSetup?: boolean }): BootMode {
  const vaultExists = fs.existsSync(opts.vaultPath);
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
  return { mode: "setup" };
}
