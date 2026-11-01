import fs from "node:fs";
import path from "node:path";
import { loadSealedConfig, resolveSecret, type LoadedConfig } from "./config.js";
import { checkPassphraseStrength, sealVaultKeyed } from "./vault.js";

function isReference(node: unknown): node is { env: string } | { file: string } {
  if (!node || typeof node !== "object" || Array.isArray(node)) return false;
  const keys = Object.keys(node);
  return keys.length === 1 && (keys[0] === "env" || keys[0] === "file") && typeof (node as Record<string, unknown>)[keys[0]] === "string";
}

export function inlineSecrets(node: unknown, baseDir: string, where = ""): unknown {
  if (isReference(node)) {
    const keepNewline = where.endsWith("privateKey");
    return resolveSecret(node, baseDir, where || "value", keepNewline);
  }
  if (Array.isArray(node)) return node.map((v, i) => inlineSecrets(v, baseDir, `${where}[${i}]`));
  if (node && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) out[k] = inlineSecrets(v, baseDir, where ? `${where}.${k}` : k);
    return out;
  }
  return node;
}

export function plainConfigToSealedJson(configPath: string): string {
  const resolved = path.resolve(configPath);
  const raw = JSON.parse(fs.readFileSync(resolved, "utf8"));
  const inlined = inlineSecrets(raw, path.dirname(resolved)) as { users?: Array<{ admin?: unknown }> };
  if (Array.isArray(inlined.users) && inlined.users.length && !inlined.users.some((u) => u?.admin === true) && inlined.users[0] && typeof inlined.users[0] === "object") {
    inlined.users[0].admin = true;
  }
  return JSON.stringify(inlined, null, 2);
}

export function writeFileAtomic(file: string, data: string, mode = 0o600) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode });
  fs.renameSync(tmp, file);
}

export function socketPathFor(vaultPath: string): string {
  return `${path.resolve(vaultPath)}.sock`;
}

export function migrateToVaultKeyed(opts: { configPath: string; vaultPath: string; passphrase: string }): { cfg: LoadedConfig; dek: Buffer } {
  if (fs.existsSync(opts.vaultPath)) throw new Error(`${opts.vaultPath} already exists`);
  const weak = checkPassphraseStrength(opts.passphrase);
  if (weak) throw new Error(weak);
  const json = plainConfigToSealedJson(opts.configPath);
  const cfg = loadSealedConfig(json);
  const dir = path.dirname(path.resolve(opts.vaultPath));
  if (!fs.existsSync(dir)) throw new Error(`the folder ${dir} for the vault does not exist; mount a writable folder there`);
  try {
    fs.accessSync(dir, fs.constants.W_OK);
  } catch {
    throw new Error(`the folder ${dir} for the vault is not writable`);
  }
  const { file, dek } = sealVaultKeyed(json, opts.passphrase);
  writeFileAtomic(path.resolve(opts.vaultPath), file);
  return { cfg, dek };
}

export function migrateToVault(opts: { configPath: string; vaultPath: string; passphrase: string }): LoadedConfig {
  const { cfg, dek } = migrateToVaultKeyed(opts);
  dek.fill(0);
  return cfg;
}
