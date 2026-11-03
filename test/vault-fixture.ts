import fs from "node:fs";
import { loadSealedConfig } from "../src/server/config.js";
import { vaultStore } from "../src/server/hostadmin.js";
import { openVault, openVaultKeyed, replaceVaultBody, sealVault } from "../src/server/vault.js";

const PASSPHRASE = "synthetic fixture passphrase";
const FAST = { N: 1 << 10, r: 8, p: 1 };

export function readFixture(file: string): any {
  return JSON.parse(openVault(fs.readFileSync(file), PASSPHRASE).toString("utf8"));
}
export function loadFixture(file: string) {
  return loadSealedConfig(openVault(fs.readFileSync(file), PASSPHRASE));
}
export function writeFixture(file: string, raw: unknown) {
  const json = JSON.stringify(raw);
  if (!fs.existsSync(file)) return fs.writeFileSync(file, sealVault(json, PASSPHRASE, FAST));
  const current = fs.readFileSync(file);
  const { plain, dek } = openVaultKeyed(current, PASSPHRASE);
  try { fs.writeFileSync(file, replaceVaultBody(current, dek, json)); }
  finally { plain.fill(0); dek.fill(0); }
}
export function fixtureStore(file: string) {
  const { plain, dek } = openVaultKeyed(fs.readFileSync(file), PASSPHRASE);
  plain.fill(0);
  return vaultStore(file, dek);
}
