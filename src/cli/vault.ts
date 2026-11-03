import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { changeVaultPassphrase, checkPassphraseStrength, openVault, sealVault, VaultError } from "../server/vault.js";
import { loadSealedConfig } from "../server/config.js";
import { plainConfigToSealedJson, socketPathFor, writeFileAtomic } from "../server/vaultops.js";
import { readNewPassphrase, readSecret } from "./prompt.js";

const vaultPath = process.env.SHELLPORT_VAULT ?? "vault.sealed";
const configPath = process.env.SHELLPORT_CONFIG ?? "config.json";

const USAGE = `Usage: vault-cli <command>

  seal              Encrypt ${configPath} (secrets inlined) into ${vaultPath}
  unseal            Unlock a running sealed server through its local socket
  edit              Edit the sealed config in $EDITOR and re-encrypt it
  check             Verify the passphrase and that the sealed config is valid
  passphrase        Change the vault passphrase
  export <file>     Write the decrypted config to a plain JSON file (0600, never overwrites)
  import <file>     Replace the vault contents with a plain JSON config (keeps the passphrase)

Set SHELLPORT_VAULT and SHELLPORT_CONFIG to use other paths.`;

function die(msg: string): never {
  console.error(msg);
  process.exit(1);
}

function readVault(): Buffer {
  try {
    return fs.readFileSync(vaultPath);
  } catch {
    die(`Cannot read ${vaultPath}.`);
  }
}

async function open(file: Buffer, prompt = "Passphrase: "): Promise<{ plain: Buffer; passphrase: string }> {
  const passphrase = await readSecret(prompt);
  try {
    return { plain: openVault(file, passphrase), passphrase };
  } catch (e) {
    if (e instanceof VaultError && e.code === "bad_passphrase") die("Wrong passphrase.");
    throw e;
  }
}

async function seal() {
  if (fs.existsSync(vaultPath)) die(`${vaultPath} already exists. Move it away first.`);
  if (!fs.existsSync(configPath)) die(`Cannot find ${configPath}.`);
  const json = plainConfigToSealedJson(configPath);
  loadSealedConfig(json);
  const passphrase = await readNewPassphrase("Choose a passphrase");
  const weak = checkPassphraseStrength(passphrase);
  if (weak) die(weak);
  writeFileAtomic(vaultPath, sealVault(json, passphrase));
  console.log(`Wrote ${vaultPath}.`);
  console.log(`Now remove ${configPath} and any .env or key files it referenced, then restart Shellport. It refuses to start while both exist.`);
}

function post(socket: string, passphrase: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ passphrase });
    const req = http.request(
      { socketPath: socket, method: "POST", path: "/api/unseal", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), Host: "localhost", Origin: "http://localhost" } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

async function unseal() {
  const socket = socketPathFor(vaultPath);
  if (!fs.existsSync(socket)) die(`No sealed server is listening on ${socket}. Run this on the same machine (or inside the container) as a sealed server.`);
  const passphrase = await readSecret("Passphrase: ");
  const r = await post(socket, passphrase).catch((e) => die(`Cannot reach the server: ${(e as Error).message}`));
  if (r.status === 204) return console.log("Unsealed.");
  let error = r.body;
  try { error = JSON.parse(r.body).message ?? JSON.parse(r.body).error; } catch {}
  die(r.status === 401 ? "Wrong passphrase." : `Unseal failed (${r.status}): ${error}`);
}

async function check() {
  const { plain } = await open(readVault());
  try {
    const cfg = loadSealedConfig(plain);
    console.log(`OK: ${cfg.hosts.length} host(s), ${cfg.users.length} user(s).`);
  } catch (e) {
    die((e as Error).message);
  } finally {
    plain.fill(0);
  }
}

async function edit() {
  const file = readVault();
  const { plain, passphrase } = await open(file);
  const base = fs.existsSync("/dev/shm") ? "/dev/shm" : os.tmpdir();
  const dir = fs.mkdtempSync(path.join(base, "shellport-edit-"));
  const tmp = path.join(dir, "config.json");
  fs.writeFileSync(tmp, plain, { mode: 0o600 });
  const original = plain.toString("utf8");
  plain.fill(0);
  try {
    const editor = process.env.VISUAL || process.env.EDITOR || "vi";
    const run = spawnSync(`${editor} "${tmp}"`, { stdio: "inherit", shell: true });
    if (run.status !== 0) die("The editor exited with an error. Nothing was changed.");
    const edited = fs.readFileSync(tmp, "utf8");
    if (edited === original) return console.log("No changes.");
    try {
      loadSealedConfig(edited);
    } catch (e) {
      die(`${(e as Error).message}\nNothing was changed.`);
    }
    writeFileAtomic(vaultPath, sealVault(edited, passphrase, undefined));
    console.log(`Updated ${vaultPath}. A running server keeps its old config until it is sealed and unsealed again, or restarted.`);
  } finally {
    try { fs.writeFileSync(tmp, Buffer.alloc(fs.statSync(tmp).size)); } catch {}
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function passphraseCmd() {
  const file = readVault();
  const oldPass = await readSecret("Current passphrase: ");
  const next = await readNewPassphrase("New passphrase");
  try {
    writeFileAtomic(vaultPath, changeVaultPassphrase(file, oldPass, next));
  } catch (e) {
    if (e instanceof VaultError) die(e.code === "bad_passphrase" ? "Wrong current passphrase." : e.message);
    throw e;
  }
  console.log("Passphrase changed.");
}

function arg(): string {
  return process.argv[3] ?? die("Give a file path.");
}

async function exportCmd() {
  const out = path.resolve(arg());
  if (fs.existsSync(out)) die(`${out} already exists.`);
  const { plain } = await open(readVault());
  try {
    fs.writeFileSync(out, plain, { mode: 0o600, flag: "wx" });
  } finally {
    plain.fill(0);
  }
  console.log(`Wrote ${out}. It holds every secret in plain text: store it somewhere safe and delete it when done.`);
}

async function importCmd() {
  const src = path.resolve(arg());
  let json: string;
  try {
    json = plainConfigToSealedJson(src);
    loadSealedConfig(json);
  } catch (e) {
    die((e as Error).message);
  }
  const { passphrase, plain } = await open(readVault(), "Vault passphrase: ");
  plain.fill(0);
  writeFileAtomic(vaultPath, sealVault(json, passphrase));
  console.log(`Replaced the contents of ${vaultPath}. A running server keeps its old config until it is sealed and unsealed again, or restarted.`);
}

const commands: Record<string, () => Promise<void>> = { seal, unseal, edit, check, passphrase: passphraseCmd, export: exportCmd, import: importCmd };
const cmd = commands[process.argv[2] ?? ""];
if (!cmd) {
  console.log(USAGE);
  process.exit(process.argv[2] ? 1 : 0);
}
await cmd().catch((e) => die((e as Error).message));
