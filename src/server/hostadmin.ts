import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import ssh2 from "ssh2";
import { keyIsEncrypted, resolveSecret, validateHost, type HostConfig, type HostAuthKey, type LoadedConfig } from "./config.js";
import { openVaultWithKey, replaceVaultBody } from "./vault.js";
import { writeFileAtomic } from "./vaultops.js";

export class HostAdminError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "HostAdminError";
  }
}

export interface HostStore {
  readonly kind: "file" | "vault";
  append(host: HostConfig, pem: string | undefined): HostConfig;
}

export interface KeyEntry {
  id: string;
  name: string;
  encrypted: boolean;
  hosts: number;
}

export interface AddHostInput {
  name: unknown;
  group: unknown;
  host: unknown;
  port: unknown;
  username: unknown;
  key: unknown;
  allowNoPassphrase: unknown;
}

export type KeyProbe = (host: string, port: number) => Promise<string>;

const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?$/;
const USER_RE = /^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$/;
const MAX_PEM_BYTES = 16 * 1024;

export function keyFingerprint(pem: string): string {
  return "key-" + crypto.createHash("sha256").update(pem.trim()).digest("hex").slice(0, 12);
}

export function fileStore(configPath: string): HostStore {
  const resolved = path.resolve(configPath);
  const dir = path.dirname(resolved);
  return {
    kind: "file",
    append(host, pem) {
      const written: string[] = [];
      try {
        if (pem !== undefined && host.auth.type === "key") {
          const keyDir = path.join(dir, "keys");
          fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
          const file = path.join(keyDir, `${host.id}.key`);
          fs.writeFileSync(file, pem.endsWith("\n") ? pem : pem + "\n", { mode: 0o600, flag: "wx" });
          written.push(file);
          host = { ...host, auth: { ...host.auth, privateKey: { file: `keys/${host.id}.key` } } };
        }
        const raw = JSON.parse(fs.readFileSync(resolved, "utf8"));
        if (!Array.isArray(raw.hosts)) raw.hosts = [];
        raw.hosts.push(host);
        writeFileAtomic(resolved, JSON.stringify(raw, null, 2) + "\n", fs.statSync(resolved).mode & 0o777);
        return host;
      } catch (e) {
        for (const f of written) try { fs.rmSync(f, { force: true }); } catch {}
        throw new HostAdminError(500, "storage_failed", `Could not save to ${configPath}: ${(e as Error).message}`);
      }
    },
  };
}

export function vaultStore(vaultPath: string, dek: Buffer): HostStore {
  const resolved = path.resolve(vaultPath);
  return {
    kind: "vault",
    append(host, pem) {
      try {
        if (pem !== undefined && host.auth.type === "key") host = { ...host, auth: { ...host.auth, privateKey: pem } };
        const file = fs.readFileSync(resolved);
        const raw = JSON.parse(openVaultWithKey(file, dek).toString("utf8"));
        if (!Array.isArray(raw.hosts)) raw.hosts = [];
        raw.hosts.push(host);
        writeFileAtomic(resolved, replaceVaultBody(file, dek, JSON.stringify(raw, null, 2)));
        return host;
      } catch (e) {
        throw new HostAdminError(500, "storage_failed", `Could not save to the vault: ${(e as Error).message}`);
      }
    },
  };
}

export function probeHostKey(host: string, port: number, timeoutMs = 8000): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = new ssh2.Client();
    let fp: string | undefined;
    let settled = false;
    const finish = (err?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.destroy();
      if (fp) resolve(fp);
      else reject(err ?? new Error("closed"));
    };
    const timer = setTimeout(() => finish(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })), timeoutMs);
    client.on("error", (e) => finish(e));
    client.on("close", () => finish());
    client.connect({
      host,
      port,
      username: "shellport-probe",
      readyTimeout: timeoutMs,
      hostVerifier: (key: Buffer) => {
        fp = "SHA256:" + crypto.createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
        return false;
      },
    });
  });
}

function probeMessage(err: Error & { code?: string }): string {
  if (err.code === "ENOTFOUND" || err.code === "EAI_AGAIN") return "That host name could not be resolved.";
  if (err.code === "ECONNREFUSED") return "The host refused the connection on that port.";
  if (err.code === "ETIMEDOUT" || err.message === "timeout") return "The host did not answer in time.";
  if (err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH") return "The host is unreachable.";
  return "Could not read the host key from that address.";
}

function text(value: unknown, what: string, max: number, required = true): string {
  if (value === undefined || value === null || value === "") {
    if (required) throw new HostAdminError(400, "invalid", `${what} is required.`);
    return "";
  }
  if (typeof value !== "string") throw new HostAdminError(400, "invalid", `${what} must be text.`);
  const v = value.trim();
  if (!v && required) throw new HostAdminError(400, "invalid", `${what} is required.`);
  if (v.length > max || /[\u0000-\u001f\u007f]/.test(v)) throw new HostAdminError(400, "invalid", `${what} is not valid.`);
  return v;
}

function slug(name: string): string {
  const base = name.toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, "").slice(0, 56);
  return base || "host";
}

function keyNameOf(h: HostConfig): string {
  const a = h.auth as HostAuthKey;
  if (a.keyName) return a.keyName;
  if (typeof a.privateKey === "object" && "file" in a.privateKey) return path.basename(a.privateKey.file);
  return `${h.name} key`;
}

export function listKeys(cfg: LoadedConfig): KeyEntry[] {
  const out = new Map<string, KeyEntry>();
  for (const h of cfg.hosts) {
    if (h.auth.type !== "key") continue;
    let pem: string;
    try {
      pem = resolveSecret(h.auth.privateKey, cfg.baseDir, "privateKey", true)!;
    } catch {
      continue;
    }
    const id = keyFingerprint(pem);
    const known = out.get(id);
    if (known) known.hosts++;
    else out.set(id, { id, name: keyNameOf(h), encrypted: keyIsEncrypted(pem) === true, hosts: 1 });
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function resolveKey(cfg: LoadedConfig, input: unknown, ack: boolean): { auth: HostAuthKey; pem?: string } {
  if (!input || typeof input !== "object") throw new HostAdminError(400, "invalid", "Choose or upload a key.");
  const k = input as { existing?: unknown; upload?: unknown };
  if (typeof k.existing === "string") {
    const source = cfg.hosts.find((h) => {
      if (h.auth.type !== "key") return false;
      try {
        return keyFingerprint(resolveSecret(h.auth.privateKey, cfg.baseDir, "privateKey", true)!) === k.existing;
      } catch {
        return false;
      }
    });
    if (!source) throw new HostAdminError(400, "unknown_key", "That key no longer exists.");
    const auth = structuredClone(source.auth) as HostAuthKey;
    const pem = resolveSecret(auth.privateKey, cfg.baseDir, "privateKey", true)!;
    if (keyIsEncrypted(pem) !== true && !ack)
      throw new HostAdminError(400, "needs_confirmation", "This key has no passphrase. Confirm to save it without one.");
    return { auth };
  }
  const up = k.upload as { name?: unknown; pem?: unknown } | undefined;
  if (!up || typeof up.pem !== "string") throw new HostAdminError(400, "invalid", "Choose or upload a key.");
  const pem = up.pem.replace(/\r\n/g, "\n");
  if (Buffer.byteLength(pem) > MAX_PEM_BYTES) throw new HostAdminError(400, "invalid", "That key file is too large.");
  const encrypted = keyIsEncrypted(pem);
  if (encrypted === undefined) throw new HostAdminError(400, "invalid_key", "That file is not a readable private key.");
  if (!encrypted && !ack) throw new HostAdminError(400, "needs_confirmation", "This key has no passphrase. Confirm to save it without one.");
  const keyName = text(up.name, "Key name", 64, false) || "uploaded key";
  const auth: HostAuthKey = { type: "key", privateKey: pem, keyName };
  if (!encrypted) auth.passphrase = false;
  return { auth, pem };
}

export async function addHost(cfg: LoadedConfig, store: HostStore, input: AddHostInput, probe: KeyProbe = probeHostKey): Promise<HostConfig> {
  const name = text(input.name, "Name", 64);
  const group = text(input.group, "Group", 64, false);
  const host = text(input.host, "Host", 253);
  const username = text(input.username, "User", 64);
  if (!HOST_RE.test(host)) throw new HostAdminError(400, "invalid", "Host must be a name or IP address.");
  if (!USER_RE.test(username)) throw new HostAdminError(400, "invalid", "User is not valid.");
  const portNum = input.port === undefined || input.port === "" ? 22 : Number(input.port);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) throw new HostAdminError(400, "invalid", "Port must be between 1 and 65535.");
  if (cfg.hosts.some((h) => h.name.toLowerCase() === name.toLowerCase())) throw new HostAdminError(409, "duplicate", "A host with that name already exists.");
  const { auth, pem } = resolveKey(cfg, input.key, input.allowNoPassphrase === true);

  let fingerprint: string;
  try {
    fingerprint = await probe(host, portNum);
  } catch (e) {
    throw new HostAdminError(422, "unreachable", probeMessage(e as Error));
  }

  let id = slug(name);
  for (let n = 2; cfg.hosts.some((h) => h.id === id); n++) id = `${slug(name).slice(0, 58)}-${n}`;
  const candidate: HostConfig = {
    id,
    name,
    ...(group ? { group } : {}),
    host,
    port: portNum,
    username,
    auth,
    hostKeyFingerprints: [fingerprint],
  };
  try {
    validateHost(structuredClone(candidate), cfg.baseDir, cfg.security, new Set(cfg.hosts.map((h) => h.id)));
  } catch (e) {
    if (pem === undefined) throw new HostAdminError(422, "invalid", (e as Error).message);
    throw new HostAdminError(400, "invalid_key", "That file is not a usable private key.");
  }
  if (cfg.hosts.some((h) => h.id === id)) throw new HostAdminError(409, "duplicate", "A host with that name already exists.");

  const saved = store.append(candidate, pem);
  const loaded: HostConfig = { ...saved, files: true };
  cfg.hosts.push(loaded);
  return loaded;
}
