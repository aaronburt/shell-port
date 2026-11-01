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
  update(id: string, host: HostConfig, pem: string | undefined): HostConfig;
  remove(id: string): void;
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

const MADE_KEY = /^keys\/sp-[0-9a-f]{12}\.key$/;

function refFile(h: HostConfig): string | undefined {
  if (h.auth.type !== "key") return undefined;
  const p = h.auth.privateKey;
  return typeof p === "object" && p !== null && "file" in p ? p.file : undefined;
}

interface StoreIo {
  read(): { hosts?: HostConfig[] } & Record<string, unknown>;
  write(raw: unknown): void;
}

function makeStore(kind: "file" | "vault", where: string, dir: string, io: StoreIo): HostStore {
  const placeKey = (host: HostConfig, pem: string | undefined, written: string[]): HostConfig => {
    if (pem === undefined || host.auth.type !== "key") return host;
    if (kind === "vault") return { ...host, auth: { ...host.auth, privateKey: pem } };
    const keyDir = path.join(dir, "keys");
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
    const name = `sp-${crypto.randomBytes(6).toString("hex")}.key`;
    const file = path.join(keyDir, name);
    fs.writeFileSync(file, pem.endsWith("\n") ? pem : pem + "\n", { mode: 0o600, flag: "wx" });
    written.push(file);
    return { ...host, auth: { ...host.auth, privateKey: { file: `keys/${name}` } } };
  };

  const run = (fn: (hosts: HostConfig[], written: string[]) => { host?: HostConfig; dropped?: HostConfig }): HostConfig | undefined => {
    const written: string[] = [];
    try {
      const raw = io.read();
      if (!Array.isArray(raw.hosts)) raw.hosts = [];
      const out = fn(raw.hosts, written);
      io.write(raw);
      const gone = out.dropped && refFile(out.dropped);
      if (kind === "file" && gone && MADE_KEY.test(gone) && !raw.hosts.some((h) => refFile(h) === gone)) {
        try { fs.rmSync(path.join(dir, gone), { force: true }); } catch {}
      }
      return out.host;
    } catch (e) {
      for (const f of written) try { fs.rmSync(f, { force: true }); } catch {}
      if (e instanceof HostAdminError) throw e;
      throw new HostAdminError(500, "storage_failed", `Could not save to ${where}: ${(e as Error).message}`);
    }
  };

  const find = (hosts: HostConfig[], id: string) => {
    const i = hosts.findIndex((h) => h.id === id);
    if (i < 0) throw new HostAdminError(404, "not_found", "That host no longer exists.");
    return i;
  };

  return {
    kind,
    append: (host, pem) => run((hosts, w) => {
      const h = placeKey(host, pem, w);
      hosts.push(h);
      return { host: h };
    })!,
    update: (id, host, pem) => run((hosts, w) => {
      const i = find(hosts, id);
      const dropped = hosts[i];
      const h = placeKey(host, pem, w);
      hosts[i] = h;
      return { host: h, dropped };
    })!,
    remove: (id) => {
      run((hosts) => {
        const i = find(hosts, id);
        const [dropped] = hosts.splice(i, 1);
        return { dropped };
      });
    },
  };
}

export function fileStore(configPath: string): HostStore {
  const resolved = path.resolve(configPath);
  return makeStore("file", configPath, path.dirname(resolved), {
    read: () => JSON.parse(fs.readFileSync(resolved, "utf8")),
    write: (raw) => writeFileAtomic(resolved, JSON.stringify(raw, null, 2) + "\n", fs.statSync(resolved).mode & 0o777),
  });
}

export function vaultStore(vaultPath: string, dek: Buffer): HostStore {
  const resolved = path.resolve(vaultPath);
  let current: Buffer;
  return makeStore("vault", "the vault", path.dirname(resolved), {
    read: () => {
      current = fs.readFileSync(resolved);
      return JSON.parse(openVaultWithKey(current, dek).toString("utf8"));
    },
    write: (raw) => writeFileAtomic(resolved, replaceVaultBody(current, dek, JSON.stringify(raw, null, 2))),
  });
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

interface Fields { name: string; group: string; host: string; port: number; username: string }

function parseFields(input: AddHostInput): Fields {
  const name = text(input.name, "Name", 64);
  const group = text(input.group, "Group", 64, false);
  const host = text(input.host, "Host", 253);
  const username = text(input.username, "User", 64);
  if (!HOST_RE.test(host)) throw new HostAdminError(400, "invalid", "Host must be a name or IP address.");
  if (!USER_RE.test(username)) throw new HostAdminError(400, "invalid", "User is not valid.");
  const port = input.port === undefined || input.port === "" ? 22 : Number(input.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HostAdminError(400, "invalid", "Port must be between 1 and 65535.");
  return { name, group, host, port, username };
}

async function pin(probe: KeyProbe, host: string, port: number): Promise<string> {
  try {
    return await probe(host, port);
  } catch (e) {
    throw new HostAdminError(422, "unreachable", probeMessage(e as Error));
  }
}

export async function addHost(cfg: LoadedConfig, store: HostStore, input: AddHostInput, probe: KeyProbe = probeHostKey): Promise<HostConfig> {
  const { name, group, host, port, username } = parseFields(input);
  if (cfg.hosts.some((h) => h.name.toLowerCase() === name.toLowerCase())) throw new HostAdminError(409, "duplicate", "A host with that name already exists.");
  const { auth, pem } = resolveKey(cfg, input.key, input.allowNoPassphrase === true);
  const fingerprint = await pin(probe, host, port);

  let id = slug(name);
  for (let n = 2; cfg.hosts.some((h) => h.id === id); n++) id = `${slug(name).slice(0, 58)}-${n}`;
  const candidate: HostConfig = {
    id,
    name,
    ...(group ? { group } : {}),
    host,
    port,
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

export interface HostDetails {
  id: string;
  name: string;
  group: string;
  host: string;
  port: number;
  username: string;
  auth: { type: "password" } | { type: "key"; keyId: string; keyName: string; encrypted: boolean };
}

function findHost(cfg: LoadedConfig, id: string): number {
  const i = cfg.hosts.findIndex((h) => h.id === id);
  if (i < 0) throw new HostAdminError(404, "not_found", "That host no longer exists.");
  return i;
}

export function describeHost(cfg: LoadedConfig, id: string): HostDetails {
  const h = cfg.hosts[findHost(cfg, id)];
  const base = { id: h.id, name: h.name, group: h.group ?? "", host: h.host, port: h.port ?? 22, username: h.username };
  if (h.auth.type !== "key") return { ...base, auth: { type: "password" } };
  const pem = resolveSecret(h.auth.privateKey, cfg.baseDir, "privateKey", true)!;
  return { ...base, auth: { type: "key", keyId: keyFingerprint(pem), keyName: keyNameOf(h), encrypted: keyIsEncrypted(pem) === true } };
}

export async function updateHost(cfg: LoadedConfig, store: HostStore, id: string, input: AddHostInput, probe: KeyProbe = probeHostKey): Promise<HostConfig> {
  const idx = findHost(cfg, id);
  const old = cfg.hosts[idx];
  const { name, group, host, port, username } = parseFields(input);
  if (cfg.hosts.some((h) => h.id !== id && h.name.toLowerCase() === name.toLowerCase())) throw new HostAdminError(409, "duplicate", "A host with that name already exists.");
  const keep = !!input.key && typeof input.key === "object" && (input.key as { keep?: unknown }).keep === true;
  const { auth, pem } = keep ? { auth: structuredClone(old.auth), pem: undefined } : resolveKey(cfg, input.key, input.allowNoPassphrase === true);
  const moved = host !== old.host || port !== (old.port ?? 22);
  const fingerprints = moved ? [await pin(probe, host, port)] : old.hostKeyFingerprints;

  const { group: _g, ...rest } = old;
  const candidate: HostConfig = { ...rest, ...(group ? { group } : {}), name, host, port, username, auth, hostKeyFingerprints: fingerprints };
  try {
    validateHost(structuredClone(candidate), cfg.baseDir, cfg.security, new Set(cfg.hosts.filter((h) => h.id !== id).map((h) => h.id)));
  } catch (e) {
    if (pem === undefined) throw new HostAdminError(422, "invalid", (e as Error).message);
    throw new HostAdminError(400, "invalid_key", "That file is not a usable private key.");
  }
  const saved = store.update(id, candidate, pem);
  const loaded: HostConfig = { ...saved, files: old.files ?? true };
  cfg.hosts[cfg.hosts.findIndex((h) => h.id === id)] = loaded;
  return loaded;
}

export function removeHost(cfg: LoadedConfig, store: HostStore, id: string): HostConfig {
  const idx = findHost(cfg, id);
  if (cfg.hosts.length <= 1) throw new HostAdminError(409, "last_host", "At least one host must remain.");
  store.remove(id);
  return cfg.hosts.splice(cfg.hosts.findIndex((h) => h.id === id), 1)[0];
}
