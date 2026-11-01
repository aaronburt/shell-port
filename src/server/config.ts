import fs from "node:fs";
import path from "node:path";
import ssh2 from "ssh2";
import { base32Decode } from "./totp.js";

export type SecretRef = string | { env: string } | { file: string };

export interface HostAuthKey {
  type: "key";
  privateKey: SecretRef;
  passphrase?: SecretRef | false;
}
export interface HostAuthPassword {
  type: "password";
  password: SecretRef;
}

export interface HostConfig {
  id: string;
  name: string;
  group?: string;
  tag?: string;
  host: string;
  port?: number;
  username: string;
  auth: HostAuthKey | HostAuthPassword;
  hostKeyFingerprints?: string[];
  allowedUsers?: Array<string | number>;
  files?: boolean;
}

export interface AppConfig {
  server: {
    port: number;
    host: string;
    publicUrl: string;
    trustProxy: boolean | number;
  };
  github: {
    clientId: string;
    clientSecret: SecretRef;
  };
  users: UserConfig[];
  session: {
    ttlHours: number;
  };
  limits: {
    maxTerminalsPerUser: number;
    idleTimeoutMinutes: number;
    loginAttemptsPer15Min: number;
    maxDownloadMB: number;
  };
  security: {
    allowUnpinnedHostKeys: boolean;
  };
  hosts: HostConfig[];
}

export interface UserConfig {
  github: string | number;
  totpSecret: SecretRef;
}

export interface LoadedUser {
  match: string;
  totpKey: Buffer;
}

export interface LoadedConfig extends Omit<AppConfig, "users"> {
  users: LoadedUser[];
  baseDir: string;
  github: AppConfig["github"] & { resolvedSecret: string };
}

function fail(msg: string): never {
  throw new Error(`config: ${msg}`);
}

export function resolveSecret(ref: SecretRef | undefined, baseDir: string, what: string, keepTrailingNewline = false): string | undefined {
  if (ref === undefined) return undefined;
  if (typeof ref === "string") return ref;
  if ("env" in ref) {
    const v = process.env[ref.env];
    if (v === undefined || v === "") fail(`${what}: environment variable ${ref.env} is not set`);
    return v;
  }
  if ("file" in ref) {
    const p = path.resolve(baseDir, ref.file);
    try {
      const text = fs.readFileSync(p, "utf8");
      return keepTrailingNewline ? text : text.replace(/\r?\n$/, "");
    } catch (e) {
      fail(`${what}: cannot read ${p} (${(e as Error).message})`);
    }
  }
  fail(`${what}: secret must be a string, {"env": ...} or {"file": ...}`);
}

export function keyIsEncrypted(pem: string): boolean | undefined {
  const r = ssh2.utils.parseKey(pem);
  if (!(r instanceof Error)) return false;
  if (/passphrase/i.test(r.message)) return true;
  return undefined;
}

export function hostNeedsPassphrase(h: HostConfig): boolean {
  return h.auth.type === "key" && h.auth.passphrase === undefined;
}

function intOption(value: unknown, name: string, def: number, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (value === undefined) return def;
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max)
    fail(`${name} must be an integer from ${min}${max === Number.MAX_SAFE_INTEGER ? " up" : ` to ${max}`}`);
  return value;
}

function trustProxyOption(value: unknown): boolean | number {
  if (value === undefined) return false;
  if (typeof value === "boolean") return value;
  return intOption(value, "server.trustProxy", 0, 0);
}

const ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;

export function loadConfig(file: string): LoadedConfig {
  const baseDir = path.dirname(path.resolve(file));
  let raw: any;
  try {
    raw = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    fail(`cannot read ${file}: ${(e as Error).message}`);
  }
  return validateConfig(raw, baseDir);
}

function findReference(node: unknown, where: string): string | undefined {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const hit = findReference(node[i], `${where}[${i}]`);
      if (hit) return hit;
    }
    return undefined;
  }
  if (node && typeof node === "object") {
    const keys = Object.keys(node);
    if (keys.length === 1 && (keys[0] === "env" || keys[0] === "file") && typeof (node as Record<string, unknown>)[keys[0]] === "string") return where;
    for (const k of keys) {
      const hit = findReference((node as Record<string, unknown>)[k], where ? `${where}.${k}` : k);
      if (hit) return hit;
    }
  }
  return undefined;
}

export function loadSealedConfig(plaintext: Buffer | string, baseDir = process.cwd()): LoadedConfig {
  let raw: any;
  try {
    raw = JSON.parse(plaintext.toString("utf8"));
  } catch {
    fail("the vault does not contain valid JSON");
  }
  const ref = findReference(raw, "");
  if (ref) fail(`${ref}: a sealed config cannot use env or file references; put the value in the vault itself`);
  return validateConfig(raw, baseDir);
}

export function validateConfig(raw: any, baseDir: string): LoadedConfig {
  const server = raw.server ?? {};
  const publicUrl = String(server.publicUrl ?? "").replace(/\/+$/, "");
  if (!/^https?:\/\/[^/]+$/.test(publicUrl)) fail(`server.publicUrl must be an origin like https://ssh.example.com`);

  if (!raw.github?.clientId) fail("github.clientId is required");
  if (!raw.github?.clientSecret) fail("github.clientSecret is required");

  const security = { allowUnpinnedHostKeys: Boolean(raw.security?.allowUnpinnedHostKeys) };

  if (!Array.isArray(raw.users) || !raw.users.length) fail("users must list at least one { github, totpSecret } entry");
  const users: LoadedUser[] = raw.users.map((u: UserConfig, i: number) => {
    const [match] = normalizeUsers([u?.github], `users[${i}].github`);
    const secret = resolveSecret(u.totpSecret, baseDir, `users[${i}] totpSecret`);
    if (secret === undefined) fail(`users[${i}] (${match}) has no totpSecret; generate one with npm run totp`);
    let totpKey: Buffer | undefined;
    try { totpKey = base32Decode(secret); } catch { fail(`users[${i}] totpSecret is not valid base32`); }
    if (totpKey.length < 16) fail(`users[${i}] totpSecret is too short (need at least 128 bits; use npm run totp)`);
    return { match, totpKey };
  });

  const hosts: HostConfig[] = raw.hosts ?? [];
  if (!Array.isArray(hosts) || !hosts.length) fail("hosts must be a non-empty array");
  const seen = new Set<string>();
  for (const h of hosts) {
    if (!ID_RE.test(h.id ?? "")) fail(`host id ${JSON.stringify(h.id)} must be 1-64 chars of letters, digits, _ . -`);
    if (seen.has(h.id)) fail(`duplicate host id ${h.id}`);
    seen.add(h.id);
    if (!h.host || !h.username) fail(`host ${h.id}: host and username are required`);
    h.name ||= h.id;
    if (h.files !== undefined && typeof h.files !== "boolean") fail(`host ${h.id}: files must be true or false`);
    h.files ??= true;
    h.port = intOption(h.port, `host ${h.id} port`, 22, 1, 65535);
    if (!h.auth || !["key", "password"].includes(h.auth.type)) fail(`host ${h.id}: auth.type must be key or password`);
    if (h.allowedUsers) h.allowedUsers = normalizeUsers(h.allowedUsers, `host ${h.id} allowedUsers`);
    if (!h.hostKeyFingerprints?.length && !security.allowUnpinnedHostKeys)
      fail(`host ${h.id}: hostKeyFingerprints is required (or set security.allowUnpinnedHostKeys for development)`);
    if (h.auth.type === "key") {
      const pem = resolveSecret(h.auth.privateKey, baseDir, `host ${h.id} privateKey`, true)!;
      const encrypted = keyIsEncrypted(pem);
      if (encrypted === undefined) fail(`host ${h.id}: privateKey is not a readable private key`);
      if (h.auth.passphrase === undefined && !encrypted)
        fail(`host ${h.id}: privateKey has no passphrase. Protect it (ssh-keygen -p -f <key>) so users unlock it in the browser, or set "passphrase": false to allow an unencrypted key`);
      if (h.auth.passphrase === false && encrypted)
        fail(`host ${h.id}: privateKey is passphrase-protected but "passphrase": false was set`);
      if (h.auth.passphrase !== undefined && h.auth.passphrase !== false) {
        const passphrase = resolveSecret(h.auth.passphrase, baseDir, `host ${h.id} passphrase`)!;
        const parsed = ssh2.utils.parseKey(pem, passphrase);
        if (parsed instanceof Error || (Array.isArray(parsed) && parsed[0] instanceof Error))
          fail(`host ${h.id}: the configured passphrase does not unlock privateKey`);
      }
    }
    if (h.auth.type === "password") resolveSecret(h.auth.password, baseDir, `host ${h.id} password`);
  }

  return {
    baseDir,
    server: {
      port: intOption(server.port, "server.port", 8080, 1, 65535),
      host: String(server.host ?? "127.0.0.1"),
      publicUrl,
      trustProxy: trustProxyOption(server.trustProxy),
    },
    github: {
      clientId: String(raw.github.clientId),
      clientSecret: raw.github.clientSecret,
      resolvedSecret: resolveSecret(raw.github.clientSecret, baseDir, "github.clientSecret")!,
    },
    users,
    session: { ttlHours: intOption(raw.session?.ttlHours, "session.ttlHours", 12, 1) },
    limits: {
      maxTerminalsPerUser: intOption(raw.limits?.maxTerminalsPerUser, "limits.maxTerminalsPerUser", 10, 1),
      idleTimeoutMinutes: intOption(raw.limits?.idleTimeoutMinutes, "limits.idleTimeoutMinutes", 30, 0),
      loginAttemptsPer15Min: intOption(raw.limits?.loginAttemptsPer15Min, "limits.loginAttemptsPer15Min", 30, 1),
      maxDownloadMB: intOption(raw.limits?.maxDownloadMB, "limits.maxDownloadMB", 256, 1, 4096),
    },
    security,
    hosts,
  };
}

function normalizeUsers(list: unknown, what: string): string[] {
  if (list === undefined) return [];
  if (!Array.isArray(list)) fail(`${what} must be an array`);
  return list.map((u) => {
    const s = String(u).trim().toLowerCase();
    if (!/^[a-z0-9-]{1,39}$/.test(s)) fail(`${what}: ${JSON.stringify(u)} is not a GitHub user id or login`);
    return s;
  });
}

export interface Identity { login: string; id: number }

export function userAllowed(list: Array<string | number>, who: Identity): boolean {
  const login = who.login.toLowerCase();
  const id = String(who.id);
  return list.some((e) => {
    const s = String(e);
    return /^\d+$/.test(s) ? s === id : s === login;
  });
}

export function findUser(cfg: LoadedConfig, who: Identity): LoadedUser | undefined {
  return cfg.users.find((u) => userAllowed([u.match], who));
}

export function hostsForUser(cfg: Pick<AppConfig, "hosts">, who: Identity): HostConfig[] {
  return cfg.hosts.filter((h) => !h.allowedUsers || userAllowed(h.allowedUsers, who));
}
