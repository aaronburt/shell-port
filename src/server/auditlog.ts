import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const AUDIT_KINDS = {
  signin: { group: "Sign-ins", label: "Signed in" },
  signin_denied: { group: "Sign-ins", label: "Sign-in denied", bad: true },
  totp_failed: { group: "Sign-ins", label: "Wrong authenticator code", bad: true },
  passkey_failed: { group: "Sign-ins", label: "Passkey sign-in failed", bad: true },
  ssh_connect: { group: "SSH connections", label: "Connected" },
  ssh_disconnect: { group: "SSH connections", label: "Disconnected" },
  ssh_failed: { group: "SSH connections", label: "Connection failed", bad: true },
  passphrase_failed: { group: "SSH connections", label: "Wrong SSH passphrase", bad: true },
  host_added: { group: "Host changes", label: "Host added" },
  host_edited: { group: "Host changes", label: "Host edited" },
  host_deleted: { group: "Host changes", label: "Host deleted" },
  key_uploaded: { group: "Host changes", label: "Key uploaded" },
  passkey_added: { group: "Passkeys", label: "Passkey added" },
  passkey_removed: { group: "Passkeys", label: "Passkey removed" },
  unlock_failed: { group: "Screen lock", label: "Unlock failed", bad: true },
  vault_sealed: { group: "Server", label: "Server sealed" },
  vault_unsealed: { group: "Server", label: "Server unsealed" },
} as const satisfies Record<string, { group: string; label: string; bad?: true }>;

export type AuditKind = keyof typeof AUDIT_KINDS;

export const AUDIT_GROUPS = [...new Set(Object.values(AUDIT_KINDS).map((k) => k.group))];

export interface AuditEntry {
  id: string;
  at: number;
  kind: AuditKind;
  user: string;
  ip: string;
  host: string;
  detail: string;
}

export interface AuditSink {
  readonly file: string;
  readonly encrypted: boolean;
  load(): { entries: AuditEntry[]; unreadable: number };
  append(entry: AuditEntry): void;
  rewrite(entries: AuditEntry[]): void;
  close(): void;
}

const LINE_PREFIX = "e1.";
const AAD = Buffer.from("shellport audit log v1");

function subKey(dek: Buffer): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", dek, Buffer.alloc(0), "shellport audit log v1", 32));
}

function isEntry(v: unknown): v is AuditEntry {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return typeof e.id === "string" && typeof e.at === "number" && typeof e.kind === "string" && e.kind in AUDIT_KINDS &&
    typeof e.user === "string" && typeof e.ip === "string" && typeof e.host === "string" && typeof e.detail === "string";
}

export function fileSink(file: string, dek?: Buffer): AuditSink {
  const key = dek ? subKey(dek) : undefined;
  const encode = (e: AuditEntry): string => {
    const json = JSON.stringify(e);
    if (!key) return json;
    const nonce = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
    c.setAAD(AAD);
    const body = Buffer.concat([c.update(json, "utf8"), c.final(), c.getAuthTag()]);
    return LINE_PREFIX + nonce.toString("base64url") + "." + body.toString("base64url");
  };
  const decode = (line: string): AuditEntry | undefined => {
    try {
      let json = line;
      if (key) {
        if (!line.startsWith(LINE_PREFIX)) return undefined;
        const [n, b] = line.slice(LINE_PREFIX.length).split(".");
        const nonce = Buffer.from(n, "base64url");
        const body = Buffer.from(b, "base64url");
        const d = crypto.createDecipheriv("aes-256-gcm", key, nonce);
        d.setAAD(AAD);
        d.setAuthTag(body.subarray(body.length - 16));
        json = Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]).toString("utf8");
      } else if (line.startsWith(LINE_PREFIX)) {
        return undefined;
      }
      const v = JSON.parse(json);
      return isEntry(v) ? v : undefined;
    } catch {
      return undefined;
    }
  };
  return {
    file,
    encrypted: !!key,
    load() {
      let text: string;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return { entries: [], unreadable: 0 };
        throw e;
      }
      const entries: AuditEntry[] = [];
      let unreadable = 0;
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        const e = decode(line);
        e ? entries.push(e) : unreadable++;
      }
      return { entries, unreadable };
    },
    append(entry) {
      fs.appendFileSync(file, encode(entry) + "\n", { mode: 0o600 });
    },
    close() {
      key?.fill(0);
    },
    rewrite(entries) {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, entries.map((e) => encode(e) + "\n").join(""), { mode: 0o600 });
      fs.renameSync(tmp, file);
    },
  };
}

export interface AuditQuery {
  user?: string;
  host?: string;
  type?: string;
  from?: number;
  limit?: number;
  offset?: number;
}

export interface AuditStatus {
  stored: boolean;
  file?: string;
  encrypted: boolean;
  error?: string;
  unreadable: number;
  retentionDays: number;
}

const DAY = 86_400_000;
const MAX_ENTRIES = 100_000;

export class AuditLog {
  private entries: AuditEntry[] = [];
  private error: string | undefined;
  private unreadable = 0;
  private timer: NodeJS.Timeout | undefined;
  private readonly now: () => number;
  readonly retentionDays: number;

  constructor(private opts: { sink?: AuditSink; retentionDays?: number; now?: () => number; onError?: (message: string) => void } = {}) {
    this.retentionDays = opts.retentionDays ?? 90;
    this.now = opts.now ?? Date.now;
    if (opts.sink) {
      try {
        const loaded = opts.sink.load();
        this.entries = loaded.entries.sort((a, b) => a.at - b.at);
        this.unreadable = loaded.unreadable;
      } catch (e) {
        this.fail(e);
      }
    }
    this.prune();
    this.timer = setInterval(() => this.prune(), DAY / 2);
    this.timer.unref();
  }

  private fail(e: unknown) {
    const message = (e as Error).message ?? String(e);
    if (!this.error) this.opts.onError?.(message);
    this.error = message;
  }

  add(e: Omit<AuditEntry, "id" | "at" | "host" | "detail"> & { at?: number; host?: string; detail?: string }) {
    const entry: AuditEntry = {
      id: crypto.randomBytes(6).toString("hex"),
      at: e.at ?? this.now(),
      kind: e.kind,
      user: e.user.slice(0, 80),
      ip: e.ip.slice(0, 64),
      host: (e.host ?? "").slice(0, 120),
      detail: (e.detail ?? "").replace(/[\r\n]+/g, " ").slice(0, 300),
    };
    this.entries.push(entry);
    if (this.entries.length > MAX_ENTRIES) this.entries.splice(0, this.entries.length - MAX_ENTRIES);
    if (!this.opts.sink) return;
    try {
      this.opts.sink.append(entry);
      this.error = undefined;
    } catch (err) {
      this.fail(err);
    }
  }

  prune(): number {
    const cutoff = this.now() - this.retentionDays * DAY;
    const keep = this.entries.filter((e) => e.at >= cutoff);
    const dropped = this.entries.length - keep.length;
    if (!dropped) return 0;
    this.entries = keep;
    try {
      this.opts.sink?.rewrite(keep);
    } catch (e) {
      this.fail(e);
    }
    return dropped;
  }

  stop() {
    clearInterval(this.timer);
    this.opts.sink?.close();
  }

  private matching(q: AuditQuery): AuditEntry[] {
    const out: AuditEntry[] = [];
    for (let i = this.entries.length - 1; i >= 0; i--) {
      const e = this.entries[i];
      if (q.from !== undefined && e.at < q.from) continue;
      if (q.user && e.user !== q.user) continue;
      if (q.host && e.host !== q.host) continue;
      if (q.type && q.type !== "all") {
        const k = AUDIT_KINDS[e.kind];
        if (q.type === "fail" ? !("bad" in k) : k.group !== q.type) continue;
      }
      out.push(e);
    }
    return out.sort((a, b) => b.at - a.at);
  }

  query(q: AuditQuery): { items: AuditEntry[]; total: number } {
    const all = this.matching(q);
    const limit = Math.min(Math.max(q.limit ?? 50, 1), 500);
    const offset = Math.max(q.offset ?? 0, 0);
    return { items: all.slice(offset, offset + limit), total: all.length };
  }

  all(q: AuditQuery): AuditEntry[] {
    return this.matching(q);
  }

  choices(): { users: string[]; hosts: string[] } {
    return {
      users: [...new Set(this.entries.map((e) => e.user).filter(Boolean))].sort(),
      hosts: [...new Set(this.entries.map((e) => e.host).filter(Boolean))].sort(),
    };
  }

  status(): AuditStatus {
    return {
      stored: !!this.opts.sink && !this.error,
      file: this.opts.sink ? path.basename(this.opts.sink.file) : undefined,
      encrypted: !!this.opts.sink?.encrypted,
      error: this.error,
      unreadable: this.unreadable,
      retentionDays: this.retentionDays,
    };
  }
}

const FORMULA = /^[=+\-@\t\r]/;

export function auditCsv(entries: AuditEntry[]): string {
  const cell = (v: string) => {
    const safe = FORMULA.test(v) ? "'" + v : v;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const rows = entries.map((e) => [new Date(e.at).toISOString(), e.user, AUDIT_KINDS[e.kind].label, e.host, e.ip, e.detail]);
  return [["time", "user", "event", "host", "from", "details"], ...rows].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}
