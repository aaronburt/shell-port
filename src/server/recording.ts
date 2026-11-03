import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";

// Session recordings keep what the terminal printed (asciicast v2 output events) and nothing the
// user typed. Each SSH session gets one .cast file plus a small .json sidecar with its details.
// When the server is sealed, every line of both files is encrypted with a key derived from the
// vault key, the same way the audit log is.

const DAY = 86_400_000;
const MB = 1024 * 1024;
const LINE_PREFIX = "e1.";
const AAD = Buffer.from("shellport recording v1");
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const ID_RE = /^[a-f0-9]{24}$/;

export const RECORDING_STATUSES = ["recording", "complete", "partial", "failed"] as const;
export type RecordingStatus = (typeof RECORDING_STATUSES)[number];

export interface RecordingMeta {
  id: string;
  hostId: string;
  host: string;
  user: string;
  ip: string;
  startedAt: number;
  endedAt?: number;
  bytes: number;
  cols: number;
  rows: number;
  status: RecordingStatus;
  reason?: string;
}

export type RecordingErrorCode = "limit" | "live" | "missing" | "unavailable" | "write";

export class RecordingError extends Error {
  constructor(message: string, readonly code: RecordingErrorCode) {
    super(message);
  }
}

export interface RecordingStart {
  hostId: string;
  host: string;
  user: string;
  ip: string;
  cols: number;
  rows: number;
}

export interface RecordingStoreOptions {
  dir: string;
  /** Vault key. When set, every line is encrypted; when absent, files are plain asciicast. */
  key?: Buffer;
  retentionDays: number;
  maxBytes: number;
  now?: () => number;
  onError?: (message: string) => void;
  /** Set when recording cannot work on this server. Every start() then fails, so sessions do not open unrecorded. */
  unavailable?: string;
}

function subKey(dek: Buffer): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", dek, Buffer.alloc(0), "shellport recording v1", 32));
}

function codec(key: Buffer | undefined) {
  return {
    encode(text: string): string {
      if (!key) return text;
      const nonce = crypto.randomBytes(12);
      const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
      c.setAAD(AAD);
      const body = Buffer.concat([c.update(text, "utf8"), c.final(), c.getAuthTag()]);
      return LINE_PREFIX + nonce.toString("base64url") + "." + body.toString("base64url");
    },
    decode(line: string): string | undefined {
      try {
        if (!key) return line.startsWith(LINE_PREFIX) ? undefined : line;
        if (!line.startsWith(LINE_PREFIX)) return undefined;
        const [n, b] = line.slice(LINE_PREFIX.length).split(".");
        const body = Buffer.from(b, "base64url");
        if (body.length < 16) return undefined;
        const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(n, "base64url"));
        d.setAAD(AAD);
        d.setAuthTag(body.subarray(body.length - 16));
        return Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]).toString("utf8");
      } catch {
        return undefined;
      }
    },
  };
}

function formatBytes(bytes: number): string {
  return bytes >= MB ? `${Math.round(bytes / MB)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function isMeta(v: unknown): v is RecordingMeta {
  if (!v || typeof v !== "object") return false;
  const m = v as Record<string, unknown>;
  return typeof m.id === "string" && ID_RE.test(m.id) &&
    typeof m.hostId === "string" && SAFE_NAME.test(m.hostId) &&
    typeof m.host === "string" && typeof m.user === "string" && typeof m.ip === "string" &&
    typeof m.startedAt === "number" && typeof m.bytes === "number" &&
    typeof m.cols === "number" && typeof m.rows === "number" &&
    typeof m.status === "string" && (RECORDING_STATUSES as readonly string[]).includes(m.status) &&
    (m.endedAt === undefined || typeof m.endedAt === "number") &&
    (m.reason === undefined || typeof m.reason === "string");
}

interface Owner {
  readonly maxBytes: number;
  now(): number;
  encode(text: string): string;
  settle(meta: RecordingMeta): void;
  warn(message: string): void;
}

/** One session being recorded. Every write goes to disk before the caller forwards the bytes. */
export class LiveRecording {
  readonly id: string;
  private readonly started: number;
  private readonly decoder = new StringDecoder("utf8");
  private size = 0;
  private elapsed = 0;
  private cols: number;
  private rows: number;
  private done = false;

  constructor(private readonly owner: Owner, private readonly meta: RecordingMeta, private readonly fd: number) {
    this.id = meta.id;
    this.started = meta.startedAt;
    this.cols = meta.cols;
    this.rows = meta.rows;
    this.writeLine(JSON.stringify({
      version: 2,
      width: meta.cols,
      height: meta.rows,
      timestamp: Math.floor(meta.startedAt / 1000),
      env: { TERM: "xterm-256color" },
    }));
  }

  /** Terminal output (stdout and stderr). Throws if the write fails or the size limit would be passed. */
  output(data: Buffer) {
    this.event("o", this.decoder.write(data));
  }

  resize(cols: number, rows: number) {
    if (cols === this.cols && rows === this.rows) return;
    this.cols = cols;
    this.rows = rows;
    this.event("r", `${cols}x${rows}`);
  }

  /** Ends the recording. Never throws; a failure to save the details is reported through onError. */
  finish(status: Exclude<RecordingStatus, "recording">, reason?: string) {
    if (this.done) return;
    try {
      const tail = this.decoder.end();
      if (tail) this.event("o", tail);
    } catch {
      // The session is ending anyway; keep what was already written.
    }
    this.done = true;
    try {
      fs.closeSync(this.fd);
    } catch (e) {
      this.owner.warn(`a recording file could not be closed (${(e as Error).message})`);
    }
    this.meta.status = status;
    this.meta.endedAt = this.owner.now();
    this.meta.bytes = this.size;
    if (reason) this.meta.reason = reason.slice(0, 200);
    this.owner.settle(this.meta);
  }

  private event(code: "o" | "r", data: string) {
    if (this.done) throw new RecordingError("This recording has already finished", "write");
    if (!data) return;
    const t = Math.max(this.elapsed, (this.owner.now() - this.started) / 1000);
    this.elapsed = t;
    this.writeLine(JSON.stringify([Number(t.toFixed(6)), code, data]));
  }

  private writeLine(json: string) {
    const line = Buffer.from(this.owner.encode(json) + "\n", "utf8");
    if (this.size + line.length > this.owner.maxBytes) {
      throw new RecordingError(`Recording reached its limit of ${formatBytes(this.owner.maxBytes)}`, "limit");
    }
    let off = 0;
    while (off < line.length) off += fs.writeSync(this.fd, line, off, line.length - off);
    this.size += line.length;
  }
}

export class RecordingStore {
  private readonly index = new Map<string, RecordingMeta>();
  private readonly live = new Map<string, LiveRecording>();
  private readonly key: Buffer | undefined;
  private readonly codec: ReturnType<typeof codec>;
  private readonly now: () => number;
  private readonly owner: Owner;
  private error: string | undefined;
  private stopped = false;
  private timer: NodeJS.Timeout | undefined;

  constructor(private readonly opts: RecordingStoreOptions) {
    this.now = opts.now ?? Date.now;
    this.key = opts.key ? subKey(opts.key) : undefined;
    this.codec = codec(this.key);
    this.owner = {
      maxBytes: opts.maxBytes,
      now: this.now,
      encode: (text) => this.codec.encode(text),
      settle: (meta) => this.settle(meta),
      warn: (message) => this.report(message),
    };
    if (opts.unavailable) {
      this.error = opts.unavailable;
    } else {
      try {
        fs.mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
        this.loadIndex();
      } catch (e) {
        this.fail(e);
      }
    }
    this.prune();
    this.timer = setInterval(() => this.prune(), DAY / 2);
    this.timer.unref();
  }

  get encrypted(): boolean {
    return !!this.key;
  }

  /** Opens a new recording for a session. Throws RecordingError when none can be started. */
  start(info: RecordingStart): LiveRecording {
    if (this.error || this.stopped) {
      throw new RecordingError(`Session recording is unavailable${this.error ? ` (${this.error})` : ""}`, "unavailable");
    }
    if (!SAFE_NAME.test(info.hostId)) throw new RecordingError("The host id cannot be used as a folder name", "unavailable");
    const meta: RecordingMeta = {
      id: crypto.randomBytes(12).toString("hex"),
      hostId: info.hostId,
      host: info.host.slice(0, 120),
      user: info.user.slice(0, 80),
      ip: info.ip.slice(0, 64),
      startedAt: this.now(),
      bytes: 0,
      cols: info.cols,
      rows: info.rows,
      status: "recording",
    };
    const dir = path.join(this.opts.dir, meta.hostId);
    const file = this.castFile(meta);
    let fd: number | undefined;
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fd = fs.openSync(file, "wx", 0o600);
      this.persist(meta);
      this.index.set(meta.id, meta);
      const rec = new LiveRecording(this.owner, meta, fd);
      this.live.set(meta.id, rec);
      return rec;
    } catch (e) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      this.index.delete(meta.id);
      fs.rmSync(file, { force: true });
      fs.rmSync(this.metaFile(meta), { force: true });
      if (e instanceof RecordingError) throw e;
      throw new RecordingError(`The recording could not be started (${(e as Error).message})`, "write");
    }
  }

  list(): RecordingMeta[] {
    return [...this.index.values()].sort((a, b) => b.startedAt - a.startedAt).map((m) => ({ ...m }));
  }

  get(id: string): RecordingMeta | undefined {
    const m = this.index.get(id);
    return m && { ...m };
  }

  /** The recording as asciicast v2 text, decrypted. Lines that cannot be decrypted are counted, not shown. */
  read(id: string): { text: string; unreadable: number } {
    const meta = this.index.get(id);
    if (!meta) throw new RecordingError("Recording not found", "missing");
    const raw = fs.readFileSync(this.castFile(meta), "utf8");
    const lines: string[] = [];
    let unreadable = 0;
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      const json = this.codec.decode(line);
      if (json === undefined) unreadable++;
      else lines.push(json);
    }
    return { text: lines.map((l) => l + "\n").join(""), unreadable };
  }

  remove(id: string): boolean {
    const meta = this.index.get(id);
    if (!meta) return false;
    if (this.live.has(id)) throw new RecordingError("This recording is still running", "live");
    fs.rmSync(this.castFile(meta), { force: true });
    fs.rmSync(this.metaFile(meta), { force: true });
    this.index.delete(id);
    return true;
  }

  /** Deletes recordings that started before the retention window. Returns how many were removed. */
  prune(): number {
    const cutoff = this.now() - this.opts.retentionDays * DAY;
    let dropped = 0;
    for (const m of [...this.index.values()]) {
      if (m.startedAt >= cutoff || this.live.has(m.id)) continue;
      try {
        if (this.remove(m.id)) dropped++;
      } catch (e) {
        this.report(`an expired recording could not be deleted (${(e as Error).message})`);
      }
    }
    return dropped;
  }

  /** Ends any recordings still open and drops the key from memory. Call before the server seals. */
  stop() {
    if (this.stopped) return;
    for (const rec of [...this.live.values()]) rec.finish("partial", "Server stopped while recording");
    this.stopped = true;
    clearInterval(this.timer);
    this.key?.fill(0);
  }

  status() {
    return {
      available: !this.error && !this.stopped,
      error: this.error,
      encrypted: this.encrypted,
      retentionDays: this.opts.retentionDays,
      maxMB: Math.round(this.opts.maxBytes / MB),
    };
  }

  private castFile(meta: RecordingMeta) {
    return path.join(this.opts.dir, meta.hostId, `${meta.id}.cast`);
  }

  private metaFile(meta: RecordingMeta) {
    return path.join(this.opts.dir, meta.hostId, `${meta.id}.json`);
  }

  private persist(meta: RecordingMeta) {
    const file = this.metaFile(meta);
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, this.codec.encode(JSON.stringify(meta)) + "\n", { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  private settle(meta: RecordingMeta) {
    this.live.delete(meta.id);
    this.index.set(meta.id, meta);
    try {
      this.persist(meta);
    } catch (e) {
      this.report(`the details of a recording could not be saved (${(e as Error).message})`);
    }
  }

  private loadIndex() {
    for (const host of fs.readdirSync(this.opts.dir, { withFileTypes: true })) {
      if (!host.isDirectory() || !SAFE_NAME.test(host.name)) continue;
      const dir = path.join(this.opts.dir, host.name);
      for (const name of fs.readdirSync(dir)) {
        if (!name.endsWith(".json")) continue;
        const id = name.slice(0, -".json".length);
        if (!ID_RE.test(id)) continue;
        const meta = this.readMeta(path.join(dir, name));
        if (!meta || meta.id !== id || meta.hostId !== host.name) continue;
        const cast = path.join(dir, `${id}.cast`);
        if (!fs.existsSync(cast)) {
          fs.rmSync(path.join(dir, name), { force: true });
          continue;
        }
        if (meta.status === "recording") {
          // Still marked running but no session holds it, so the server stopped before it was finished.
          const stat = fs.statSync(cast);
          meta.status = "partial";
          meta.reason = "Server stopped while recording";
          meta.endedAt = Math.max(stat.mtimeMs, meta.startedAt);
          meta.bytes = stat.size;
          this.persist(meta);
        }
        this.index.set(id, meta);
      }
    }
  }

  private readMeta(file: string): RecordingMeta | undefined {
    try {
      const json = this.codec.decode(fs.readFileSync(file, "utf8").trim());
      const v = json === undefined ? undefined : JSON.parse(json);
      return isMeta(v) ? v : undefined;
    } catch {
      return undefined;
    }
  }

  private fail(e: unknown) {
    const message = (e as Error).message ?? String(e);
    if (!this.error) this.opts.onError?.(message);
    this.error = message;
  }

  private report(message: string) {
    this.opts.onError?.(message);
  }
}
