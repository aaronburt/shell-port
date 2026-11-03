import path from "node:path";
import type { Readable } from "node:stream";
import type { SFTPWrapper, Stats, FileEntryWithStats } from "ssh2";

export const MAX_PATH_LEN = 4096;
export const MAX_ENTRIES = 5000;
export const VIEW_BYTES = 256 * 1024;
export const OP_TIMEOUT_MS = 30_000;

const SFTP_NO_SUCH_FILE = 2;
const SFTP_PERMISSION_DENIED = 3;

export class FileError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

export function cleanPath(input: unknown): string {
  if (typeof input !== "string" || !input || input.length > MAX_PATH_LEN) throw new FileError(400, "bad_path");
  if (/[\x00-\x1f\x7f]/.test(input) || !input.startsWith("/")) throw new FileError(400, "bad_path");
  if (input.split("/").some((seg) => seg === "..")) throw new FileError(400, "bad_path");
  return path.posix.normalize(input).replace(/(.)\/+$/, "$1");
}

export function describeError(e: unknown): FileError {
  if (e instanceof FileError) return e;
  const code = (e as { code?: unknown })?.code;
  if (code === SFTP_NO_SUCH_FILE) return new FileError(404, "not_found");
  if (code === SFTP_PERMISSION_DENIED) return new FileError(403, "permission_denied");
  return new FileError(502, "file_error");
}

export function withTimeout<T>(p: Promise<T>, ms = OP_TIMEOUT_MS): Promise<T> {
  let timer: NodeJS.Timeout;
  const t = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new FileError(504, "timeout")), ms);
  });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

const call = <T>(fn: (cb: (err: Error | null | undefined, value: T) => void) => void): Promise<T> =>
  withTimeout(new Promise<T>((resolve, reject) => fn((err, v) => (err ? reject(err) : resolve(v)))));

export type EntryKind = "dir" | "file" | "link" | "other";

export interface Entry {
  name: string;
  kind: EntryKind;
  size: number;
  mtime: number;
  mode: string;
}

const kindOf = (a: Stats): EntryKind =>
  a.isDirectory() ? "dir" : a.isFile() ? "file" : a.isSymbolicLink() ? "link" : "other";

export function modeString(mode: number, kind: EntryKind): string {
  const t = kind === "dir" ? "d" : kind === "link" ? "l" : kind === "file" ? "-" : "?";
  const bits = "rwxrwxrwx";
  let out = t;
  for (let i = 0; i < 9; i++) out += mode & (1 << (8 - i)) ? bits[i] : "-";
  return out;
}

export async function home(sftp: SFTPWrapper): Promise<string> {
  return cleanPath(await call<string>((cb) => sftp.realpath(".", cb)));
}

export async function list(sftp: SFTPWrapper, dir: string): Promise<{ entries: Entry[]; truncated: boolean }> {
  const raw = await call<FileEntryWithStats[]>((cb) => sftp.readdir(dir, cb));
  const items = raw.filter((r) => r.filename !== "." && r.filename !== "..");
  const truncated = items.length > MAX_ENTRIES;
  const entries = await Promise.all(
    items.slice(0, MAX_ENTRIES).map(async (r): Promise<Entry> => {
      let attrs: Stats = r.attrs;
      let kind = kindOf(attrs);
      if (kind === "link") {
        try {
          const target = await call<Stats>((cb) => sftp.stat(path.posix.join(dir, r.filename), cb));
          attrs = target;
          kind = target.isDirectory() ? "dir" : "link";
        } catch {}
      }
      return { name: r.filename, kind, size: Number(attrs.size) || 0, mtime: Number(attrs.mtime) || 0, mode: modeString(attrs.mode, kind) };
    }),
  );
  return { entries, truncated };
}

export async function preview(sftp: SFTPWrapper, file: string): Promise<{ size: number; truncated: boolean; binary: boolean; text: string }> {
  const st = await call<Stats>((cb) => sftp.stat(file, cb));
  if (!st.isFile()) throw new FileError(400, "not_a_file");
  const size = Number(st.size) || 0;
  const chunks: Buffer[] = [];
  let got = 0;
  if (size > 0) {
    const stream: Readable = sftp.createReadStream(file, { start: 0, end: Math.min(size, VIEW_BYTES) - 1 });
    await withTimeout(new Promise<void>((resolve, reject) => {
      stream.on("data", (c: Buffer) => { chunks.push(c); got += c.length; });
      stream.on("error", reject);
      stream.on("end", resolve);
    })).finally(() => stream.destroy());
  }
  const buf = Buffer.concat(chunks).subarray(0, VIEW_BYTES);
  const binary = buf.includes(0);
  return { size, truncated: size > got, binary, text: binary ? "" : buf.toString("utf8") };
}

export async function fileSize(sftp: SFTPWrapper, file: string): Promise<number> {
  const st = await call<Stats>((cb) => sftp.stat(file, cb));
  if (!st.isFile()) throw new FileError(400, "not_a_file");
  return Number(st.size) || 0;
}

export async function remove(sftp: SFTPWrapper, target: string): Promise<"file" | "dir"> {
  if (target === "/") throw new FileError(400, "bad_path");
  const st = await call<Stats>((cb) => sftp.lstat(target, cb));
  if (st.isDirectory()) {
    try {
      await call<void>((cb) => sftp.rmdir(target, cb));
    } catch (e) {
      throw (e as { code?: unknown })?.code === 4 ? new FileError(409, "cannot_remove") : e;
    }
    return "dir";
  }
  await call<void>((cb) => sftp.unlink(target, cb));
  return "file";
}

export function downloadName(file: string): { ascii: string; utf8: string } {
  const base = path.posix.basename(file) || "download";
  const utf8 = encodeURIComponent(base).replace(/['()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
  const ascii = base.replace(/[^\x20-\x7e]|["\\%;]/g, "_");
  return { ascii, utf8 };
}
