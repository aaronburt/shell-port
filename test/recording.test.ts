import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import ssh2 from "ssh2";
import WebSocket from "ws";
import { validateConfig, type LoadedConfig } from "../src/server/config.js";
import { createApp } from "../src/server/app.js";
import { RecordingError, RecordingStore } from "../src/server/recording.js";
import { base32Encode, hotp } from "../src/server/totp.js";
import { generateEd25519 } from "./keys.js";

const { Server, utils } = ssh2;
const DAY = 86_400_000;
const MB = 1024 * 1024;
const KEY = Buffer.alloc(32, 5);
const TOTP_KEY = crypto.randomBytes(20);
const hostKey = generateEd25519();
const hostPub = utils.parseKey(hostKey.private) as any;
const fp = "SHA256:" + crypto.createHash("sha256").update(hostPub.getPublicSSH()).digest("base64").replace(/=+$/, "");

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "shellport-rec-"));
}

function parseCast(text: string) {
  const lines = text.trim().split("\n").map((l) => JSON.parse(l));
  return { header: lines[0], events: lines.slice(1) };
}

const plainStore = (over: Partial<ConstructorParameters<typeof RecordingStore>[0]> = {}) =>
  new RecordingStore({ dir: tmp(), retentionDays: 90, maxBytes: MB, ...over });

const startOpts = { hostId: "web1", host: "web 1", user: "aaron", ip: "203.0.113.7", cols: 80, rows: 24 };

test("a plain recording is asciicast v2 with output and resize events only", () => {
  let now = Date.UTC(2026, 10, 3, 10, 0, 0);
  const dir = tmp();
  const store = plainStore({ dir, now: () => now });
  const rec = store.start(startOpts);
  now += 1500;
  rec.output(Buffer.from("hello\r\n"));
  now += 500;
  rec.resize(100, 30);
  rec.output(Buffer.from([0xe2, 0x82])); // first two bytes of a euro sign: nothing complete yet
  rec.output(Buffer.from([0xac, 0x0a]));
  rec.finish("complete", "Browser disconnected");

  const meta = store.list()[0];
  assert.equal(meta.status, "complete");
  assert.equal(meta.reason, "Browser disconnected");
  assert.equal(meta.user, "aaron");
  const { text } = store.read(meta.id);
  const { header, events } = parseCast(text);
  assert.deepEqual(header, { version: 2, width: 80, height: 24, timestamp: Math.floor(Date.UTC(2026, 10, 3, 10) / 1000), env: { TERM: "xterm-256color" } });
  assert.deepEqual(events, [[1.5, "o", "hello\r\n"], [2, "r", "100x30"], [2, "o", "€\n"]]);
  assert.equal(meta.bytes, fs.statSync(path.join(dir, meta.hostId, `${meta.id}.cast`)).size);
  assert.ok(!events.some((e) => e[1] === "i"), "typed input is never recorded");
});

test("a sealed recording is encrypted line by line and only opens with the same key", () => {
  const dir = tmp();
  const store = new RecordingStore({ dir, key: KEY, retentionDays: 90, maxBytes: MB });
  const rec = store.start({ ...startOpts, hostId: "db", host: "db-01" });
  rec.output(Buffer.from("SECRET-OUTPUT-MARKER\r\n"));
  rec.finish("complete");
  const id = store.list()[0].id;
  const castFile = path.join(dir, "db", `${id}.cast`);
  const metaFile = path.join(dir, "db", `${id}.json`);
  const raw = fs.readFileSync(castFile, "utf8");
  assert.ok(!raw.includes("SECRET-OUTPUT-MARKER") && !raw.includes("db-01"));
  assert.ok(raw.split("\n").filter(Boolean).every((l) => l.startsWith("e1.")));
  assert.ok(!fs.readFileSync(metaFile, "utf8").includes("db-01"));
  assert.equal(fs.statSync(castFile).mode & 0o777, 0o600);
  assert.match(store.read(id).text, /SECRET-OUTPUT-MARKER/);
  store.stop();

  const again = new RecordingStore({ dir, key: KEY, retentionDays: 90, maxBytes: MB });
  assert.equal(again.get(id)?.host, "db-01");
  assert.match(again.read(id).text, /SECRET-OUTPUT-MARKER/);
  const wrong = new RecordingStore({ dir, key: Buffer.alloc(32, 6), retentionDays: 90, maxBytes: MB });
  assert.deepEqual(wrong.list(), []);
  assert.deepEqual(new RecordingStore({ dir: tmp(), retentionDays: 90, maxBytes: MB }).list(), []);
  again.stop();
  wrong.stop();
});

test("recordings refuse to start when the store is unavailable, and no file is created", () => {
  const dir = tmp();
  const store = new RecordingStore({ dir, retentionDays: 90, maxBytes: MB, unavailable: "the server has no key" });
  assert.equal(store.status().available, false);
  assert.throws(() => store.start(startOpts), (e) => e instanceof RecordingError && e.code === "unavailable");
  assert.deepEqual(fs.readdirSync(dir), []);
});

test("a recording stops at its size limit, keeps what was written, and is marked failed", () => {
  const store = plainStore({ maxBytes: 400 });
  const rec = store.start(startOpts);
  let thrown: unknown;
  try {
    for (let i = 0; i < 100; i++) rec.output(Buffer.from(`line ${i}\n`));
  } catch (e) {
    thrown = e;
  }
  assert.ok(thrown instanceof RecordingError && thrown.code === "limit");
  rec.finish("failed", (thrown as Error).message);
  const meta = store.list()[0];
  assert.equal(meta.status, "failed");
  assert.ok(meta.bytes <= 400);
  const { text } = store.read(meta.id);
  assert.match(text, /line 0/);
  assert.doesNotMatch(text, /line 99/);
});

test("a running recording cannot be deleted, and finished ones can", () => {
  const store = plainStore();
  const rec = store.start(startOpts);
  assert.throws(() => store.remove(rec.id), (e) => e instanceof RecordingError && e.code === "live");
  rec.finish("complete");
  assert.equal(store.remove(rec.id), true);
  assert.equal(store.get(rec.id), undefined);
  assert.equal(store.remove(rec.id), false);
});

test("recordings past the retention window are deleted, and running ones are kept", () => {
  let now = Date.UTC(2026, 0, 1);
  const dir = tmp();
  const store = new RecordingStore({ dir, retentionDays: 10, maxBytes: MB, now: () => now });
  const old = store.start(startOpts);
  old.output(Buffer.from("old\r\n"));
  old.finish("complete");
  const running = store.start(startOpts);
  now += 11 * DAY;
  assert.equal(store.prune(), 1);
  assert.deepEqual(store.list().map((m) => m.id), [running.id]);
  assert.equal(fs.existsSync(path.join(dir, "web1", `${old.id}.cast`)), false);
  running.finish("complete");
  store.stop();
});

test("a recording left running by a crash is marked partial when the store next opens", () => {
  const dir = tmp();
  const first = new RecordingStore({ dir, retentionDays: 90, maxBytes: MB });
  const rec = first.start(startOpts);
  rec.output(Buffer.from("written before the crash\r\n"));
  // No finish(): the process went away.
  const second = new RecordingStore({ dir, retentionDays: 90, maxBytes: MB });
  const meta = second.get(rec.id)!;
  assert.equal(meta.status, "partial");
  assert.match(meta.reason ?? "", /Server stopped/);
  assert.match(second.read(rec.id).text, /written before the crash/);
  assert.equal(second.remove(rec.id), true);
  first.stop();
  second.stop();
});

test("recording settings are validated with sensible defaults", () => {
  const base = {
    server: { publicUrl: "https://ssh.example.com" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: "aaronburt", totpSecret: base32Encode(Buffer.alloc(20, 3)) }],
    hosts: [{ id: "h1", host: "10.0.0.5", username: "deploy", auth: { type: "password", password: "x" }, hostKeyFingerprints: [fp] }],
  };
  const load = (recording?: unknown): LoadedConfig => validateConfig({ ...base, ...(recording === undefined ? {} : { recording }) }, ".");
  assert.deepEqual(load().recording, { enabled: true, retentionDays: 90, maxMB: 100 });
  assert.deepEqual(load({ enabled: false, retentionDays: 30, maxMB: 5 }).recording, { enabled: false, retentionDays: 30, maxMB: 5 });
  assert.throws(() => load({ enabled: "yes" }), /recording\.enabled/);
  assert.throws(() => load({ maxMB: 0 }), /recording\.maxMB/);
  assert.throws(() => load({ retentionDays: 1.5 }), /recording\.retentionDays/);
  assert.throws(() => load([]), /recording must be an object/);
});

// ---- End to end: the real WebSocket proxy against a fake SSH server ----

const sshd = new Server({ hostKeys: [hostKey.private] }, (client) => {
  client.on("authentication", (ctx) =>
    ctx.method === "password" && ctx.username === "deploy" && ctx.password === "s3cret" ? ctx.accept() : ctx.reject(["password"]));
  client.on("ready", () => {
    client.on("session", (accept) => {
      const session = accept();
      session.on("pty", (acc) => acc?.());
      session.on("window-change", (acc) => acc?.());
      session.on("shell", (acc) => {
        const ch = acc();
        ch.write("banner-ok\r\n");
        ch.on("data", (d: Buffer) => {
          const s = d.toString();
          // Input is never echoed, so anything recorded from the typed text would be a leak.
          if (s.includes("print")) ch.write("printed-output\r\n");
          if (s.includes("big")) ch.write("B".repeat(200) + "\r\n");
          if (s.includes("exit")) { ch.exit(0); ch.end(); }
        });
      });
    });
  });
  client.on("error", () => {});
});

let sshPort = 0;
let nextLogin = "aaronburt";
const apps: Array<{ server: import("node:http").Server; shutdown: () => Promise<void> }> = [];

function config(port: number, publicUrl: string): LoadedConfig {
  return validateConfig({
    server: { port, publicUrl },
    github: { clientId: "id", clientSecret: "secret" },
    users: [
      { github: "aaronburt", totpSecret: base32Encode(TOTP_KEY), admin: true },
      { github: "other", totpSecret: base32Encode(TOTP_KEY) },
    ],
    limits: { loginAttemptsPer15Min: 200 },
    hosts: [{ id: "rec-host", name: "rec-host", host: "127.0.0.1", port: sshPort, username: "deploy",
      auth: { type: "password", password: "s3cret" }, hostKeyFingerprints: [fp] }],
  }, process.cwd());
}

async function startApp(recordings: RecordingStore | undefined) {
  const probe = (await import("node:net")).createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r()));
  const port = (probe.address() as AddressInfo).port;
  await new Promise((r) => probe.close(r));
  const base = `http://127.0.0.1:${port}`;
  const cfg = config(port, base);
  const app = createApp(cfg, {
    publicDir: path.resolve("dist/public"),
    recordings,
    exchange: async (code) => {
      if (code !== "good") throw new Error("bad code");
      return { id: nextLogin === "other" ? 2 : 1, login: nextLogin, name: nextLogin };
    },
  });
  await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  apps.push({ server: app.server, shutdown: () => app.shutdown(1000, "test") });
  return { app, base };
}

const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

async function signIn(base: string, login: string): Promise<string> {
  nextLogin = login;
  const start = await fetch(`${base}/auth/github`, { redirect: "manual" });
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const cb = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  const pending = cb.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
  const r = await fetch(`${base}/auth/totp`, {
    method: "POST",
    headers: { cookie: pending, origin: base, "content-type": "application/json" },
    body: JSON.stringify({ code: hotp(TOTP_KEY, Math.floor(Date.now() / 30_000)) }),
  });
  assert.equal(r.status, 204);
  return r.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
}

const api = (base: string, cookie: string, path: string, init: RequestInit = {}) =>
  fetch(`${base}${path}`, { ...init, headers: { cookie, origin: base, ...(init.headers ?? {}) } });

function openSession(base: string, cookie: string, host = "rec-host") {
  const ws = new WebSocket(`${base.replace("http", "ws")}/ws?host=${host}&cols=80&rows=24`, { headers: { cookie, origin: base } });
  const json: any[] = [];
  let out = "";
  ws.on("message", (d, bin) => (bin ? (out += d.toString()) : json.push(JSON.parse(d.toString()))));
  const waitFor = (pred: () => boolean, ms = 5000) =>
    new Promise<void>((res, rej) => {
      const t0 = Date.now();
      const iv = setInterval(() => {
        if (pred()) { clearInterval(iv); res(); }
        else if (Date.now() - t0 > ms) { clearInterval(iv); rej(new Error(`timeout; json=${JSON.stringify(json)} out=${out}`)); }
      }, 20);
    });
  return { ws, json, get out() { return out; }, waitFor, closed: () => json.some((m) => m.t === "status" && m.state === "closed") };
}

async function eventually<T>(read: () => Promise<T>, done: (v: T) => boolean, ms = 5000): Promise<T> {
  const t0 = Date.now();
  for (;;) {
    const v = await read();
    if (done(v)) return v;
    if (Date.now() - t0 > ms) throw new Error("timed out waiting for the recording");
    await new Promise((r) => setTimeout(r, 25));
  }
}

let recordingDir = "";
let store: RecordingStore;
let main: { app: ReturnType<typeof createApp>; base: string };
// A user's authenticator code can only be used once, so each user signs in once per app and shares the cookie.
let adminCookie = "";

before(async () => {
  await new Promise<void>((r) => sshd.listen(0, "127.0.0.1", () => r()));
  sshPort = (sshd.address() as AddressInfo).port;
  recordingDir = tmp();
  store = new RecordingStore({ dir: recordingDir, retentionDays: 90, maxBytes: MB });
  main = await startApp(store);
});

after(async () => {
  for (const a of apps) await a.shutdown();
  store?.stop();
  sshd.close();
  fs.rmSync(recordingDir, { recursive: true, force: true });
  setTimeout(() => process.exit(0), 50).unref();
});

test("a session is recorded as output only, listed for admins, and linked from its connect entry", async () => {
  const { base, app } = main;
  const admin = (adminCookie = await signIn(base, "aaronburt"));
  const empty = await api(base, admin, "/api/recordings");
  assert.equal(empty.status, 200);
  assert.deepEqual((await empty.json()).items, []);

  const t = openSession(base, admin);
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  assert.equal(t.json.find((m) => m.state === "connected").info.recording, true);
  await t.waitFor(() => t.out.includes("banner-ok"));
  t.ws.send(Buffer.from("typed-secret-xyz"), { binary: true });
  t.ws.send(Buffer.from("print\r"), { binary: true });
  await t.waitFor(() => t.out.includes("printed-output"));
  t.ws.send(JSON.stringify({ t: "resize", cols: 100, rows: 30 }));
  await eventually(() => api(base, admin, `/api/recordings/${store.list()[0].id}`).then((r) => r.text()), (text) => text.includes('"100x30"'));
  t.ws.close();
  await t.waitFor(() => t.ws.readyState === WebSocket.CLOSED);

  const list = await eventually(() => api(base, admin, "/api/recordings").then((r) => r.json()), (j) => j.items[0]?.status === "complete");
  const [meta] = list.items;
  assert.equal(meta.hostId, "rec-host");
  assert.equal(meta.user, "aaronburt");

  const view = await api(base, admin, `/api/recordings/${meta.id}`);
  assert.equal(view.status, 200);
  const { header, events } = parseCast(await view.text());
  assert.equal(header.version, 2);
  assert.deepEqual(events.map((e) => e[1]), ["o", "o", "r"]);
  assert.match(events.map((e) => e[2]).join(""), /banner-ok[\s\S]*printed-output/);
  assert.ok(!JSON.stringify(events).includes("typed-secret-xyz"), "typed input must not be recorded");

  const download = await api(base, admin, `/api/recordings/${meta.id}/download`);
  assert.equal(download.status, 200);
  assert.match(download.headers.get("content-disposition") ?? "", /attachment; filename="shellport-rec-host-/);
  assert.equal(await download.text(), await (await api(base, admin, `/api/recordings/${meta.id}`)).text());

  const connect = app.auditLog.all({ user: "aaronburt" }).find((e) => e.kind === "ssh_connect");
  assert.equal(connect?.ref, meta.id);
  const kinds = app.auditLog.all({ type: "Recordings" }).map((e) => e.kind);
  assert.ok(kinds.includes("recording_viewed") && kinds.includes("recording_downloaded"));
});

test("only admins can list, read, download or delete recordings", async () => {
  const { base } = main;
  const id = store.list()[0].id;
  const other = await signIn(base, "other");
  assert.equal((await api(base, other, "/api/recordings")).status, 403);
  assert.equal((await api(base, other, `/api/recordings/${id}`)).status, 403);
  assert.equal((await api(base, other, `/api/recordings/${id}/download`)).status, 403);
  assert.equal((await api(base, other, `/api/recordings/${id}`, { method: "DELETE" })).status, 403);
  assert.equal(store.list().length, 1);
});

test("an admin can delete a finished recording, and the audit log says so", async () => {
  const { base, app } = main;
  const admin = adminCookie;
  const id = store.list()[0].id;
  const removed = await api(base, admin, `/api/recordings/${id}`, { method: "DELETE" });
  assert.equal(removed.status, 200);
  assert.deepEqual((await (await api(base, admin, "/api/recordings")).json()).items, []);
  assert.equal((await api(base, admin, `/api/recordings/${id}`)).status, 404);
  assert.ok(app.auditLog.all({ type: "Recordings" }).some((e) => e.kind === "recording_deleted"));
});

test("when recording cannot start, the session does not open and nothing is forwarded", async () => {
  const broken = new RecordingStore({ dir: tmp(), retentionDays: 90, maxBytes: MB, unavailable: "the server has no key to encrypt recordings" });
  const { base } = await startApp(broken);
  const cookie = await signIn(base, "aaronburt");
  const t = openSession(base, cookie);
  await t.waitFor(() => t.closed());
  assert.ok(t.json.some((m) => m.t === "error" && /recording is unavailable/.test(m.message)));
  assert.ok(!t.json.some((m) => m.state === "connected"));
  assert.equal(t.out.includes("banner-ok"), false);
  assert.equal(broken.list().length, 0);
});

test("a recording that reaches its size limit closes the session before the overflow is shown", async () => {
  const small = new RecordingStore({ dir: tmp(), retentionDays: 90, maxBytes: 400 });
  const { base } = await startApp(small);
  const cookie = await signIn(base, "aaronburt");
  const t = openSession(base, cookie);
  await t.waitFor(() => t.out.includes("banner-ok"));
  t.ws.send(Buffer.from("big\r"), { binary: true });
  await t.waitFor(() => t.out.split("B").length - 1 === 200);
  t.ws.send(Buffer.from("big\r"), { binary: true });
  await t.waitFor(() => t.closed());
  assert.ok(t.json.some((m) => m.t === "error" && /recording size limit/.test(m.message)));
  assert.equal(t.out.split("B").length - 1, 200, "the chunk that overflowed the limit is not forwarded");
  const [meta] = small.list();
  assert.equal(meta.status, "failed");
  assert.match(meta.reason ?? "", /limit/);
  assert.ok(small.read(meta.id).text.includes("banner-ok"));
});
