import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import ssh2 from "ssh2";
import WebSocket from "ws";
import { validateConfig, resolveSecret } from "../src/server/config.js";
import { RateLimiter } from "../src/server/sessions.js";
import { feedPassphrase } from "../src/client/passphrase.js";
import { base32Encode, hotp } from "../src/server/totp.js";
import { createApp, clientIp } from "../src/server/app.js";
import { generateEd25519 } from "./keys.js";
import { serveSftp } from "./sftp-fake.js";

const { Server, utils } = ssh2;

const hostKey = generateEd25519();
const hostPub = utils.parseKey(hostKey.private) as any;
const fp = "SHA256:" + crypto.createHash("sha256").update(hostPub.getPublicSSH()).digest("base64").replace(/=+$/, "");
const userKey = generateEd25519("correct horse");
const userPub = utils.parseKey(userKey.public) as any;
const plainKey = generateEd25519();
const secretDir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-test-"));
const FLOOD_BYTES = 24 * 1024 * 1024;
const FLOOD = Buffer.alloc(FLOOD_BYTES, "abcdefghijklmnopqrstuvwxyz0123456789\n");
const sftpRoot = path.join(secretDir, "remote");
for (const d of ["home/demo/docs", "home/demo/empty", "home/demo/full"]) fs.mkdirSync(path.join(sftpRoot, d), { recursive: true });
fs.writeFileSync(path.join(sftpRoot, "home/demo/notes.txt"), "hello from notes\n");
fs.writeFileSync(path.join(sftpRoot, "home/demo/docs/a.txt"), "doc a");
fs.writeFileSync(path.join(sftpRoot, "home/demo/full/x.txt"), "x");
fs.writeFileSync(path.join(sftpRoot, "home/demo/blob.bin"), Buffer.from([1, 2, 0, 3, 4]));
fs.writeFileSync(path.join(sftpRoot, "home/demo/long.txt"), "0123456789".repeat(40_000));
fs.writeFileSync(path.join(sftpRoot, "home/demo/huge.dat"), Buffer.alloc(1536 * 1024, 7));
fs.writeFileSync(path.join(sftpRoot, "home/demo/déjà vu \"q\".txt"), "unicode");
fs.writeFileSync(path.join(sftpRoot, "home/demo/trash1.txt"), "bye");
fs.writeFileSync(path.join(sftpRoot, "home/demo/trash2.txt"), "bye");
fs.symlinkSync("docs", path.join(sftpRoot, "home/demo/docs-link"));
let sshPort = 0;
let lastPty: any;
let lastWindow: any;
const sshd = new Server({ hostKeys: [hostKey.private] }, (client) => {
  client.on("authentication", (ctx) => {
    if (ctx.method === "password" && ctx.username === "deploy" && ctx.password === "s3cret") ctx.accept();
    else if (ctx.method === "publickey" && ctx.username === "deploy" && ctx.key.algo === userPub.type &&
      Buffer.compare(ctx.key.data, userPub.getPublicSSH()) === 0 && (!ctx.signature || userPub.verify(ctx.blob!, ctx.signature, ctx.hashAlgo) === true)) ctx.accept();
    else ctx.reject(["password", "publickey"]);
  });
  client.on("ready", () => {
    client.on("session", (accept) => {
      const session = accept();
      session.on("sftp", (acc) => serveSftp(sftpRoot, acc));
      session.on("pty", (acc, _rej, info) => { lastPty = info; acc?.(); });
      session.on("window-change", (acc, _rej, info) => { lastWindow = info; acc?.(); });
      session.on("shell", (acc) => {
        const ch = acc();
        ch.write("welcome to fake-host\r\n$ ");
        let pasted = Buffer.alloc(0);
        ch.on("data", (d: Buffer) => {
          const s = d.toString();
          if (s.includes("flood")) { ch.write(FLOOD); return; }
          if (pasted.length === 0 && /^[0-9a-f]+$/.test(s)) {
            ch.pause();
            setTimeout(() => ch.resume(), 300);
          }
          pasted = Buffer.concat([pasted, d]);
          const end = pasted.indexOf("<<END>>");
          if (end >= 0) {
            ch.write(`PASTE ${end} ${crypto.createHash("sha256").update(pasted.subarray(0, end)).digest("hex")}\r\n`);
            pasted = Buffer.alloc(0);
            return;
          }
          if (s.includes("exit")) { ch.exit(0); ch.end(); return; }
          if (/^[0-9a-f]+$/.test(s)) return;
          ch.write(s.toUpperCase());
        });
      });
    });
  });
  client.on("error", () => {});
});

let base = "";
let app: ReturnType<typeof createApp>;
let nextUser = "aaronburt";
const TOTP_KEY = crypto.randomBytes(20);
let clock = Date.now();
const timing: { passphraseWaitMs?: number; idleTimeoutMs?: number } = {};
const code = () => hotp(TOTP_KEY, Math.floor(clock / 30_000));
const passwordFile = path.join(secretDir, "password.txt");

let sealCalls = 0;
before(async () => {
  await new Promise<void>((r) => sshd.listen(0, "127.0.0.1", () => r()));
  sshPort = (sshd.address() as AddressInfo).port;
  process.env.TEST_PW = "s3cret";
  fs.writeFileSync(passwordFile, "s3cret\r\n");
  const probe = (await import("node:net")).createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r()));
  const port = (probe.address() as AddressInfo).port;
  await new Promise((r) => probe.close(r));
  base = `http://127.0.0.1:${port}`;
  const cfg = validateConfig({
    server: { port, publicUrl: base },
    github: { clientId: "id", clientSecret: "secret" },
    users: [
      { github: "AaronBurt", totpSecret: base32Encode(TOTP_KEY) },
      { github: "other", totpSecret: base32Encode(TOTP_KEY) },
      { github: 777, totpSecret: base32Encode(TOTP_KEY) },
      { github: 4242, totpSecret: base32Encode(TOTP_KEY) },
      ...["pp1", "pp2", "pp3", "throttle-user", "bystander"].map((github) => ({ github, totpSecret: base32Encode(TOTP_KEY) })),
    ],
    limits: { maxTerminalsPerUser: 3, loginAttemptsPer15Min: 200, maxDownloadMB: 1 },
    hosts: [
      { id: "fake", name: "fake-host", group: "Test", host: "127.0.0.1", port: sshPort, username: "deploy",
        auth: { type: "password", password: { env: "TEST_PW" } }, hostKeyFingerprints: [fp] },
      { id: "nofiles", host: "127.0.0.1", port: sshPort, username: "deploy", files: false,
        auth: { type: "password", password: "s3cret" }, hostKeyFingerprints: [fp] },
      { id: "locked", host: "127.0.0.1", port: sshPort, username: "deploy",
        auth: { type: "key", privateKey: userKey.private }, hostKeyFingerprints: [fp] },
      { id: "wrongkey", host: "127.0.0.1", port: sshPort, username: "deploy",
        auth: { type: "password", password: "s3cret" }, hostKeyFingerprints: ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] },
      { id: "badpw", host: "127.0.0.1", port: sshPort, username: "deploy",
        auth: { type: "password", password: "nope" }, hostKeyFingerprints: [fp] },
      { id: "filepw", host: "127.0.0.1", port: sshPort, username: "deploy",
        auth: { type: "password", password: { file: passwordFile } }, hostKeyFingerprints: [fp] },
      { id: "private", host: "127.0.0.1", port: sshPort, username: "deploy",
        auth: { type: "password", password: "s3cret" }, hostKeyFingerprints: [fp], allowedUsers: ["other"] },
    ],
  }, process.cwd());
  app = createApp(cfg, {
    publicDir: path.resolve("dist/public"),
    onSeal: () => { sealCalls++; },
    now: () => clock,
    timing,
    exchange: async (code) => {
      if (code !== "good") throw new Error("bad code");
      const fixed: Record<string, number> = { mallory: 999, "old-name": 4242, "new-name": 4242, pp1: 5001, pp2: 5002, pp3: 5003, "throttle-user": 5004, bystander: 5005 };
      const id = fixed[nextUser] ?? 42388542;
      return { id, login: nextUser, name: nextUser };
    },
  });
  await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
});

after(() => {
  app.server.close();
  sshd.close();
  fs.rmSync(secretDir, { recursive: true, force: true });
  setTimeout(() => process.exit(0), 50).unref();
});

const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

async function githubStep(user: string): Promise<string> {
  nextUser = user;
  const start = await fetch(`${base}/auth/github`, { redirect: "manual" });
  const loc = new URL(start.headers.get("location")!);
  assert.equal(loc.host, "github.com");
  const state = loc.searchParams.get("state")!;
  const cb = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  assert.equal(cb.headers.get("location"), "/");
  const sid = cb.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!;
  assert.match(sid, /HttpOnly/i);
  assert.match(sid, /SameSite=Lax/i);
  return sid.split(";")[0];
}

const postCode = (cookie: string, c: string) =>
  fetch(`${base}/auth/totp`, { method: "POST", headers: { cookie, origin: base, "content-type": "application/json" }, body: JSON.stringify({ code: c }) });

async function signIn(user = "aaronburt"): Promise<string> {
  const pending = await githubStep(user);
  clock += 30_000;
  const r = await postCode(pending, code());
  assert.equal(r.status, 204);
  const full = r.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
  assert.notEqual(full, pending, "session id must change after the second factor");
  return full;
}

function openWs(cookie: string, host: string, origin = base) {
  const ws = new WebSocket(`${base.replace("http", "ws")}/ws?host=${host}&cols=100&rows=30`, { headers: { cookie, origin } });
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
  const closed = () => json.find((m) => m.t === "status" && m.state === "closed");
  return { ws, json, get out() { return out; }, closed, waitFor };
}

function wsStatus(cookie: string | undefined, host: string, origin?: string): Promise<number> {
  return new Promise((res) => {
    const headers: Record<string, string> = {};
    if (cookie) headers.cookie = cookie;
    if (origin) headers.origin = origin;
    const ws = new WebSocket(`${base.replace("http", "ws")}/ws?host=${host}`, { headers });
    ws.on("unexpected-response", (_req, r) => res(r.statusCode!));
    ws.on("open", () => { ws.close(); res(101); });
    ws.on("error", () => {});
  });
}

test("logged-out visitors only get the sign-in page", async () => {
  const r = await fetch(base + "/");
  const html = await r.text();
  assert.match(html, /Sign in to Shellport/);
  assert.doesNotMatch(html, /\/assets\/app-/);
  assert.match(r.headers.get("content-security-policy")!, /frame-ancestors 'none'/);
  assert.equal((await fetch(base + "/api/hosts")).status, 401);
  assert.equal((await fetch(base + "/api/me")).status, 401);
});

test("OAuth state must match", async () => {
  const r = await fetch(`${base}/auth/github/callback?code=good&state=forged`, { redirect: "manual" });
  assert.equal(r.headers.get("location"), "/?error=state");
});

test("GitHub users not on the allowlist are refused", async () => {
  nextUser = "mallory";
  const start = await fetch(`${base}/auth/github`, { redirect: "manual" });
  const state = new URL(start.headers.get("location")!).searchParams.get("state");
  const cb = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  assert.equal(cb.headers.get("location"), "/?error=denied");
  assert.ok(!cb.headers.getSetCookie().some((c) => c.startsWith("sp_sid=") && !c.startsWith("sp_sid=;")));
});

test("GitHub sign-in alone is not enough: pending session is locked out until TOTP", async () => {
  const pending = await githubStep("aaronburt");
  assert.match(await (await fetch(base + "/", { headers: { cookie: pending } })).text(), /Two-factor/);
  assert.equal((await fetch(base + "/api/hosts", { headers: { cookie: pending } })).status, 401);
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: pending } })).status, 401);
  assert.equal(await wsStatus(pending, "fake", base), 401);
  const bad = await postCode(pending, "000000");
  assert.equal(bad.status, 400);
  assert.equal((await postCode(pending, "abc")).status, 400);
  const xo = await fetch(`${base}/auth/totp`, { method: "POST", headers: { cookie: pending, origin: "https://evil.example", "content-type": "application/json" }, body: "{}" });
  assert.equal(xo.status, 403);
  clock += 30_000;
  const c = code();
  const ok = await postCode(pending, c);
  assert.equal(ok.status, 204);
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: pending } })).status, 401);
  const pending2 = await githubStep("aaronburt");
  assert.equal((await postCode(pending2, c)).status, 400);
});

test("five wrong codes destroy the pending session", async () => {
  const pending = await githubStep("aaronburt");
  let last = 0;
  for (let i = 0; i < 5; i++) last = (await postCode(pending, "000000")).status;
  assert.equal(last, 401);
  clock += 30_000;
  assert.equal((await postCode(pending, code())).status, 401);
});

test("TOTP codes tolerate one step of clock drift but not more", async () => {
  const { verifyTotp } = await import("../src/server/totp.js");
  const now = 1_700_000_000_000;
  const step = Math.floor(now / 30_000);
  assert.equal(verifyTotp(TOTP_KEY, hotp(TOTP_KEY, step), now), step);
  assert.equal(verifyTotp(TOTP_KEY, hotp(TOTP_KEY, step - 1), now), step - 1);
  assert.equal(verifyTotp(TOTP_KEY, hotp(TOTP_KEY, step + 1), now), step + 1);
  assert.equal(verifyTotp(TOTP_KEY, hotp(TOTP_KEY, step + 3), now), undefined);
  assert.equal(verifyTotp(TOTP_KEY, "12345", now), undefined);
});

test("RFC 6238 test vector", async () => {
  const { hotp: h } = await import("../src/server/totp.js");
  const key = Buffer.from("12345678901234567890");
  assert.equal(h(key, Math.floor(59 / 30)), "287082");
  assert.equal(h(key, Math.floor(1111111109 / 30)), "081804");
});

test("signed-in user gets the app and only display fields for permitted hosts", async () => {
  const cookie = await signIn("AaronBurt");
  assert.match(await (await fetch(base + "/", { headers: { cookie } })).text(), /\/assets\/app-[A-Z0-9]{8}\.js/);
  const hosts = await (await fetch(base + "/api/hosts", { headers: { cookie } })).json();
  assert.deepEqual(hosts.map((h: any) => h.id), ["fake", "nofiles", "locked", "wrongkey", "badpw", "filepw"]);
  const raw = JSON.stringify(hosts);
  assert.doesNotMatch(raw, /s3cret|SHA256|password/);
  assert.equal(hosts[0].addr, `deploy@127.0.0.1:${sshPort}`);
});

test("WebSocket upgrade requires session, same origin and a permitted host", async () => {
  const cookie = await signIn();
  assert.equal(await wsStatus(undefined, "fake", base), 401);
  assert.equal(await wsStatus(cookie, "fake"), 403);
  assert.equal(await wsStatus(cookie, "fake", "https://evil.example"), 403);
  assert.equal(await wsStatus(cookie, "private", base), 404);
  assert.equal(await wsStatus(cookie, "nope", base), 404);
});

test("terminal round trip, resize and exit", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "fake");
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  const info = t.json.find((m) => m.state === "connected").info;
  assert.equal(info.hostKey, "pinned");
  assert.ok(info.cipher);
  assert.deepEqual([lastPty.cols, lastPty.rows, lastPty.term], [100, 30, "xterm-256color"]);
  await t.waitFor(() => t.out.includes("welcome to fake-host"));
  t.ws.send(Buffer.from("hello"), { binary: true });
  await t.waitFor(() => t.out.includes("HELLO"));
  t.ws.send(JSON.stringify({ t: "resize", cols: 120, rows: 40 }));
  await t.waitFor(() => lastWindow?.cols === 120 && lastWindow?.rows === 40);
  t.ws.send(Buffer.from("exit\r"), { binary: true });
  await t.waitFor(() => t.json.some((m) => m.state === "closed"));
});

test("host key mismatch is refused", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "wrongkey");
  await t.waitFor(() => t.json.some((m) => m.state === "closed"));
  assert.match(t.json.find((m) => m.t === "error").message, /Host key did not match/);
});

test("bad credentials give a clear error", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "badpw");
  await t.waitFor(() => t.json.some((m) => m.state === "closed"));
  assert.match(t.json.find((m) => m.t === "error").message, /rejected the configured credentials/);
});

test("per-user terminal limit", async () => {
  const cookie = await signIn();
  const ts = [openWs(cookie, "fake"), openWs(cookie, "fake"), openWs(cookie, "fake")];
  await Promise.all(ts.map((t) => t.waitFor(() => t.json.some((m) => m.state === "connected"))));
  assert.equal(await wsStatus(cookie, "fake", base), 429);
  for (const t of ts) t.ws.close();
  await new Promise((r) => setTimeout(r, 200));
});

test("signing out closes open terminals and kills the session", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "fake");
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  assert.equal((await fetch(base + "/auth/logout", { method: "POST", headers: { cookie, origin: "https://evil.example" } })).status, 403);
  const r = await fetch(base + "/auth/logout", { method: "POST", headers: { cookie, origin: base } });
  assert.equal(r.status, 204);
  await t.waitFor(() => t.json.some((m) => m.state === "closed"));
  assert.equal((await fetch(base + "/api/me", { headers: { cookie } })).status, 401);
});

test("key hosts ask for the passphrase in the browser, retry on a wrong one, and never expose it", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "locked");
  await t.waitFor(() => t.json.some((m) => m.t === "passphrase"));
  assert.equal(t.json.find((m) => m.t === "passphrase").retry, false);
  t.ws.send(Buffer.from("ignored before unlock"), { binary: true });
  t.ws.send(JSON.stringify({ t: "passphrase", value: "wrong" }));
  await t.waitFor(() => t.json.filter((m) => m.t === "passphrase").length === 2);
  const retry = t.json.filter((m) => m.t === "passphrase")[1];
  assert.equal(retry.retry, true);
  assert.equal(retry.remaining, 2);
  assert.ok(!t.json.some((m) => m.state === "connected"));
  t.ws.send(JSON.stringify({ t: "passphrase", value: "correct horse" }));
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  assert.equal(t.json.find((m) => m.state === "connected").info.auth, "key, passphrase entered in browser");
  await t.waitFor(() => t.out.includes("welcome to fake-host"));
  assert.doesNotMatch(JSON.stringify(t.json), /correct horse|wrong/);
  t.ws.close();
  await new Promise((r) => setTimeout(r, 100));
});

test("three wrong passphrases close the terminal", async () => {
  const cookie = await signIn("pp1");
  const t = openWs(cookie, "locked");
  for (let i = 0; i < 3; i++) {
    await t.waitFor(() => t.json.filter((m) => m.t === "passphrase").length === i + 1);
    t.ws.send(JSON.stringify({ t: "passphrase", value: "nope" }));
  }
  await t.waitFor(() => t.json.some((m) => m.state === "closed"));
  assert.match(t.json.find((m) => m.t === "error").message, /Incorrect passphrase/);
});

test("empty and oversized passphrases count as failed tries", async () => {
  const cookie = await signIn("pp2");
  const t = openWs(cookie, "locked");
  const values = ["", "x".repeat(2000), ""];
  for (let i = 0; i < values.length; i++) {
    await t.waitFor(() => t.json.filter((m) => m.t === "passphrase").length === i + 1);
    t.ws.send(JSON.stringify({ t: "passphrase", value: values[i] }));
  }
  await t.waitFor(() => t.json.some((m) => m.state === "closed"));
  assert.match(t.json.find((m) => m.t === "error").message, /Incorrect passphrase/);
  const remaining = t.json.filter((m) => m.t === "passphrase").map((m) => m.remaining);
  assert.deepEqual(remaining, [3, 2, 1]);
});

test("a rejected passphrase does not restart the pending timer", async () => {
  timing.passphraseWaitMs = 1000;
  try {
    const cookie = await signIn("pp3");
    const t = openWs(cookie, "locked");
    await t.waitFor(() => t.json.some((m) => m.t === "passphrase"));
    const asked = Date.now();
    await new Promise((r) => setTimeout(r, 600));
    t.ws.send(JSON.stringify({ t: "passphrase", value: "" }));
    await t.waitFor(() => t.json.filter((m) => m.t === "passphrase").length === 2);
    await t.waitFor(() => t.json.some((m) => m.state === "closed"), 3000);
    const elapsed = Date.now() - asked;
    assert.match(t.json.find((m) => m.t === "error").message, /in time/);
    assert.match(t.json.find((m) => m.state === "closed").reason, /Passphrase timeout/);
    assert.ok(elapsed < 1300, `the timer was restarted by a rejected passphrase (closed after ${elapsed} ms)`);
  } finally {
    timing.passphraseWaitMs = undefined;
  }
});

test("a passphrase prompt that is never answered times out", async () => {
  timing.passphraseWaitMs = 500;
  try {
    const cookie = await signIn();
    const t = openWs(cookie, "locked");
    await t.waitFor(() => t.json.some((m) => m.state === "closed"), 3000);
    assert.match(t.json.find((m) => m.state === "closed").reason, /Passphrase timeout/);
  } finally {
    timing.passphraseWaitMs = undefined;
  }
});

test("idle terminals are closed after the idle timeout", async () => {
  timing.idleTimeoutMs = 1200;
  try {
    const cookie = await signIn();
    const t = openWs(cookie, "fake");
    await t.waitFor(() => t.json.some((m) => m.state === "connected"));
    await t.waitFor(() => t.json.some((m) => m.state === "closed"), 5000);
    assert.match(t.json.find((m) => m.state === "closed").reason, /idle/);
  } finally {
    timing.idleTimeoutMs = undefined;
  }
});

test("a resize sent before the shell opens still sizes the remote terminal", async () => {
  const cookie = await signIn("pp3");
  const t = openWs(cookie, "locked");
  await t.waitFor(() => t.json.some((m) => m.t === "passphrase"));
  t.ws.send(JSON.stringify({ t: "resize", cols: 132, rows: 43 }));
  t.ws.send(JSON.stringify({ t: "passphrase", value: "correct horse" }));
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  assert.equal(lastPty.cols, 132);
  assert.equal(lastPty.rows, 43);
  t.ws.close();
  await new Promise((r) => setTimeout(r, 100));
});

test("passphrase messages are ignored unless the server asked", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "fake");
  await new Promise((r) => t.ws.once("open", r));
  t.ws.send(JSON.stringify({ t: "passphrase", value: "x" }));
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  assert.ok(!t.json.some((m) => m.t === "passphrase" || m.t === "error"));
  t.ws.close();
  await new Promise((r) => setTimeout(r, 100));
});

test("sign-in activity lists sign-ins and failures for the account only, and signs out other sessions", async () => {
  const first = await signIn();
  assert.equal((await postCode(await githubStep("aaronburt"), "111111")).status, 400);
  const t = openWs(first, "locked");
  await t.waitFor(() => t.json.some((m) => m.t === "passphrase"));
  t.ws.send(JSON.stringify({ t: "passphrase", value: "nope" }));
  await t.waitFor(() => t.json.filter((m) => m.t === "passphrase").length === 2);
  t.ws.close();

  const get = async (cookie: string, q = "") => (await fetch(`${base}/api/signins${q}`, { headers: { cookie } })).json() as Promise<any>;
  const withHost = await get(first, "?host=locked");
  const kinds = withHost.items.map((i: any) => i.kind);
  assert.ok(kinds.includes("signin") && kinds.includes("totp_failed") && kinds.includes("passphrase_failed"));
  assert.ok(withHost.items.find((i: any) => i.kind === "signin" && i.current));
  assert.ok(!(await get(first, "?host=fake")).items.some((i: any) => i.kind === "passphrase_failed"));
  assert.ok(!(await get(first)).items.some((i: any) => i.kind === "passphrase_failed"));
  assert.doesNotMatch(JSON.stringify(withHost), new RegExp(first.split("=")[1]));
  assert.ok(withHost.others >= 0);

  const other = await signIn();
  assert.ok((await get(first)).others >= 1);
  assert.equal((await fetch(`${base}/api/signins/signout-others`, { method: "POST", headers: { cookie: first, origin: "https://evil.example" } })).status, 403);
  const r = await fetch(`${base}/api/signins/signout-others`, { method: "POST", headers: { cookie: first, origin: base } });
  assert.equal(r.status, 200);
  assert.ok((await r.json() as any).ended >= 1);
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: other } })).status, 401);
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: first } })).status, 200);
  assert.equal((await fetch(base + "/api/signins", { headers: { cookie: other } })).status, 401);
  assert.equal(((await get(first)).others), 0);
  assert.equal((await fetch(base + "/api/signins")).status, 401);
});

test("config: key hosts must be passphrase-protected unless passphrase is false", () => {
  const secret = base32Encode(crypto.randomBytes(20));
  const base = { server: { publicUrl: "https://x.example" }, github: { clientId: "a", clientSecret: "b" }, users: [{ github: "a", totpSecret: secret }], security: { allowUnpinnedHostKeys: true } };
  const host = (auth: object) => ({ id: "h", host: "h", username: "u", auth });
  assert.doesNotThrow(() => validateConfig({ ...base, hosts: [host({ type: "key", privateKey: userKey.private })] }, "."));
  assert.throws(() => validateConfig({ ...base, hosts: [host({ type: "key", privateKey: plainKey.private })] }, "."), /has no passphrase/);
  assert.doesNotThrow(() => validateConfig({ ...base, hosts: [host({ type: "key", privateKey: plainKey.private, passphrase: false })] }, "."));
  assert.throws(() => validateConfig({ ...base, hosts: [host({ type: "key", privateKey: userKey.private, passphrase: false })] }, "."), /passphrase-protected/);
  assert.doesNotThrow(() => validateConfig({ ...base, hosts: [host({ type: "key", privateKey: userKey.private, passphrase: "correct horse" })] }, "."));
  assert.throws(() => validateConfig({ ...base, hosts: [host({ type: "key", privateKey: "garbage" })] }, "."), /readable private key/);
});

test("config refuses unpinned hosts, missing TOTP secrets and bad users", () => {
  const secret = base32Encode(crypto.randomBytes(20));
  const base = { server: { publicUrl: "https://x.example" }, github: { clientId: "a", clientSecret: "b" }, users: [{ github: "a", totpSecret: secret }] };
  const host = { id: "h", host: "h", username: "u", auth: { type: "password", password: "p" } };
  const loose = { allowUnpinnedHostKeys: true };
  assert.throws(() => validateConfig({ ...base, hosts: [host] }, "."), /hostKeyFingerprints is required/);
  assert.doesNotThrow(() => validateConfig({ ...base, hosts: [host], security: loose }, "."));
  assert.throws(() => validateConfig({ ...base, users: [], hosts: [host], security: loose }, "."), /users must list/);
  assert.throws(() => validateConfig({ ...base, users: [{ github: "bad user!", totpSecret: secret }], hosts: [host], security: loose }, "."), /not a GitHub user id/);
  assert.throws(() => validateConfig({ ...base, users: [{ github: "a" }], hosts: [host], security: loose }, "."), /no totpSecret/);
  assert.throws(() => validateConfig({ ...base, users: [{ github: "a", totpSecret: "AAAA" }], hosts: [host], security: loose }, "."), /too short/);
  assert.throws(() => validateConfig({ ...base, users: [{ github: "a", totpSecret: "!!!" }], hosts: [host], security: loose }, "."), /base32/);
  assert.throws(() => validateConfig({ ...base, hosts: [{ ...host, auth: { type: "agent" } }], security: loose }, "."), /auth.type must be key or password/);
  assert.throws(() => validateConfig({ ...base, hosts: [{ ...host, auth: { type: "password", password: { env: "NOPE_X" } } }], security: loose }, "."), /NOPE_X/);
});

test("config: numeric options must be integers within range", () => {
  const secret = base32Encode(crypto.randomBytes(20));
  const host = { id: "h", host: "h", username: "u", auth: { type: "password", password: "p" } };
  const cfg = (extra: object, h: object = host) => validateConfig({
    server: { publicUrl: "https://x.example" }, github: { clientId: "a", clientSecret: "b" },
    users: [{ github: "a", totpSecret: secret }], security: { allowUnpinnedHostKeys: true }, hosts: [h], ...extra,
  }, ".");
  const loaded = cfg({});
  assert.equal(loaded.server.port, 8080);
  assert.equal(loaded.session.ttlHours, 12);
  assert.equal(loaded.limits.maxTerminalsPerUser, 10);
  assert.equal(loaded.hosts[0].port, 22);
  assert.equal(cfg({ limits: { idleTimeoutMinutes: 0 } }).limits.idleTimeoutMinutes, 0);
  assert.equal(cfg({ server: { publicUrl: "https://x.example", trustProxy: 2 } }).server.trustProxy, 2);
  assert.throws(() => cfg({ server: { publicUrl: "https://x.example", port: 0 } }), /server.port/);
  assert.throws(() => cfg({ server: { publicUrl: "https://x.example", port: 70000 } }), /server.port/);
  assert.throws(() => cfg({ server: { publicUrl: "https://x.example", port: "8080" } }), /server.port/);
  assert.throws(() => cfg({ server: { publicUrl: "https://x.example", trustProxy: -1 } }), /server.trustProxy/);
  assert.throws(() => cfg({ server: { publicUrl: "https://x.example", trustProxy: "yes" } }), /server.trustProxy/);
  assert.throws(() => cfg({ session: { ttlHours: 0 } }), /session.ttlHours/);
  assert.throws(() => cfg({ session: { ttlHours: 1.5 } }), /session.ttlHours/);
  assert.throws(() => cfg({ limits: { maxTerminalsPerUser: 0 } }), /maxTerminalsPerUser/);
  assert.throws(() => cfg({ limits: { idleTimeoutMinutes: -1 } }), /idleTimeoutMinutes/);
  assert.throws(() => cfg({ limits: { loginAttemptsPer15Min: Number.NaN } }), /loginAttemptsPer15Min/);
  assert.throws(() => cfg({}, { ...host, port: 0 }), /host h port/);
  assert.throws(() => cfg({}, { ...host, port: 22.5 }), /host h port/);
});

test("allowlist matches numeric ids or logins", async () => {
  const { userAllowed } = await import("../src/server/config.js");
  assert.ok(userAllowed(["42388542"], { login: "renamed", id: 42388542 }));
  assert.ok(userAllowed(["AaronBurt".toLowerCase()], { login: "AaronBurt", id: 1 }));
  assert.ok(!userAllowed(["42388542"], { login: "42388542", id: 5 }));
  assert.ok(!userAllowed(["aaronburt"], { login: "aaronburt2", id: 42388542 }));
});

test("security headers are on every response, and private responses are not cacheable", async () => {
  for (const url of ["/", "/api/me", "/healthz", "/nope", "/auth/github"]) {
    const r = await fetch(base + url, { redirect: "manual" });
    const h = r.headers;
    assert.equal(h.get("x-content-type-options"), "nosniff", url);
    assert.equal(h.get("x-frame-options"), "DENY", url);
    assert.equal(h.get("referrer-policy"), "no-referrer", url);
    assert.equal(h.get("cross-origin-opener-policy"), "same-origin", url);
    assert.equal(h.get("cross-origin-resource-policy"), "same-origin", url);
    assert.equal(h.get("cache-control"), "no-store", url);
    assert.match(h.get("permissions-policy")!, /camera=\(\)/, url);
    assert.equal(h.get("x-powered-by"), null, url);
    const csp = h.get("content-security-policy")!;
    for (const d of ["default-src 'self'", "script-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'"]) assert.ok(csp.includes(d), `${url}: ${d}`);
    assert.doesNotMatch(csp, /script-src[^;]*unsafe/, url);
    assert.equal(h.get("strict-transport-security"), null, url);
  }
});

test("no CORS: cross-origin pages cannot read responses or pass a preflight", async () => {
  const r = await fetch(base + "/api/me", { headers: { origin: "https://evil.example" } });
  assert.equal(r.headers.get("access-control-allow-origin"), null);
  assert.equal(r.headers.get("access-control-allow-credentials"), null);
  const pre = await fetch(base + "/auth/totp", {
    method: "OPTIONS",
    headers: { origin: "https://evil.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type" },
  });
  assert.equal(pre.headers.get("access-control-allow-origin"), null);
});

test("origin is checked before the body is parsed, and bad input never produces a stack trace", async () => {
  const cookie = await signIn();
  const bad = await fetch(base + "/auth/logout", { method: "POST", headers: { cookie } });
  assert.equal(bad.status, 403, "missing Origin is refused");
  assert.equal((await fetch(base + "/auth/logout", { method: "POST", headers: { cookie, origin: "null" } })).status, 403);
  const xo = await fetch(base + "/auth/totp", { method: "POST", headers: { cookie, origin: "https://evil.example", "content-type": "application/json" }, body: "{not json" });
  assert.equal(xo.status, 403);
  const malformed = await fetch(base + "/auth/totp", { method: "POST", headers: { cookie, origin: base, "content-type": "application/json" }, body: "{not json" });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.headers.get("content-type")?.split(";")[0], "application/json");
  assert.doesNotMatch(await malformed.text(), /at |node_modules|Error/);
  const missing = await fetch(base + "/assets/does-not-exist.js");
  assert.equal(missing.status, 404);
  assert.equal(missing.headers.get("content-type")?.split(";")[0], "application/json");
});

test("built assets are content-hashed and cached long; unhashed ones revalidate", async () => {
  const cookie = await signIn();
  const html = await (await fetch(base + "/", { headers: { cookie } })).text();
  const js = html.match(/\/assets\/app-[A-Z0-9]{8}\.js/)![0];
  const css = html.match(/\/assets\/app-[A-Z0-9]{8}\.css/)![0];
  for (const p of [js, css]) {
    const r = await fetch(base + p);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("cache-control")!, /max-age=31536000, immutable/);
  }
  assert.match((await fetch(base + "/assets/favicon.svg")).headers.get("cache-control")!, /no-cache/);
  assert.equal((await fetch(base + "/", { headers: { cookie } })).headers.get("cache-control"), "no-store");
});

test("session and OAuth state cookies are HttpOnly, SameSite and scoped to the host", async () => {
  const start = await fetch(base + "/auth/github", { redirect: "manual" });
  const state = start.headers.getSetCookie().find((c) => c.startsWith("sp_state="))!;
  assert.match(state, /HttpOnly/i);
  assert.match(state, /SameSite=Lax/i);
  assert.match(state, /Path=\//);
  assert.match(state, /Max-Age=600/);
  assert.doesNotMatch(state, /Domain=/i);
  const authorize = new URL(start.headers.get("location")!);
  assert.equal(authorize.origin, "https://github.com");
  assert.ok(authorize.searchParams.get("state")!.length >= 32);
  assert.equal(authorize.searchParams.get("scope"), "");
});

test("OAuth state is single use and cannot be replayed from another browser", async () => {
  const start = await fetch(base + "/auth/github", { redirect: "manual" });
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const first = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  assert.equal(first.headers.get("location"), "/");
  const replay = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, { redirect: "manual" });
  assert.equal(replay.headers.get("location"), "/?error=state");
  const wrong = await fetch(`${base}/auth/github/callback?code=good&state=${state}x`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  assert.equal(wrong.headers.get("location"), "/?error=state");
});

test("over https: __Host- cookies with Secure, HSTS, and upgrade-insecure-requests", async () => {
  const cfg = validateConfig({
    server: { publicUrl: "https://ssh.example.test" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: "someone", totpSecret: base32Encode(TOTP_KEY) }],
    hosts: [{ id: "h", host: "127.0.0.1", port: sshPort, username: "deploy", auth: { type: "password", password: "x" }, hostKeyFingerprints: [fp] }],
  }, process.cwd());
  const secure = createApp(cfg, { publicDir: path.resolve("dist/public") });
  await new Promise<void>((r) => secure.server.listen(0, "127.0.0.1", () => r()));
  try {
    const url = `http://127.0.0.1:${(secure.server.address() as AddressInfo).port}`;
    const r = await fetch(url + "/auth/github", { redirect: "manual" });
    const state = r.headers.getSetCookie().find((c) => c.startsWith("__Host-sp_state="))!;
    assert.ok(state, "state cookie uses the __Host- prefix");
    assert.match(state, /; Secure/i);
    assert.match(state, /HttpOnly/i);
    assert.match(r.headers.get("strict-transport-security")!, /max-age=31536000; includeSubDomains/);
    assert.match(r.headers.get("content-security-policy")!, /upgrade-insecure-requests/);
    assert.match(r.headers.get("content-security-policy")!, /connect-src 'self' wss:\/\/ssh\.example\.test/);
  } finally {
    secure.server.close();
  }
});

test("client address behind a proxy is taken from the trusted end of X-Forwarded-For", () => {
  assert.equal(clientIp("10.0.0.2", "1.1.1.1", false), "10.0.0.2");
  assert.equal(clientIp("10.0.0.2", undefined, 1), "10.0.0.2");
  assert.equal(clientIp("172.18.0.3", "6.6.6.6, 203.0.113.9", 1), "203.0.113.9");
  assert.equal(clientIp("172.18.0.3", "203.0.113.9", 1), "203.0.113.9");
  assert.equal(clientIp("172.18.0.3", "6.6.6.6, 203.0.113.9, 172.18.0.2", 2), "203.0.113.9");
  assert.equal(clientIp("172.18.0.3", "203.0.113.9", 5), "203.0.113.9");
});

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const BANNER = "welcome to fake-host\r\n$ ";
const sha256 = (v: string | Buffer) => crypto.createHash("sha256").update(v).digest("hex");

test("a password host can use a file secret that ends with a newline", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "filepw");
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  t.ws.close();
  await pause(100);
});

test("the terminal cap counts a GitHub id across logins", async () => {
  const before = await signIn("old-name");
  const renamed = await signIn("new-name");
  const ts = [openWs(before, "fake"), openWs(before, "fake"), openWs(renamed, "fake")];
  await Promise.all(ts.map((t) => t.waitFor(() => t.json.some((m) => m.state === "connected"))));
  assert.equal(await wsStatus(renamed, "fake", base), 429);
  assert.equal(await wsStatus(before, "fake", base), 429);
  for (const t of ts) t.ws.close();
  await pause(200);
  const again = openWs(renamed, "fake");
  await again.waitFor(() => again.json.some((m) => m.state === "connected"));
  again.ws.close();
  await pause(100);
});

test("the passphrase throttle follows the GitHub user across sign-ins", async () => {
  const prompts = (t: ReturnType<typeof openWs>) => t.json.filter((m) => m.t === "passphrase").length;
  const throttled = (t: ReturnType<typeof openWs>) => t.json.some((m) => m.t === "error" && /Too many incorrect passphrases/.test(m.message));
  const first = await signIn("throttle-user");
  let attempts = 0;
  let blocked = false;
  while (!blocked && attempts < 15) {
    const t = openWs(first, "locked");
    await t.waitFor(() => prompts(t) === 1);
    for (let i = 0; i < 3 && !blocked && !t.closed(); i++) {
      const seen = prompts(t);
      t.ws.send(JSON.stringify({ t: "passphrase", value: "nope" }));
      attempts++;
      await t.waitFor(() => prompts(t) > seen || t.closed());
      blocked = throttled(t);
    }
    t.ws.close();
    await pause(100);
  }
  assert.ok(blocked, "the throttle never engaged");
  assert.equal(attempts, 11, "ten attempts per 15 minutes are allowed, the eleventh is refused");

  const second = await signIn("throttle-user");
  const t = openWs(second, "locked");
  await t.waitFor(() => prompts(t) === 1);
  t.ws.send(JSON.stringify({ t: "passphrase", value: "nope" }));
  await t.waitFor(() => t.closed());
  assert.ok(throttled(t), "a new session must not reset the throttle");

  const other = await signIn("bystander");
  const o = openWs(other, "locked");
  await o.waitFor(() => prompts(o) === 1);
  o.ws.send(JSON.stringify({ t: "passphrase", value: "nope" }));
  await o.waitFor(() => prompts(o) === 2);
  assert.ok(!throttled(o), "other users are not affected");
  o.ws.close();
  await pause(100);
});

test("large terminal output arrives intact and promptly when the browser reads slowly", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "fake");
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  const socket = (t.ws as unknown as { _socket: { pause(): void; resume(): void } })._socket;
  socket.pause();
  t.ws.send(Buffer.from("flood\n"));
  await pause(500);
  const started = Date.now();
  socket.resume();
  await t.waitFor(() => t.out.length >= BANNER.length + FLOOD_BYTES, 30_000);
  const elapsed = Date.now() - started;
  assert.equal(t.out.length, BANNER.length + FLOOD_BYTES);
  assert.equal(sha256(t.out.slice(BANNER.length)), sha256(FLOOD));
  assert.ok(elapsed < 8000, `the output took ${elapsed} ms to arrive; it should not wait on a once-a-second timer`);
  t.ws.close();
  await pause(200);
});

test("a large paste reaches the host intact while the host stops reading for a moment", async () => {
  const cookie = await signIn();
  const t = openWs(cookie, "fake");
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  const pasted = crypto.randomBytes(1_500_000).toString("hex");
  const frame = 48 * 1024;
  for (let i = 0; i < pasted.length; i += frame) t.ws.send(Buffer.from(pasted.slice(i, i + frame)));
  t.ws.send(Buffer.from("<<END>>"));
  await t.waitFor(() => t.out.includes("PASTE "), 30_000);
  assert.ok(t.out.includes(`PASTE ${pasted.length} ${sha256(pasted)}`), `the host received a different paste: ${t.out.slice(-120)}`);
  t.ws.close();
  await pause(200);
});

async function terminalWithFiles(cookie: string, host = "fake") {
  const t = openWs(cookie, host);
  await t.waitFor(() => t.json.some((m) => m.state === "connected"));
  const id = t.json.find((m) => m.state === "connected").info.id as string;
  const files = (route = "", query: Record<string, string> = {}, init: RequestInit = {}) =>
    fetch(`${base}/api/terminals/${id}/files${route}${Object.keys(query).length ? "?" + new URLSearchParams(query) : ""}`, { ...init, headers: { cookie, ...(init.headers as object) } });
  const del = (p: unknown, origin: string | null = base) =>
    files("/delete", {}, { method: "POST", headers: { ...(origin ? { origin } : {}), "content-type": "application/json" }, body: JSON.stringify({ path: p }) });
  return { t, id, files, del };
}

test("files: the connected status carries an unguessable terminal id and whether files are on", async () => {
  const cookie = await signIn();
  const a = await terminalWithFiles(cookie);
  assert.match(a.id, /^[A-Za-z0-9_-]{20,}$/);
  assert.equal(a.t.json.find((m) => m.state === "connected").info.files, true);
  const b = await terminalWithFiles(cookie, "nofiles");
  assert.equal(b.t.json.find((m) => m.state === "connected").info.files, false);
  const r = await b.files();
  assert.equal(r.status, 403);
  assert.deepEqual(await r.json(), { error: "files_disabled" });
  a.t.ws.close();
  b.t.ws.close();
});

test("files: listing starts in the home folder, tells folders from files and follows folder links", async () => {
  const cookie = await signIn();
  const { t, files } = await terminalWithFiles(cookie);
  const r = await files();
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("cache-control"), "no-store");
  const body = await r.json();
  assert.equal(body.path, "/home/demo");
  assert.equal(body.maxDownloadBytes, 1024 * 1024);
  const by = Object.fromEntries(body.entries.map((e: any) => [e.name, e]));
  assert.equal(by["docs"].kind, "dir");
  assert.equal(by["docs-link"].kind, "dir");
  assert.equal(by["notes.txt"].kind, "file");
  assert.equal(by["notes.txt"].size, 17);
  assert.match(by["notes.txt"].mode, /^-[rwx-]{9}$/);
  assert.ok(!("." in by) && !(".." in by));
  const sub = await (await files("", { path: "/home/demo/docs" })).json();
  assert.deepEqual(sub.entries.map((e: any) => e.name), ["a.txt"]);
  assert.equal((await files("", { path: "/home/demo/nope" })).status, 404);
  t.ws.close();
});

test("files: only the owning session can reach a terminal's files", async () => {
  const cookie = await signIn();
  const { t, id, files } = await terminalWithFiles(cookie);
  const anon = await fetch(`${base}/api/terminals/${id}/files`);
  assert.equal(anon.status, 401);
  const other = await signIn("other");
  const stolen = await fetch(`${base}/api/terminals/${id}/files`, { headers: { cookie: other } });
  assert.equal(stolen.status, 404);
  const second = await signIn();
  assert.equal((await fetch(`${base}/api/terminals/${id}/files`, { headers: { cookie: second } })).status, 404, "another sign-in of the same user is a different session");
  assert.equal((await fetch(`${base}/api/terminals/not-a-real-id/files`, { headers: { cookie } })).status, 404);
  assert.equal((await files()).status, 200);
  t.ws.close();
});

test("files: paths must be absolute, free of .. and control characters, and of sane length", async () => {
  const cookie = await signIn();
  const { t, files, del } = await terminalWithFiles(cookie);
  const bad = ["relative/path", "/home/../etc/passwd", "/home/demo/..", "/a\u0000b", "/a\nb", "/" + "x".repeat(5000)];
  for (const p of bad) {
    for (const route of ["", "/view", "/download"]) {
      const r = await files(route, { path: p });
      assert.equal(r.status, 400, `${route} ${JSON.stringify(p.slice(0, 20))}`);
      assert.deepEqual(await r.json(), { error: "bad_path" });
    }
    assert.equal((await del(p)).status, 400);
  }
  assert.equal((await files("/view")).status, 400, "view needs a path");
  assert.equal((await del(undefined)).status, 400);
  assert.equal((await del("/")).status, 400, "the root can never be deleted");
  t.ws.close();
});

test("files: view returns text, flags binary files and caps the preview", async () => {
  const cookie = await signIn();
  const { t, files } = await terminalWithFiles(cookie);
  const note = await (await files("/view", { path: "/home/demo/notes.txt" })).json();
  assert.deepEqual([note.text, note.truncated, note.binary, note.size], ["hello from notes\n", false, false, 17]);
  const bin = await (await files("/view", { path: "/home/demo/blob.bin" })).json();
  assert.deepEqual([bin.binary, bin.text], [true, ""]);
  const long = await (await files("/view", { path: "/home/demo/long.txt" })).json();
  assert.equal(long.truncated, true);
  assert.equal(long.size, 400_000);
  assert.equal(long.text.length, 256 * 1024);
  const dir = await files("/view", { path: "/home/demo/docs" });
  assert.equal(dir.status, 400);
  assert.deepEqual(await dir.json(), { error: "not_a_file" });
  t.ws.close();
});

test("files: download streams the file as an attachment, refuses folders, oversize files and cross-site requests", async () => {
  const cookie = await signIn();
  const { t, files } = await terminalWithFiles(cookie);
  const ok = await files("/download", { path: "/home/demo/notes.txt" });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get("content-type"), "application/octet-stream");
  assert.equal(ok.headers.get("x-content-type-options"), "nosniff");
  assert.equal(ok.headers.get("content-length"), "17");
  assert.match(ok.headers.get("content-disposition")!, /^attachment; filename="notes\.txt"/);
  assert.equal(await ok.text(), "hello from notes\n");
  const odd = await files("/download", { path: "/home/demo/déjà vu \"q\".txt" });
  const cd = odd.headers.get("content-disposition")!;
  assert.match(cd, /filename="d_j_ vu _q_\.txt"/);
  assert.match(cd, /filename\*=UTF-8''d%C3%A9j%C3%A0%20vu%20%22q%22\.txt/);
  assert.equal(await odd.text(), "unicode");
  const big = await files("/download", { path: "/home/demo/huge.dat" });
  assert.equal(big.status, 413);
  assert.deepEqual(await big.json(), { error: "too_large" });
  assert.equal((await files("/download", { path: "/home/demo/docs" })).status, 400);
  const cross = await files("/download", { path: "/home/demo/notes.txt" }, { headers: { "sec-fetch-site": "cross-site" } });
  assert.equal(cross.status, 403);
  assert.equal((await files("", {}, { headers: { "sec-fetch-site": "same-site" } })).status, 403);
  assert.equal((await files("/download", { path: "/home/demo/notes.txt" }, { headers: { "sec-fetch-site": "none" } })).status, 200);
  t.ws.close();
});

test("files: delete needs the same origin, removes files and empty folders, and refuses non-empty folders", async () => {
  const cookie = await signIn();
  const { t, files, del } = await terminalWithFiles(cookie);
  assert.equal((await del("/home/demo/trash1.txt", null)).status, 403);
  assert.equal((await del("/home/demo/trash1.txt", "https://evil.example")).status, 403);
  assert.ok(fs.existsSync(path.join(sftpRoot, "home/demo/trash1.txt")));
  const ok = await del("/home/demo/trash1.txt");
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { deleted: "/home/demo/trash1.txt" });
  assert.ok(!fs.existsSync(path.join(sftpRoot, "home/demo/trash1.txt")));
  const names = (await (await files()).json()).entries.map((e: any) => e.name);
  assert.ok(!names.includes("trash1.txt"));
  assert.equal((await del("/home/demo/trash1.txt")).status, 404);
  const full = await del("/home/demo/full");
  assert.equal(full.status, 409);
  assert.deepEqual(await full.json(), { error: "cannot_remove" });
  assert.ok(fs.existsSync(path.join(sftpRoot, "home/demo/full/x.txt")));
  assert.equal((await del("/home/demo/empty")).status, 200);
  assert.ok(!fs.existsSync(path.join(sftpRoot, "home/demo/empty")));
  t.ws.close();
});

test("files: every list, view, download and delete is audit logged with the user, host and path", async () => {
  const cookie = await signIn();
  const { t, files, del } = await terminalWithFiles(cookie);
  const lines: any[] = [];
  const orig = console.log;
  console.log = (line: unknown) => { try { lines.push(JSON.parse(String(line))); } catch { orig(line); } };
  try {
    await files();
    await files("/view", { path: "/home/demo/notes.txt" });
    await (await files("/download", { path: "/home/demo/notes.txt" })).text();
    await del("/home/demo/trash2.txt");
    await files("", { path: "/home/demo/missing" });
    await new Promise((r) => setTimeout(r, 50));
  } finally {
    console.log = orig;
  }
  const events = lines.map((l) => l.event);
  for (const e of ["sftp.list", "sftp.view", "sftp.download", "sftp.download_end", "sftp.delete", "sftp.error"]) assert.ok(events.includes(e), `${e} logged: ${events}`);
  const d = lines.find((l) => l.event === "sftp.delete");
  assert.deepEqual([d.user, d.host, d.path, d.kind], ["aaronburt", "fake", "/home/demo/trash2.txt", "file"]);
  assert.equal(lines.find((l) => l.event === "sftp.download_end").complete, true);
  assert.equal(lines.find((l) => l.event === "sftp.error").error, "not_found");
  assert.ok(!JSON.stringify(lines).includes("s3cret"));
  t.ws.close();
});

test("files: closing the terminal ends file access to it", async () => {
  const cookie = await signIn();
  const { t, files } = await terminalWithFiles(cookie);
  assert.equal((await files()).status, 200);
  t.ws.close();
  await t.waitFor(() => t.ws.readyState === WebSocket.CLOSED);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal((await files()).status, 404);
});

test("files: using the file explorer keeps the terminal from being closed as idle", async () => {
  const cookie = await signIn();
  const { t, files } = await terminalWithFiles(cookie);
  timing.idleTimeoutMs = 700;
  try {
    for (let i = 0; i < 4; i++) {
      await new Promise((r) => setTimeout(r, 300));
      assert.equal((await files()).status, 200);
    }
    assert.equal(t.closed(), undefined);
  } finally {
    delete timing.idleTimeoutMs;
    t.ws.close();
  }
});

test("config: host files flag and the download limit are validated", () => {
  const base = { server: { publicUrl: "http://x.test" }, github: { clientId: "i", clientSecret: "s" }, users: [{ github: "a", totpSecret: base32Encode(crypto.randomBytes(20)) }] };
  const host = (extra: object) => ({ id: "h", host: "h", username: "u", auth: { type: "password", password: "p" }, hostKeyFingerprints: ["SHA256:x"], ...extra });
  assert.equal(validateConfig({ ...base, hosts: [host({})] }, ".").hosts[0].files, true);
  assert.equal(validateConfig({ ...base, hosts: [host({ files: false })] }, ".").hosts[0].files, false);
  assert.throws(() => validateConfig({ ...base, hosts: [host({ files: "no" })] }, "."), /files must be true or false/);
  assert.equal(validateConfig({ ...base, hosts: [host({})] }, ".").limits.maxDownloadMB, 256);
  for (const bad of [0, 5000, 1.5, "10"]) assert.throws(() => validateConfig({ ...base, limits: { maxDownloadMB: bad }, hosts: [host({})] }, "."), /maxDownloadMB/);
});

test("sealing needs a signed-in session and a same-origin request, then hands over to the seal hook", async () => {
  const cookie = await signIn("aaronburt");
  const me = await (await fetch(base + "/api/me", { headers: { cookie } })).json();
  assert.equal(me.sealable, true);

  const anon = await fetch(base + "/api/seal", { method: "POST", headers: { origin: base } });
  assert.equal(anon.status, 401);
  const crossSite = await fetch(base + "/api/seal", { method: "POST", headers: { cookie, origin: "https://evil.example.com" } });
  assert.equal(crossSite.status, 403);
  const noOrigin = await fetch(base + "/api/seal", { method: "POST", headers: { cookie } });
  assert.equal(noOrigin.status, 403);
  const pending = await githubStep("aaronburt");
  const halfSignedIn = await fetch(base + "/api/seal", { method: "POST", headers: { cookie: pending, origin: base } });
  assert.equal(halfSignedIn.status, 401);
  assert.equal(sealCalls, 0);

  const ok = await fetch(base + "/api/seal", { method: "POST", headers: { cookie, origin: base } });
  assert.equal(ok.status, 204);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(sealCalls, 1);
});

test("shutdown closes open terminals with a reason, stops listening and returns before the deadline", async () => {
  const cookie = await signIn();
  const ts = [openWs(cookie, "fake"), openWs(cookie, "fake")];
  await Promise.all(ts.map((t) => t.waitFor(() => t.json.some((m) => m.state === "connected"))));
  const started = Date.now();
  const done = app.shutdown(3000, "test");
  assert.equal(app.shutdown(), done, "a second call must return the same shutdown");
  await done;
  assert.ok(Date.now() - started < 3000, "shutdown hit its deadline instead of finishing cleanly");
  for (const t of ts) {
    await t.waitFor(() => t.json.some((m) => m.state === "closed"));
    assert.match(t.json.find((m) => m.state === "closed").reason, /shutting down/);
  }
  await assert.rejects(fetch(base + "/healthz"));
});

test("an app without a vault offers no way to seal", async () => {
  const plain = createApp(
    validateConfig({
      server: { port: 1, publicUrl: "http://127.0.0.1:1" },
      github: { clientId: "id", clientSecret: "secret" },
      users: [{ github: 1, totpSecret: base32Encode(TOTP_KEY) }],
      hosts: [{ id: "h", host: "127.0.0.1", username: "u", auth: { type: "password", password: "pw" }, hostKeyFingerprints: [fp] }],
    }, process.cwd()),
    { publicDir: path.resolve("dist/public") },
  );
  await new Promise<void>((r) => plain.server.listen(0, "127.0.0.1", () => r()));
  try {
    const port = (plain.server.address() as AddressInfo).port;
    const r = await fetch(`http://127.0.0.1:${port}/api/seal`, { method: "POST", headers: { origin: `http://127.0.0.1:${port}` } });
    assert.equal(r.status, 404);
  } finally {
    await plain.shutdown(200, "test");
  }
});
