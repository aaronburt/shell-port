import { before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import type { AddressInfo } from "node:net";
import WebSocket from "ws";
import { Client as SshClient } from "ssh2";
import { validateConfig } from "../../src/server/config.js";
import { base32Encode, hotp } from "../../src/server/totp.js";
import { createApp } from "../../src/server/app.js";
import { leftovers, startTargets, type SmokeTargets } from "./docker.js";
import { startBrowser, closeBrowser } from "./browser.js";
import { until, sleep } from "./helpers.js";

const USERS: Record<string, number> = {
  "smoke-user": 4242,
  "other-user": 4343,
  "cap-user": 4444,
  "session-user": 4545,
  "lockout-user": 4646,
  "logout-user": 4747,
  "ui-user": 4848,
  "ui-peer": 4949,
};

const TOTP_KEY = crypto.randomBytes(20);
const MISMATCH_FP = "SHA256:" + Buffer.alloc(32).toString("base64").replace(/=+$/, "");
export const SECRET_PASSWORD = "never-send-this-password-to-a-browser";
export const timing: { passphraseWaitMs?: number; idleTimeoutMs?: number } = {};

export let targets: SmokeTargets;
export let base = "";
let app: ReturnType<typeof createApp>;
let clock = Date.now();

export const code = () => hotp(TOTP_KEY, Math.floor(clock / 30_000));
async function freePort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r()));
  const port = (probe.address() as AddressInfo).port;
  await new Promise((r) => probe.close(r));
  return port;
}

function buildConfig(port: number) {
  return validateConfig({
    server: { publicUrl: `http://127.0.0.1:${port}` },
    github: { clientId: "smoke", clientSecret: "smoke" },
    users: Object.values(USERS).map((id) => ({ github: id, totpSecret: base32Encode(TOTP_KEY) })),
    limits: { maxTerminalsPerUser: 3, loginAttemptsPer15Min: 300 },
    hosts: [
      { id: "plain", name: "demo-plain", group: "Smoke", tag: "key", host: "127.0.0.1", port: targets.plain.port, username: "demo",
        auth: { type: "key", privateKey: targets.plain.privateKey, passphrase: false }, hostKeyFingerprints: [targets.plain.fingerprint] },
      { id: "locked", name: "demo-locked", group: "Smoke", tag: "passphrase", host: "127.0.0.1", port: targets.locked.port, username: "demo",
        auth: { type: "key", privateKey: targets.locked.privateKey }, hostKeyFingerprints: [targets.locked.fingerprint] },
      { id: "nofiles", name: "demo-nofiles", group: "Smoke", host: "127.0.0.1", port: targets.plain.port, username: "demo", files: false,
        auth: { type: "key", privateKey: targets.plain.privateKey, passphrase: false }, hostKeyFingerprints: [targets.plain.fingerprint] },
      { id: "mismatch", name: "demo-mismatch", group: "Smoke", host: "127.0.0.1", port: targets.plain.port, username: "demo",
        auth: { type: "key", privateKey: targets.plain.privateKey, passphrase: false }, hostKeyFingerprints: [MISMATCH_FP] },
      { id: "restricted", name: "demo-restricted", group: "Private", host: "127.0.0.1", port: targets.plain.port, username: "demo",
        auth: { type: "password", password: SECRET_PASSWORD }, hostKeyFingerprints: [targets.plain.fingerprint], allowedUsers: ["other-user"] },
    ],
  }, process.cwd());
}

export function advanceClock() { clock += 30_000; }

export function useApp({ browser = false, ready }: { browser?: boolean; ready?: () => Promise<void> } = {}) {
  // Register once per test file. Node runs files in separate processes.
  before(async () => {
    assert.ok(fs.existsSync(path.resolve("dist/public")), "dist/public is missing; run npm run build");
    targets = await startTargets();
    for (let attempt = 0; ; attempt++) {
      const port = await freePort();
      base = `http://127.0.0.1:${port}`;
      app = createApp(buildConfig(port), {
        publicDir: path.resolve("dist/public"),
        now: () => clock,
        timing,
        exchange: async (c) => {
          const id = USERS[c];
          if (!id) throw new Error("unknown smoke user");
          return { id, login: c, name: c, avatarUrl: "https://avatars.githubusercontent.com/u/1" };
        },
      });
      try {
        await new Promise<void>((res, rej) => {
          app.server.once("error", rej);
          app.server.listen(port, "127.0.0.1", () => res());
        });
        break;
      } catch (e) {
        if (attempt >= 4) throw e;
      }
    }
    if (browser) await startBrowser();
    await ready?.();
  });

  after(async () => {
    if (browser) await closeBrowser();
    app?.server.closeAllConnections?.();
    app?.server.close();
    targets?.cleanup();
    const left = targets ? leftovers(targets.id) : [];
    if (left.length) console.error(`smoke cleanup left behind: ${left.join(", ")}`);
    else console.log("smoke cleanup: no containers or images left behind");
    setTimeout(() => process.exit(process.exitCode ?? 0), 100).unref();
  });

}

export const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

export async function githubStep(login: string): Promise<string> {
  const start = await fetch(`${base}/auth/github`, { redirect: "manual" });
  const loc = new URL(start.headers.get("location")!);
  assert.equal(loc.host, "github.com");
  const cb = await fetch(`${base}/auth/github/callback?code=${login}&state=${loc.searchParams.get("state")}`, {
    redirect: "manual",
    headers: { cookie: cookiesOf(start) },
  });
  assert.equal(cb.headers.get("location"), "/");
  return cb.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
}

export const postCode = (cookie: string, c: string) =>
  fetch(`${base}/auth/totp`, { method: "POST", headers: { cookie, origin: base, "content-type": "application/json" }, body: JSON.stringify({ code: c }) });

export async function signIn(login: string): Promise<string> {
  const pending = await githubStep(login);
  clock += 30_000;
  const r = await postCode(pending, code());
  assert.equal(r.status, 204);
  const full = r.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
  assert.notEqual(full, pending);
  return full;
}

export const getJson = async (cookie: string, p: string) => {
  const r = await fetch(base + p, { headers: { cookie } });
  return { status: r.status, body: r.status === 200 ? await r.json() : await r.json().catch(() => ({})) } as { status: number; body: any };
};

export function openWs(cookie: string, host: string, { origin = base, cols = 100, rows = 30 } = {}) {
  const ws = new WebSocket(`${base.replace("http", "ws")}/ws?host=${host}&cols=${cols}&rows=${rows}`, { headers: { cookie, origin } });
  const json: any[] = [];
  let out = "";
  ws.on("message", (d, bin) => (bin ? (out += d.toString()) : json.push(JSON.parse(d.toString()))));
  const closed = () => json.find((m) => m.t === "status" && m.state === "closed");
  return {
    ws,
    json,
    get out() { return out; },
    closed,
    waitFor: (what: string, pred: () => unknown, ms = 10_000) => until(`${what} (json=${JSON.stringify(json.slice(-4))} out=${JSON.stringify(out.slice(-200))})`, pred, ms),
    send: (msg: object) => ws.send(JSON.stringify(msg)),
    type: (s: string) => ws.send(Buffer.from(s)),
    close: () => ws.close(),
  };
}

type Term = ReturnType<typeof openWs>;

export async function connect(cookie: string, host: string, opts = {}): Promise<Term> {
  const t = openWs(cookie, host, opts);
  await t.waitFor("terminal connected", () => t.json.some((m) => m.state === "connected"), 20_000);
  return t;
}

export function wsStatus(cookie: string | undefined, host: string, origin?: string): Promise<number> {
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

export async function settle(...terms: Term[]) {
  for (const t of terms) {
    if (t.ws.readyState !== WebSocket.CLOSED) t.close();
  }
  await sleep(150);
}

export function remoteExec(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const c = new SshClient();
    let out = "";
    c.on("ready", () => {
      c.exec(cmd, (err, stream) => {
        if (err) { c.end(); return reject(err); }
        stream.on("data", (d: Buffer) => { out += d.toString(); });
        stream.on("close", (code: number) => { c.end(); code === 0 ? resolve(out) : reject(new Error(`remote command failed (${code}): ${cmd}`)); });
      });
    });
    c.on("error", reject);
    c.connect({ host: "127.0.0.1", port: targets.plain.port, username: "demo", privateKey: targets.plain.privateKey, readyTimeout: 15_000 });
  });
}

export async function sftpFixture(tag: string) {
  await remoteExec(`mkdir -p ~/fx-${tag}/sub && echo hello-${tag} > ~/fx-${tag}/note.txt && echo bye > ~/fx-${tag}/gone.txt && yes aaaaaaaaa | head -c 300000 > ~/fx-${tag}/long.txt; printf 'a\\0b' > ~/fx-${tag}/blob.bin`);
}
