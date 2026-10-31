import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { spawn } from "node:child_process";
import net from "node:net";
import path from "node:path";
import type { AddressInfo } from "node:net";
import WebSocket from "ws";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";
import { validateConfig } from "../../src/server/config.js";
import { base32Encode, hotp } from "../../src/server/totp.js";
import { createApp } from "../../src/server/app.js";
import { leftovers, startTargets, type SmokeTargets } from "./docker.js";

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
const SECRET_PASSWORD = "never-send-this-password-to-a-browser";
const timing: { passphraseWaitMs?: number; idleTimeoutMs?: number } = {};

let targets: SmokeTargets;
let base = "";
let app: ReturnType<typeof createApp>;
let browser: Browser;
let clock = Date.now();
const contexts: BrowserContext[] = [];

const code = () => hotp(TOTP_KEY, Math.floor(clock / 30_000));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until(what: string, fn: () => unknown | Promise<unknown>, ms = 10_000) {
  const t0 = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(40);
  }
}

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
      { id: "mismatch", name: "demo-mismatch", group: "Smoke", host: "127.0.0.1", port: targets.plain.port, username: "demo",
        auth: { type: "key", privateKey: targets.plain.privateKey, passphrase: false }, hostKeyFingerprints: [MISMATCH_FP] },
      { id: "restricted", name: "demo-restricted", group: "Private", host: "127.0.0.1", port: targets.plain.port, username: "demo",
        auth: { type: "password", password: SECRET_PASSWORD }, hostKeyFingerprints: [targets.plain.fingerprint], allowedUsers: ["other-user"] },
    ],
  }, process.cwd());
}

async function launchBrowser(): Promise<Browser> {
  const wanted = process.env.SMOKE_BROWSER;
  const attempts = wanted ? [wanted] : ["bundled", "chrome", "msedge"];
  const errors: string[] = [];
  for (const a of attempts) {
    try {
      return await chromium.launch(a === "bundled" ? { headless: true } : { headless: true, channel: a });
    } catch (e) {
      errors.push(`${a}: ${(e as Error).message.split("\n")[0]}`);
    }
  }
  throw new Error(`no browser could be launched (${errors.join("; ")}). Install one with: npx playwright-core install chromium`);
}

before(async () => {
  assert.ok(path.resolve("dist/public"), "dist/public is missing; run npm run build");
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
  browser = await launchBrowser();
});

after(async () => {
  for (const c of contexts) await c.close().catch(() => {});
  await browser?.close().catch(() => {});
  app?.server.closeAllConnections?.();
  app?.server.close();
  targets?.cleanup();
  const left = targets ? leftovers(targets.id) : [];
  if (left.length) console.error(`smoke cleanup left behind: ${left.join(", ")}`);
  else console.log("smoke cleanup: no containers or images left behind");
  setTimeout(() => process.exit(process.exitCode ?? 0), 100).unref();
});

const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

async function githubStep(login: string): Promise<string> {
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

const postCode = (cookie: string, c: string) =>
  fetch(`${base}/auth/totp`, { method: "POST", headers: { cookie, origin: base, "content-type": "application/json" }, body: JSON.stringify({ code: c }) });

async function signIn(login: string): Promise<string> {
  const pending = await githubStep(login);
  clock += 30_000;
  const r = await postCode(pending, code());
  assert.equal(r.status, 204);
  const full = r.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
  assert.notEqual(full, pending);
  return full;
}

const getJson = async (cookie: string, p: string) => {
  const r = await fetch(base + p, { headers: { cookie } });
  return { status: r.status, body: r.status === 200 ? await r.json() : await r.json().catch(() => ({})) } as { status: number; body: any };
};

function openWs(cookie: string, host: string, { origin = base, cols = 100, rows = 30 } = {}) {
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

async function connect(cookie: string, host: string, opts = {}): Promise<Term> {
  const t = openWs(cookie, host, opts);
  await t.waitFor("terminal connected", () => t.json.some((m) => m.state === "connected"), 20_000);
  return t;
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

async function settle(...terms: Term[]) {
  for (const t of terms) {
    if (t.ws.readyState !== WebSocket.CLOSED) t.close();
  }
  await sleep(150);
}

test("the signed-out instance serves only the sign-in page", async () => {
  const r = await fetch(base + "/");
  const html = await r.text();
  assert.match(html, /Sign in to Shellport/);
  assert.doesNotMatch(html, /\/assets\/app-/);
  for (const p of ["/api/me", "/api/hosts", "/api/signins"]) assert.equal((await fetch(base + p)).status, 401, p);
});

test("GitHub step alone leaves a pending session that only sees the TOTP page", async () => {
  const pending = await githubStep("smoke-user");
  const page = await (await fetch(base + "/", { headers: { cookie: pending } })).text();
  assert.match(page, /Two-factor authentication/);
  assert.doesNotMatch(page, /\/assets\/app-/);
  for (const p of ["/api/me", "/api/hosts", "/api/signins"]) assert.equal((await fetch(base + p, { headers: { cookie: pending } })).status, 401, p);
  assert.equal(await wsStatus(pending, "plain", base), 401);
});

test("a wrong TOTP code is refused and counted down", async () => {
  const pending = await githubStep("smoke-user");
  clock += 30_000;
  const wrong = code() === "123456" ? "654321" : "123456";
  const r = await postCode(pending, wrong);
  assert.equal(r.status, 400);
  const body: any = await r.json();
  assert.equal(body.error, "invalid_code");
  assert.equal(body.remaining, 4);
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: pending } })).status, 401);
});

test("a correct TOTP code signs in and the session id rotates", async () => {
  const pending = await githubStep("smoke-user");
  clock += 30_000;
  const r = await postCode(pending, code());
  assert.equal(r.status, 204);
  const full = r.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!;
  assert.match(full, /HttpOnly/i);
  assert.match(full, /SameSite=Lax/i);
  assert.notEqual(full.split(";")[0], pending, "the pending session id must not survive the second factor");
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: pending } })).status, 401, "the pending cookie must stop working");
  assert.equal((await getJson(full.split(";")[0], "/api/me")).status, 200);
});

test("a TOTP code cannot be replayed", async () => {
  const first = await githubStep("smoke-user");
  clock += 30_000;
  const used = code();
  assert.equal((await postCode(first, used)).status, 204);
  const second = await githubStep("smoke-user");
  const replay = await postCode(second, used);
  assert.equal(replay.status, 400);
  assert.equal(((await replay.json()) as any).error, "invalid_code");
  clock += 30_000;
  assert.equal((await postCode(second, code())).status, 204);
});

test("five wrong TOTP codes destroy the pending login", async () => {
  const pending = await githubStep("lockout-user");
  clock += 30_000;
  const wrong = code() === "111111" ? "222222" : "111111";
  let last: Response | undefined;
  for (let i = 0; i < 5; i++) last = await postCode(pending, wrong);
  assert.equal(last!.status, 401);
  assert.equal(((await last!.json()) as any).error, "too_many_attempts");
  const after = await postCode(pending, code());
  assert.equal(after.status, 401);
  assert.equal(((await after.json()) as any).error, "no_pending_login");
});

test("the host list shows only permitted hosts and never a secret", async () => {
  const cookie = await signIn("smoke-user");
  const { status, body } = await getJson(cookie, "/api/hosts");
  assert.equal(status, 200);
  assert.deepEqual(body.map((h: any) => h.id).sort(), ["locked", "mismatch", "plain"]);
  for (const h of body) assert.deepEqual(Object.keys(h).sort(), ["addr", "group", "id", "name", "tag"]);
  const text = JSON.stringify(body);
  assert.doesNotMatch(text, /SHA256:|PRIVATE KEY|OPENSSH|never-send|password|privateKey/i);
  assert.ok(!text.includes(targets.plain.fingerprint.slice(7, 20)), "the host list must not carry the host key fingerprint");
  const other = await getJson(await signIn("other-user"), "/api/hosts");
  assert.ok(other.body.some((h: any) => h.id === "restricted"), "the allowed user should see the restricted host");
  assert.ok(!JSON.stringify(other.body).includes(SECRET_PASSWORD));
});

test("a real terminal runs commands and returns their output", async () => {
  const cookie = await signIn("smoke-user");
  const t = await connect(cookie, "plain");
  const info = t.json.find((m) => m.state === "connected").info;
  assert.equal(info.hostKey, "pinned");
  assert.match(info.auth, /server-managed key/);
  t.type("echo smoke-$((6*7)) && whoami\n");
  await t.waitFor("command output", () => /smoke-42/.test(t.out));
  await t.waitFor("whoami output", () => /\r?\ndemo\r?\n/.test(t.out));
  await settle(t);
});

test("resizing the terminal reaches the remote pty", async () => {
  const cookie = await signIn("smoke-user");
  const t = await connect(cookie, "plain", { cols: 90, rows: 25 });
  t.type("echo size:$(stty size)\n");
  await t.waitFor("initial size", () => /size:25 90/.test(t.out));
  t.send({ t: "resize", cols: 132, rows: 43 });
  await sleep(200);
  t.type("echo size:$(stty size)\n");
  await t.waitFor("resized", () => /size:43 132/.test(t.out));
  await settle(t);
});

test("several terminals on one session are independent", async () => {
  const cookie = await signIn("smoke-user");
  const a = await connect(cookie, "plain");
  const b = await connect(cookie, "plain");
  a.type("echo only-in-a\n");
  b.type("echo only-in-b\n");
  await a.waitFor("a output", () => /only-in-a/.test(a.out));
  await b.waitFor("b output", () => /only-in-b/.test(b.out));
  assert.ok(!/only-in-b/.test(a.out) && !/only-in-a/.test(b.out));
  await settle(a, b);
});

test("the per-user terminal cap refuses the fourth terminal", async () => {
  const cookie = await signIn("cap-user");
  const open = [await connect(cookie, "plain"), await connect(cookie, "plain"), await connect(cookie, "plain")];
  assert.equal(await wsStatus(cookie, "plain", base), 429);
  await settle(...open);
  await sleep(300);
  const again = await connect(cookie, "plain");
  await settle(again);
});

test("a host key that does not match the pin is refused", async () => {
  const cookie = await signIn("smoke-user");
  const t = openWs(cookie, "mismatch");
  await t.waitFor("closed", () => t.closed(), 15_000);
  assert.match(t.json.find((m) => m.t === "error").message, /Host key did not match/);
  assert.ok(!t.json.some((m) => m.state === "connected"));
});

test("a host the user may not open is refused at the WebSocket", async () => {
  const cookie = await signIn("smoke-user");
  assert.equal(await wsStatus(cookie, "restricted", base), 404);
  assert.equal(await wsStatus(cookie, "plain", "https://evil.example"), 403);
  assert.equal(await wsStatus(undefined, "plain", base), 401);
});

test("a passphrase host prompts, counts wrong, empty and oversized tries, and closes after three", async () => {
  const cookie = await signIn("smoke-user");
  const t = openWs(cookie, "locked");
  const prompts = () => t.json.filter((m) => m.t === "passphrase");
  await t.waitFor("first prompt", () => prompts().length === 1);
  assert.equal(prompts()[0].retry, false);
  assert.equal(prompts()[0].remaining, 3);
  t.send({ t: "passphrase", value: "wrong" });
  await t.waitFor("second prompt", () => prompts().length === 2);
  assert.deepEqual([prompts()[1].retry, prompts()[1].remaining], [true, 2]);
  t.send({ t: "passphrase", value: "" });
  await t.waitFor("third prompt", () => prompts().length === 3);
  assert.equal(prompts()[2].remaining, 1);
  t.send({ t: "passphrase", value: "x".repeat(4000) });
  await t.waitFor("closed", () => t.closed());
  assert.match(t.json.find((m) => m.t === "error").message, /Incorrect passphrase/);
  assert.ok(!t.json.some((m) => m.state === "connected"));
});

test("a passphrase host connects with the right passphrase and never echoes it", async () => {
  const cookie = await signIn("smoke-user");
  const t = openWs(cookie, "locked");
  await t.waitFor("prompt", () => t.json.some((m) => m.t === "passphrase"));
  t.send({ t: "passphrase", value: "nope" });
  await t.waitFor("retry prompt", () => t.json.filter((m) => m.t === "passphrase").length === 2);
  t.send({ t: "passphrase", value: targets.locked.passphrase });
  await t.waitFor("connected", () => t.json.some((m) => m.state === "connected"), 20_000);
  assert.match(t.json.find((m) => m.state === "connected").info.auth, /passphrase entered in browser/);
  t.type("echo locked-$((5*5))\n");
  await t.waitFor("output", () => /locked-25/.test(t.out));
  assert.doesNotMatch(JSON.stringify(t.json) + t.out, new RegExp(targets.locked.passphrase));
  await settle(t);
});

test("a rejected passphrase does not restart the 120 second timer (shortened for the run)", async () => {
  timing.passphraseWaitMs = 1500;
  try {
    const cookie = await signIn("smoke-user");
    const t = openWs(cookie, "locked");
    await t.waitFor("prompt", () => t.json.some((m) => m.t === "passphrase"));
    const asked = Date.now();
    await sleep(900);
    t.send({ t: "passphrase", value: "" });
    await t.waitFor("closed", () => t.closed(), 5000);
    const elapsed = Date.now() - asked;
    assert.match(t.closed().reason, /Passphrase timeout/);
    assert.ok(elapsed < 2100, `closed after ${elapsed} ms; a restarted timer would take about 2400 ms`);
  } finally {
    timing.passphraseWaitMs = undefined;
  }
});

test("idle terminals are closed after the idle timeout (shortened for the run)", async () => {
  timing.idleTimeoutMs = 1500;
  try {
    const cookie = await signIn("smoke-user");
    const t = await connect(cookie, "plain");
    await t.waitFor("idle close", () => t.closed(), 6000);
    assert.match(t.closed().reason, /idle/);
  } finally {
    timing.idleTimeoutMs = undefined;
  }
});

test("sign-ins lists sessions and failures, and signing out others ends them and their terminals", async () => {
  const first = await signIn("session-user");
  const bad = await githubStep("session-user");
  clock += 30_000;
  await postCode(bad, code() === "999999" ? "888888" : "999999");
  const second = await signIn("session-user");
  const secondTerm = await connect(second, "plain");

  const list = await getJson(first, "/api/signins");
  assert.equal(list.status, 200);
  const kinds = list.body.items.map((i: any) => i.kind);
  assert.ok(kinds.includes("signin") && kinds.includes("totp_failed"));
  assert.equal(list.body.others, 1);
  const current = list.body.items.filter((i: any) => i.kind === "signin" && i.current);
  assert.equal(current.length, 1);
  assert.ok(list.body.items.some((i: any) => i.kind === "signin" && i.active && !i.current));

  const cross = await fetch(`${base}/api/signins/signout-others`, { method: "POST", headers: { cookie: first, origin: "https://evil.example" } });
  assert.equal(cross.status, 403);
  const r = await fetch(`${base}/api/signins/signout-others`, { method: "POST", headers: { cookie: first, origin: base } });
  assert.equal(r.status, 200);
  assert.equal(((await r.json()) as any).ended, 1);

  await secondTerm.waitFor("second session's terminal closed", () => secondTerm.closed());
  assert.match(secondTerm.closed().reason, /Signed out/);
  assert.equal((await getJson(second, "/api/me")).status, 401);
  assert.equal((await getJson(first, "/api/me")).status, 200);
  const after = await getJson(first, "/api/signins");
  assert.equal(after.body.others, 0);
});

test("one user cannot see another user's sign-in activity", async () => {
  const mine = await getJson(await signIn("smoke-user"), "/api/signins");
  const theirs = await getJson(await signIn("other-user"), "/api/signins");
  const ids = new Set(mine.body.items.map((i: any) => i.id));
  assert.ok(!theirs.body.items.some((i: any) => ids.has(i.id)));
});

test("signing out closes the session's terminals and kills the session", async () => {
  const cookie = await signIn("logout-user");
  const t = await connect(cookie, "plain");
  const cross = await fetch(`${base}/auth/logout`, { method: "POST", headers: { cookie, origin: "https://evil.example" } });
  assert.equal(cross.status, 403);
  assert.equal((await getJson(cookie, "/api/me")).status, 200);
  const out = await fetch(`${base}/auth/logout`, { method: "POST", headers: { cookie, origin: base } });
  assert.equal(out.status, 204);
  await t.waitFor("terminal closed", () => t.closed());
  assert.match(t.closed().reason, /Signed out/);
  assert.equal((await getJson(cookie, "/api/me")).status, 401);
  assert.equal(await wsStatus(cookie, "plain", base), 401);
});

async function newContext(login: string): Promise<BrowserContext> {
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 720 } });
  contexts.push(ctx);
  await ctx.route((url) => url.origin !== base, (route) => route.abort());
  await ctx.route(`${base}/auth/github`, async (route) => {
    const upstream = await route.fetch({ maxRedirects: 0 });
    const state = new URL(upstream.headers().location).searchParams.get("state");
    await route.fulfill({
      status: 302,
      headers: { ...upstream.headers(), location: `${base}/auth/github/callback?code=${encodeURIComponent(login)}&state=${state}` },
    });
  });
  return ctx;
}

const sidOf = async (ctx: BrowserContext) => (await ctx.cookies()).find((c) => c.name === "sp_sid")?.value;

async function uiSignIn(ctx: BrowserContext): Promise<Page> {
  const page = await ctx.newPage();
  page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
  await page.goto(base + "/");
  await page.getByRole("link", { name: /Continue with GitHub/ }).click();
  await page.waitForSelector("#code", { timeout: 8000 }).catch(async (e) => {
    throw new Error(`TOTP page did not appear: at ${page.url()}: ${(await page.locator("body").innerText()).slice(0, 200)} (${String(e.message).split("\n")[0]})`);
  });
  const pending = await sidOf(ctx);
  assert.ok(pending, "a pending session cookie should exist on the TOTP page");
  clock += 30_000;
  await page.fill("#code", code() === "000000" ? "111111" : "000000");
  await page.click("#go");
  await page.waitForSelector("#error:not([hidden])");
  assert.match(await page.textContent("#error") ?? "", /didn't work/);
  await page.fill("#code", code());
  await page.click("#go");
  await page.waitForSelector("#hosts .host");
  const full = await sidOf(ctx);
  assert.ok(full && full !== pending, "the session cookie must rotate after the second factor");
  return page;
}

const termText = (page: Page) => page.locator(".pane:not([hidden]) .xterm-rows").innerText();

async function typeLine(page: Page, line: string) {
  await page.locator(".pane:not([hidden]) .xterm-helper-textarea").focus();
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
}

const flatten = (s: string) => s.split(/\s+/).join(" ");

async function waitTerm(page: Page, pattern: RegExp, ms = 15_000) {
  const t0 = Date.now();
  while (!pattern.test(await termText(page))) {
    if (Date.now() - t0 > ms) {
      throw new Error(`timed out waiting for terminal text ${pattern}; screen: ${JSON.stringify(flatten(await termText(page)).slice(-300))}; status: ${JSON.stringify(flatten(await statusText(page)))}`);
    }
    await sleep(60);
  }
}

const statusText = async (page: Page) => (await page.locator(".tab.active").getAttribute("data-state", { timeout: 1500 }).catch(() => null)) ?? "no session";

async function closeAllTabs(page: Page) {
  while ((await page.locator("#tab-scroll .tab").count()) > 0) {
    if (await page.locator("#drawer").evaluate((el) => el.classList.contains("closed"))) await page.locator("#drawer-toggle").click();
    await page.locator("#close-session").click();
    await sleep(80);
  }
}

let uiCtx: BrowserContext;
let ui: Page;

test("UI: GitHub sign-in, TOTP page, wrong then right code, session rotation", async () => {
  uiCtx = await newContext("ui-user");
  ui = await uiSignIn(uiCtx);
  assert.equal(await ui.locator("#me-login").innerText(), "ui-user");
  assert.equal(await ui.locator("#me-avatar").getAttribute("src"), "https://avatars.githubusercontent.com/u/1");
});

test("UI: the toggle and a slim search box share one wide tab at the left of a full-width tab bar", async () => {
  assert.equal(await ui.locator(".rail .logo, .rail .brand, #search-kbd, .rail kbd, .rail-top, #menu-btn").count(), 0);
  const cell = ui.locator(".tab-search");
  assert.equal(await cell.locator("#rail-toggle").count(), 1);
  assert.equal(await cell.locator("#host-search").count(), 1);
  const [bar, ws, toggle, search, rail, shell] = await Promise.all([
    ui.locator("#tabs").boundingBox(),
    ui.locator("#ws").boundingBox(),
    ui.locator("#rail-toggle").boundingBox(),
    ui.locator(".tab-search .search").boundingBox(),
    ui.locator(".rail").boundingBox(),
    cell.boundingBox(),
  ]);
  assert.ok(bar && ws && toggle && search && rail && shell);
  assert.ok(Math.abs(bar.width - ws.width) < 1 && Math.abs(bar.x - ws.x) < 1, "the tab bar spans the full width");
  assert.ok(Math.abs(shell.x - bar.x) < 1, "the search tab is at the left end of the bar");
  assert.ok(Math.abs(shell.width - rail.width) < 2, "the search tab is as wide as the sidebar below it");
  assert.ok(toggle.x + toggle.width <= search.x + 1, "the toggle sits left of the search box");
  assert.ok(Math.abs(toggle.y + toggle.height / 2 - (search.y + search.height / 2)) < 4, "the toggle and search share a row");
  assert.equal(Math.round(search.height), 26, "the search box is 26px high");
  assert.ok(rail.y >= bar.y + bar.height - 1, "the sidebar starts below the tab bar");
  assert.equal(await ui.locator("#add-tab, #tabs .add").count(), 0);
  assert.deepEqual(await ui.locator(".tab-tools button").evaluateAll((els) => els.map((e) => e.id)), ["drawer-toggle"]);
});

test("UI: the sidebar footer is pinned to the bottom and shows only the avatar and login", async () => {
  const foot = ui.locator(".rail-foot");
  const rail = await ui.locator(".rail").boundingBox();
  const box = await foot.boundingBox();
  assert.ok(rail && box && Math.abs(rail.y + rail.height - (box.y + box.height)) < 2, "the footer touches the bottom of the sidebar");
  assert.match(flatten(await foot.innerText()), /^(UI )?ui-user$/);
  assert.equal(await foot.locator("svg, button:not(#account-btn)").count(), 0);
  assert.equal(await foot.locator("#account-btn #me-avatar").count(), 1);
  assert.equal(await ui.locator("#account-btn").getAttribute("aria-haspopup"), "dialog");
  assert.equal(await ui.locator("#account-btn").getAttribute("aria-label"), "Account menu");
  assert.equal(await ui.locator("#signout, #umenu").count(), 0);
});

test("UI: the host list shows permitted hosts and no secret anywhere on the page", async () => {
  const names = await ui.locator("#hosts .host .name").allInnerTexts();
  assert.deepEqual(names.sort(), ["demo-locked", "demo-mismatch", "demo-plain"]);
  const html = await ui.content();
  assert.doesNotMatch(html, /SHA256:|PRIVATE KEY|never-send|demo-restricted/);
});

test("UI: opening a host runs a command and shows its output", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await typeLine(ui, "echo ui-$((6*7)); whoami");
  await waitTerm(ui, /ui-42/);
  await waitTerm(ui, /\ndemo\s*\n/);
});

test("UI: there is no status bar, and the terminal reaches the bottom of the window", async () => {
  assert.equal(await ui.locator("#status, .status").count(), 0);
  const wrap = await ui.locator(".term-wrap").boundingBox();
  const viewport = ui.viewportSize()!;
  assert.ok(wrap && Math.abs(wrap.y + wrap.height - viewport.height) < 1.5, `the terminal area ends at ${wrap && wrap.y + wrap.height}, the window at ${viewport.height}`);
  assert.equal(await ui.locator(".tab.active").getAttribute("data-state"), "connected");
});

test("UI: the session panel has a Close session action and no shortcuts", async () => {
  const drawer = await ui.locator("#drawer").innerText();
  assert.match(drawer, /session/i);
  assert.match(drawer, /sign-ins/i);
  assert.doesNotMatch(drawer, /shortcuts|toggle sidebar|search hosts/i);
  assert.equal(await ui.locator("#drawer #keys").count(), 0);
  const close = ui.locator("#drawer #close-session");
  assert.equal(await close.isVisible(), true);
  assert.equal(await close.innerText(), "Close session");
  const head = await ui.locator("#drawer .drawer-head").first().boundingBox();
  const btn = await close.boundingBox();
  const details = await ui.locator("#kv").boundingBox();
  assert.ok(head && btn && details && btn.y >= head.y - 1 && btn.y + btn.height <= details.y, "the action sits at the top of the panel, above the details");
});

test("UI: the session panel slides without scrollbars or sideways scrolling, and the sidebar toggle is coloured while it is open", async () => {
  const sample = () => ui.evaluate(() => {
    const body = document.querySelector<HTMLElement>("#drawer .drawer-body")!;
    const drawer = document.getElementById("drawer")!;
    return {
      page: document.documentElement.scrollWidth - innerWidth,
      ws: document.getElementById("ws")!.scrollWidth - document.getElementById("ws")!.clientWidth,
      hosts: document.getElementById("hosts")!.scrollWidth - document.getElementById("hosts")!.clientWidth,
      drawerOverflow: getComputedStyle(drawer).overflow,
      bodyWidth: body.getBoundingClientRect().width,
      drawerWidth: drawer.getBoundingClientRect().width,
    };
  });
  const noSideways = (s: Awaited<ReturnType<typeof sample>>) => s.page <= 0 && s.ws <= 0 && s.hosts <= 0;
  const accentOf = () => ui.evaluate(() => ({
    toggle: getComputedStyle(document.getElementById("rail-toggle")!).color,
    pressed: getComputedStyle(document.getElementById("drawer-toggle")!).color,
  }));
  const open = await accentOf();
  assert.equal(open.toggle, open.pressed, "the sidebar toggle is accent coloured while the sidebar is open");

  await ui.locator("#drawer-toggle").click();
  const during: Awaited<ReturnType<typeof sample>>[] = [];
  for (let i = 0; i < 10; i++) {
    during.push(await sample());
    await sleep(25);
  }
  await sleep(300);
  const closed = await sample();
  assert.ok(during.every(noSideways) && noSideways(closed), `sideways scroll while sliding: ${JSON.stringify(during.filter((s) => !noSideways(s))[0])}`);
  assert.equal(closed.drawerOverflow, "hidden", "the closing panel clips its content instead of showing scrollbars");
  assert.ok(Math.abs(closed.drawerWidth) < 1, "the panel is fully closed");
  assert.ok(during.every((s) => s.bodyWidth >= 279 && s.bodyWidth <= 281), "the content keeps its width while the panel slides, so it does not reflow");
  assert.equal(await ui.locator("#drawer-toggle").getAttribute("aria-pressed"), "false");
  assert.equal(await ui.locator("#drawer .drawer-body").evaluate((el) => getComputedStyle(el).visibility), "hidden");
  await ui.locator("#drawer-toggle").click();
  await sleep(350);
  assert.ok(Math.abs((await sample()).drawerWidth - 280) < 1, "the panel reopens at full width");
  assert.equal(await ui.locator("#drawer-toggle").getAttribute("aria-pressed"), "true");
});

test("UI: resizing the browser resizes the remote terminal", async () => {
  const rows = () => ui.locator(".pane:not([hidden]) .xterm-rows > div").count();
  const readSize = async (tag: string) => {
    const m = new RegExp(`${tag}:(\\d+) (\\d+)`).exec(await termText(ui));
    return m ? { rows: Number(m[1]), cols: Number(m[2]) } : undefined;
  };
  await typeLine(ui, "echo sz1:$(stty size)");
  await until("first size", async () => !!(await readSize("sz1")));
  const first = (await readSize("sz1"))!;
  assert.equal(first.rows, await rows(), "the remote pty has the same number of rows as the browser terminal");
  await ui.setViewportSize({ width: 800, height: 520 });
  await until("size change", async () => (await rows()) !== first.rows);
  await sleep(300);
  await typeLine(ui, "echo sz2:$(stty size)");
  await until("second size", async () => !!(await readSize("sz2")));
  const second = (await readSize("sz2"))!;
  assert.equal(second.rows, await rows());
  assert.ok(second.rows < first.rows && second.cols < first.cols, `the remote size followed the window: ${JSON.stringify({ first, second })}`);
  await ui.setViewportSize({ width: 1100, height: 720 });
});

test("UI: the hover plus on a host row opens a second session, and it is reachable from the keyboard", async () => {
  const plus = ui.locator('button.host-new[data-new="plain"]');
  const row = ui.locator(".host-row", { has: plus });
  await ui.mouse.move(700, 400);
  await ui.locator("#hosts").evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  assert.equal(await plus.evaluate((el) => getComputedStyle(el).opacity), "0", "hidden until hover or focus");
  await row.hover();
  assert.equal(await plus.evaluate((el) => getComputedStyle(el).opacity), "1", "visible on hover");
  await ui.mouse.move(700, 400);
  await ui.locator('button.host[data-host="plain"]').focus();
  await ui.keyboard.press("Tab");
  assert.equal(await plus.evaluate((el) => document.activeElement === el), true, "Tab from the host reaches the plus");
  assert.equal(await plus.evaluate((el) => getComputedStyle(el).opacity), "1", "visible on keyboard focus");
  await ui.locator('button.host[data-host="plain"]').focus();
  await row.hover();
  await plus.click();
  await until("two tabs", async () => (await ui.locator("#tab-scroll .tab").count()) === 2);
  await until("second connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await typeLine(ui, "echo second-tab-only");
  await waitTerm(ui, /second-tab-only/);
  await ui.locator("#tab-scroll .tab").first().click();
  await sleep(300);
  assert.doesNotMatch(await termText(ui), /second-tab-only/);
  await closeAllTabs(ui);
  assert.equal(await ui.locator("#tab-scroll .tab").count(), 0);
});

test("UI: tabs have no close cross, and Close session in the panel closes the active tab", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await ui.locator('button.host-new[data-new="plain"]').click({ force: true });
  await until("two tabs", async () => (await ui.locator("#tab-scroll .tab").count()) === 2);
  assert.equal(await ui.locator("#tab-scroll .tab .x, #tab-scroll [data-close], #tab-scroll [aria-label='Close tab']").count(), 0);
  const names = await ui.locator("#tab-scroll .tab .name").allInnerTexts();
  assert.deepEqual(names, ["demo-plain", "demo-plain (2)"]);
  assert.equal(await ui.locator(".tab.active .name").innerText(), "demo-plain (2)");
  await ui.locator("#close-session").click();
  await until("one tab", async () => (await ui.locator("#tab-scroll .tab").count()) === 1);
  assert.equal(await ui.locator(".tab.active .name").innerText(), "demo-plain");
  await ui.locator("#close-session").click();
  await until("no tabs", async () => (await ui.locator("#tab-scroll .tab").count()) === 0);
  assert.equal(await ui.locator("#close-session").isVisible(), false, "nothing to close without a session");
  assert.equal(await ui.locator("#empty").isVisible(), true);
});

test("UI: tabs can be reordered by dragging", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("plain connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await ui.locator('button.host[data-host="mismatch"]').click();
  await until("two tabs", async () => (await ui.locator("#tab-scroll .tab").count()) === 2);
  try {
    await until("mismatch tab settled", async () => (await ui.locator("#tab-scroll .tab").nth(1).getAttribute("data-state")) === "closed", 20_000);
    const order = () => ui.locator("#tab-scroll .tab .name").allInnerTexts();
    assert.deepEqual(await order(), ["demo-plain", "demo-mismatch"]);
    assert.equal(await ui.locator("#tab-scroll .tab").first().getAttribute("draggable"), "true");
    const activeBefore = await ui.locator(".tab.active .name").innerText();
    const dragUntil = (label: string, from: number, to: number, x: number, want: string) =>
      until(label, async () => {
        if ((await order()).join() === want) return true;
        await ui.locator("#tab-scroll .tab").nth(from).dragTo(ui.locator("#tab-scroll .tab").nth(to), { targetPosition: { x, y: 20 } });
        return (await order()).join() === want;
      }, 15_000);
    await dragUntil("reordered", 0, 1, 170, "demo-mismatch,demo-plain");
    assert.equal(await ui.locator(".tab.active .name").innerText(), activeBefore, "dragging does not change the active tab");
    await dragUntil("reordered back", 1, 0, 20, "demo-plain,demo-mismatch");
  } finally {
    await closeAllTabs(ui);
  }
});

test("UI: tabs are 200px wide and shrink to 120px only when the bar is full", async () => {
  const widths = () => ui.locator("#tab-scroll .tab").evaluateAll((els) => els.map((e) => e.getBoundingClientRect().width));
  const settle = async (label: string, ok: (w: number[]) => boolean) => {
    let last: number[] = [];
    await until(`${label}: ${JSON.stringify(last)}`, async () => ok((last = await widths())), 3000).catch((e) => {
      throw new Error(`${label}; widths were ${JSON.stringify(last)} (${e.message})`);
    });
  };
  const tabCount = () => ui.locator("#tab-scroll .tab").count();
  const addMismatch = async () => {
    await ui.locator('button.host[data-host="mismatch"]').hover();
    await ui.locator('button.host-new[data-new="mismatch"]').click();
  };
  const addUntil = async (n: number) => {
    while ((await tabCount()) < n) {
      await addMismatch();
      await sleep(60);
    }
    await until(`${n} tabs`, async () => (await tabCount()) === n);
  };
  await addUntil(1);
  await settle("a lone tab is 200px wide", (w) => w.every((x) => Math.abs(x - 200) < 1));
  await addUntil(3);
  await settle("three tabs still fit at 200px", (w) => w.every((x) => Math.abs(x - 200) < 1));
  await addUntil(5);
  await settle("a full bar shrinks every tab evenly, but not below 120px", (w) => w.every((x) => x < 199 && x > 121) && Math.max(...w) - Math.min(...w) < 1);
  await addUntil(13);
  await settle("tabs stop shrinking at 120px", (w) => w.every((x) => Math.abs(x - 120) < 1));
  assert.equal(await ui.locator("#tab-scroll").evaluate((el) => el.scrollWidth > el.clientWidth), true, "the bar scrolls once the tabs reach their minimum");
  await closeAllTabs(ui);
});

test("UI: the passphrase prompt counts down on wrong and empty tries, then connects", async () => {
  await ui.locator('button.host[data-host="locked"]').click();
  await waitTerm(ui, /Passphrase for demo@127\.0\.0\.1/);
  await typeLine(ui, "definitely wrong");
  await waitTerm(ui, /Incorrect passphrase\.\s*2 tries left/);
  await ui.keyboard.press("Enter");
  await waitTerm(ui, /1 try left/);
  const passphrase = targets.locked.passphrase;
  const half = Math.floor(passphrase.length / 2);
  await ui.locator(".pane:not([hidden]) .xterm-helper-textarea").focus();
  await ui.keyboard.type(passphrase.slice(0, half));
  for (const key of ["ArrowLeft", "ArrowLeft", "Home", "Delete", "End", "ArrowUp", "ArrowDown", "PageUp", "F5"]) await ui.keyboard.press(key);
  await ui.keyboard.insertText("😀");
  await ui.keyboard.press("Backspace");
  await ui.keyboard.type(passphrase.slice(half));
  await ui.keyboard.press("Enter");
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  assert.doesNotMatch(await termText(ui), new RegExp(passphrase));
  assert.doesNotMatch(await termText(ui), /definitely wrong/);
  await typeLine(ui, "echo locked-ui-$((4*4))");
  await waitTerm(ui, /locked-ui-16/);
  await closeAllTabs(ui);
});

test("UI: three wrong passphrases close the tab and offer a reconnect", async () => {
  await ui.locator('button.host[data-host="locked"]').click();
  await waitTerm(ui, /Passphrase for/);
  for (let i = 0; i < 3; i++) {
    await typeLine(ui, `wrong-${i}`);
    if (i < 2) await waitTerm(ui, new RegExp(`${2 - i} tr(y|ies) left`));
  }
  await until("closed", async () => /closed/.test(await statusText(ui)), 10_000);
  await ui.waitForSelector(".pane:not([hidden]) .banner");
  assert.match(await ui.locator(".pane:not([hidden]) .banner").innerText(), /Reconnect/);
  await closeAllTabs(ui);
});

test("UI: a host-key mismatch is refused with a clear message", async () => {
  await ui.locator('button.host[data-host="mismatch"]').click();
  await waitTerm(ui, /Host key did not match the pinned fingerprint/);
  await until("closed", async () => /closed/.test(await statusText(ui)), 10_000);
  await closeAllTabs(ui);
});

test("UI: the Sign-ins panel shows the other session and signs it out, closing its terminal", async () => {
  const peerCtx = await newContext("ui-user");
  const peer = await uiSignIn(peerCtx);
  await peer.locator('button.host[data-host="plain"]').click();
  await until("peer connected", async () => /connected/.test(await statusText(peer)), 20_000);

  await ui.locator('button.host[data-host="plain"]').click();
  await until("ui connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await ui.goto(base + "/");
  await ui.waitForSelector("#hosts .host");
  await until("other session listed", async () => /other session/.test(await ui.locator("#signins").innerText()));
  await ui.locator("#signout-others").waitFor({ state: "visible" });
  const peerSid = (await sidOf(peerCtx))!;
  await ui.route("**/api/signins/signout-others", (route) => route.fulfill({ status: 500, contentType: "application/json", body: "{}" }));
  try {
    await ui.locator("#signout-others").click();
    await ui.locator("#notice:not([hidden])").waitFor();
    assert.match(await ui.locator("#notice").innerText(), /Could not sign out the other sessions \(status 500\)/);
    assert.equal((await getJson(`sp_sid=${peerSid}`, "/api/me")).status, 200, "a failed request must leave the other session alone");
  } finally {
    await ui.unroute("**/api/signins/signout-others");
  }
  await ui.locator("#signout-others").click();
  await until("peer terminal closed", async () => /closed|Disconnected/.test(await statusText(peer)), 10_000);
  await peer.goto(base + "/").catch(() => {});
  await peer.getByRole("heading", { name: /Sign in to Shellport/ }).waitFor();
  await until("no other sessions", async () => !(await ui.locator("#signins").innerText()).includes("other session"));
  await peerCtx.close();
});

const openAccount = async (page: Page) => {
  await page.locator("#account-btn").click();
  await page.locator("#acct").waitFor({ state: "visible" });
};

const chooseSignOut = async (page: Page) => {
  await openAccount(page);
  await page.locator("#acct-signout").click();
  await page.locator("#signout-dialog").waitFor({ state: "visible" });
};

const isFocused = (page: Page, selector: string) => page.locator(selector).evaluate((el) => document.activeElement === el);

test("UI: the avatar opens a large centred account modal with the display switch, the shortcuts, Close and Sign out", async () => {
  assert.equal(await ui.locator("#acct").isVisible(), false);
  await openAccount(ui);
  const modal = ui.locator("#acct");
  await sleep(350);
  assert.equal(await modal.evaluate((el) => (el as HTMLDialogElement).matches(":modal")), true, "it is a real modal dialog");
  assert.equal(await modal.getAttribute("aria-labelledby"), "acct-title");
  assert.equal(await ui.locator("#account-btn").getAttribute("aria-haspopup"), "dialog");
  assert.equal(await ui.locator("#acct-title").innerText(), "ui-user");
  assert.match(await modal.innerText(), /Signed in with GitHub/);
  const box = await modal.boundingBox();
  const viewport = ui.viewportSize()!;
  assert.ok(box && box.width > 500 && box.width <= 640.5, `the modal is large: ${box?.width}px wide`);
  assert.ok(Math.abs(box.x + box.width / 2 - viewport.width / 2) < 2 && Math.abs(box.y + box.height / 2 - viewport.height / 2) < 2, `the modal is centred in the window: ${JSON.stringify({ box, viewport })}`);
  const text = flatten(await modal.innerText());
  assert.match(text, /display/i);
  assert.match(text, /Hide host addresses/);
  assert.match(text, /shortcuts/i);
  for (const entry of ["Toggle sidebar", "Search hosts", "Copy / paste", "Previous / next tab"]) assert.ok(text.includes(entry), entry);
  assert.match(text, /Ctrl Shift B|⌘ B/);
  const toggle = modal.locator("#addr-toggle");
  assert.equal(await toggle.getAttribute("role"), "switch");
  assert.equal(await toggle.getAttribute("aria-checked"), "false");
  assert.deepEqual(await modal.locator(".acct-foot button").allInnerTexts(), ["Close", "Sign out"]);
  assert.equal(await ui.locator("#umenu").count(), 0, "the old popover menu is gone");
});

test("UI: Escape, the close button, Close and the backdrop all close the account modal and return focus to the avatar", async () => {
  const modal = ui.locator("#acct");
  assert.equal(await modal.isVisible(), true);
  await ui.keyboard.press("Escape");
  assert.equal(await modal.isVisible(), false);
  assert.ok(await isFocused(ui, "#account-btn"), "focus returns to the avatar after Escape");
  await openAccount(ui);
  await ui.locator("#acct-x").click();
  assert.equal(await modal.isVisible(), false);
  await openAccount(ui);
  await ui.locator("#acct-close").click();
  assert.equal(await modal.isVisible(), false);
  assert.ok(await isFocused(ui, "#account-btn"));
  await openAccount(ui);
  await ui.mouse.click(8, 8);
  assert.equal(await modal.isVisible(), false);
  await openAccount(ui);
  await modal.locator("h3").click();
  assert.equal(await modal.isVisible(), true, "clicking inside the modal keeps it open");
  await ui.keyboard.press("Escape");
});

test("UI: the Hide host addresses switch hides the address line in the sidebar and is remembered", async () => {
  const addr = ui.locator('button.host[data-host="plain"] .addr');
  assert.equal(await addr.isVisible(), true);
  await openAccount(ui);
  const toggle = ui.locator("#addr-toggle");
  await toggle.click();
  assert.equal(await toggle.getAttribute("aria-checked"), "true");
  await ui.keyboard.press("Escape");
  assert.equal(await addr.isVisible(), false, "the address line is hidden");
  assert.equal(await ui.locator('button.host[data-host="plain"] .name').isVisible(), true, "the host name stays");
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.hideAddr")), "1");
  await ui.goto(base + "/");
  await ui.waitForSelector("#hosts .host");
  assert.equal(await ui.locator('button.host[data-host="plain"] .addr').isVisible(), false, "the setting survives a reload");
  await openAccount(ui);
  assert.equal(await ui.locator("#addr-toggle").getAttribute("aria-checked"), "true");
  await ui.locator("#addr-toggle").click();
  await ui.keyboard.press("Escape");
  assert.equal(await ui.locator('button.host[data-host="plain"] .addr').isVisible(), true);
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.hideAddr")), "0");
});

test("UI: Sign out asks first, and Cancel, Escape and the backdrop all keep the session", async () => {
  const sid = (await sidOf(uiCtx))!;
  const dialog = ui.locator("#signout-dialog");
  await chooseSignOut(ui);
  assert.equal(await dialog.getAttribute("role"), "alertdialog");
  assert.equal(await dialog.getAttribute("aria-labelledby"), "signout-title");
  assert.equal(await ui.locator("#signout-title").innerText(), "Sign out of Shellport?");
  assert.equal(await ui.locator("#signout-text").innerText(), "Your open terminals will disconnect.");
  assert.deepEqual(await dialog.locator("button").allInnerTexts(), ["Cancel", "Sign out"]);
  assert.ok((await dialog.boundingBox())!.width <= 360.5);
  assert.equal(await ui.locator("#acct").isVisible(), false, "the account modal closes when the confirmation opens");

  await ui.locator("#signout-cancel").click();
  assert.equal(await dialog.isVisible(), false);
  assert.ok(await isFocused(ui, "#account-btn"));

  await chooseSignOut(ui);
  await ui.keyboard.press("Escape");
  assert.equal(await dialog.isVisible(), false);

  await chooseSignOut(ui);
  await ui.mouse.click(10, 10);
  assert.equal(await dialog.isVisible(), false);

  await chooseSignOut(ui);
  await dialog.click();
  assert.equal(await dialog.isVisible(), true, "clicking inside the dialog does not close it");
  await ui.locator("#signout-cancel").focus();
  await ui.keyboard.press("Tab");
  assert.ok(await isFocused(ui, "#signout-confirm"));
  await ui.keyboard.press("Tab");
  assert.ok(await isFocused(ui, "#signout-cancel"), "focus stays inside the dialog");
  await ui.keyboard.press("Escape");

  assert.equal((await getJson(`sp_sid=${sid}`, "/api/me")).status, 200, "the session is untouched");
  assert.equal(await ui.getByRole("heading", { name: /Sign in to Shellport/ }).count(), 0);
});

test("UI: a collapsed sidebar shows only the toggle and the avatar, and expands again", async () => {
  const accentOf = () => ui.evaluate(() => ({
    toggle: getComputedStyle(document.getElementById("rail-toggle")!).color,
    muted: getComputedStyle(document.getElementById("signout-others")!).color,
  }));
  const openColor = (await accentOf()).toggle;
  await ui.locator("#rail-toggle").click();
  await until("collapsed", async () => (await ui.locator("#ws").getAttribute("class"))?.includes("collapsed"));
  await sleep(300);
  assert.equal(await ui.locator("#rail-toggle").isVisible(), true);
  assert.equal(await ui.locator(".tab-search .search").isVisible(), false);
  assert.equal(await ui.locator("#hosts").isVisible(), false);
  assert.equal(await ui.locator("#me-login").isVisible(), false);
  assert.equal(await ui.locator("#account-btn").isVisible(), true);
  const strip = await ui.locator(".tab-search").boundingBox();
  const rail = await ui.locator(".rail").boundingBox();
  const toggle = await ui.locator("#rail-toggle").boundingBox();
  assert.ok(rail && strip && toggle && Math.abs(rail.width - 48) < 2 && Math.abs(strip.width - 48) < 2, `strip widths ${rail?.width} and ${strip?.width}`);
  assert.ok(Math.abs(toggle.x + toggle.width / 2 - (strip.x + strip.width / 2)) < 2, "the toggle is centred in the strip");
  assert.equal(await ui.locator("#rail-toggle").getAttribute("aria-expanded"), "false");
  assert.notEqual((await accentOf()).toggle, openColor, "the toggle is not accent coloured while the sidebar is collapsed");
  await ui.locator("#rail-toggle").click();
  await until("expanded", async () => !(await ui.locator("#ws").getAttribute("class"))?.includes("collapsed"));
  assert.equal(await ui.locator(".tab-search .search").isVisible(), true);
  await sleep(300);
  assert.equal((await accentOf()).toggle, openColor);
});

test("UI: the active host marker is a straight 2px amber bar", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  const marker = await ui.locator('button.host[data-host="plain"]').evaluate((el) => {
    const before = getComputedStyle(el, "::before");
    const row = getComputedStyle(el);
    return { content: before.content, width: before.width, radius: before.borderTopLeftRadius, position: before.position, background: before.backgroundColor, shadow: row.boxShadow };
  });
  assert.equal(marker.width, "2px");
  assert.equal(marker.position, "absolute");
  assert.equal(marker.shadow, "none", "no inset shadow: the bar is its own element");
  assert.notEqual(marker.background, "rgba(0, 0, 0, 0)");
  await closeAllTabs(ui);
});

async function phoneSignIn(login: string) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 800 }, isMobile: true, hasTouch: true });
  contexts.push(ctx);
  await ctx.route((url) => url.origin !== base, (route) => route.abort());
  await ctx.route(`${base}/auth/github`, async (route) => {
    const upstream = await route.fetch({ maxRedirects: 0 });
    const state = new URL(upstream.headers().location).searchParams.get("state");
    await route.fulfill({ status: 302, headers: { ...upstream.headers(), location: `${base}/auth/github/callback?code=${login}&state=${state}` } });
  });
  const page = await ctx.newPage();
  await page.goto(base + "/");
  await page.getByRole("link", { name: /Continue with GitHub/ }).click();
  await page.waitForSelector("#code");
  clock += 30_000;
  await page.fill("#code", code());
  await page.click("#go");
  await page.waitForSelector("#rail-toggle");
  return { ctx, page };
}

test("UI: on a phone the toggle opens the sidebar, and Close session is reachable from the session panel", async () => {
  const { ctx, page } = await phoneSignIn("ui-peer");
  const rail = () => page.locator(".rail").boundingBox();
  assert.ok((await rail())!.x + (await rail())!.width <= 1, "the sidebar starts off screen");
  assert.equal(await page.locator(".tab-search .search").isVisible(), false, "only the toggle shows in the closed tab bar");
  assert.equal(await page.locator("#menu-btn").count(), 0);
  await page.locator("#rail-toggle").click();
  await sleep(450);
  assert.ok(Math.abs((await rail())!.x) < 1, "the sidebar slides in");
  assert.equal(await page.locator(".tab-search .search").isVisible(), true, "the search box appears with the sidebar");
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "no sideways scroll");
  const bar = await page.locator("#tabs").boundingBox();
  assert.ok(Math.abs((await rail())!.y - (bar!.y + bar!.height)) < 2, `the sidebar sits right under the tab bar: ${JSON.stringify({ rail: await rail(), bar })}`);
  await page.locator('button.host[data-host="plain"]').click();
  await until("phone connected", async () => /connected/.test(await statusText(page)), 20_000);
  await sleep(450);
  assert.ok((await rail())!.x + (await rail())!.width <= 1, "choosing a host closes the sidebar");
  assert.equal(await page.locator("#drawer").evaluate((el) => el.classList.contains("closed")), true, "the session panel starts closed on a phone");
  assert.equal(await page.locator("#tab-scroll .tab .x").count(), 0);
  await page.locator("#drawer-toggle").click();
  await sleep(350);
  assert.equal(await page.locator("#close-session").isVisible(), true);
  await page.locator("#close-session").click();
  await until("tab closed", async () => (await page.locator("#tab-scroll .tab").count()) === 0);
  await ctx.close();
});

test("UI: screenshots (only when SMOKE_SCREENSHOTS names a folder)", { skip: !process.env.SMOKE_SCREENSHOTS }, async () => {
  const dir = path.resolve(process.env.SMOKE_SCREENSHOTS!);
  fs.mkdirSync(dir, { recursive: true });
  const shot = (page: Page, name: string) => page.screenshot({ path: path.join(dir, name) });
  await ui.locator("#notice").evaluate((el) => { (el as HTMLElement).hidden = true; });
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await typeLine(ui, "echo welcome to $(hostname); uname -sr; ls -la /etc | head -14");
  await waitTerm(ui, /Linux/);
  await ui.locator('button.host[data-host="plain"]').hover();
  await ui.locator('button.host-new[data-new="plain"]').click();
  await until("second tab", async () => (await ui.locator("#tab-scroll .tab").count()) === 2);
  await ui.locator('button.host[data-host="mismatch"]').click();
  await until("third tab", async () => (await ui.locator("#tab-scroll .tab").count()) === 3);
  await ui.locator("#tab-scroll .tab").first().click();
  await ui.locator("#hosts .host").nth(1).hover();
  await sleep(400);
  await shot(ui, "1-desktop-sidebar-open.png");
  await ui.locator("#drawer-toggle").click();
  await sleep(400);
  await shot(ui, "2-desktop-session-panel-closed.png");
  await ui.locator("#drawer-toggle").click();
  await ui.locator("#rail-toggle").click();
  await sleep(500);
  await shot(ui, "3-desktop-sidebar-collapsed.png");
  await ui.locator("#rail-toggle").click();
  await sleep(500);
  await openAccount(ui);
  await sleep(300);
  await shot(ui, "4-desktop-account-modal.png");
  await ui.locator("#addr-toggle").click();
  await ui.keyboard.press("Escape");
  await sleep(200);
  await shot(ui, "5-desktop-host-addresses-hidden.png");
  await openAccount(ui);
  await ui.locator("#addr-toggle").click();
  await ui.locator("#acct-signout").click();
  await ui.locator("#signout-dialog").waitFor({ state: "visible" });
  await shot(ui, "6-desktop-sign-out-dialog.png");
  await ui.keyboard.press("Escape");
  await closeAllTabs(ui);

  const { ctx: mobileCtx, page: mobile } = await phoneSignIn("ui-peer");
  await mobile.waitForSelector("#rail-toggle");
  await sleep(300);
  await shot(mobile, "7-phone-empty.png");
  await mobile.locator("#rail-toggle").click();
  await sleep(500);
  await shot(mobile, "8-phone-sidebar-open.png");
  await mobile.locator('button.host[data-host="plain"]').click();
  await until("mobile connected", async () => /connected/.test(await statusText(mobile)), 20_000);
  await typeLine(mobile, "echo mobile $(hostname)");
  await waitTerm(mobile, /mobile/);
  await sleep(300);
  await shot(mobile, "9-phone-terminal.png");
  await mobile.locator("#drawer-toggle").click();
  await sleep(400);
  await shot(mobile, "10-phone-session-panel.png");
  await mobile.locator("#drawer-toggle").click();
  await mobile.locator("#rail-toggle").click();
  await sleep(400);
  await openAccount(mobile);
  await sleep(300);
  await shot(mobile, "11-phone-account-modal.png");
  await mobile.keyboard.press("Escape");
  await mobileCtx.close();
});

test("UI: a failed sign out says so and keeps the page and session", async () => {
  const sid = (await sidOf(uiCtx))!;
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await ui.route("**/auth/logout", (route) => route.fulfill({ status: 403, contentType: "application/json", body: '{"error":"bad_origin"}' }));
  try {
    await chooseSignOut(ui);
    await ui.locator("#signout-confirm").click();
    await until("failed signout notice", async () => /Sign out failed \(status 403\)\. You are still signed in/.test(await ui.locator("#notice").innerText()));
    assert.equal(await ui.getByRole("heading", { name: /Sign in to Shellport/ }).count(), 0, "the page must not reload to the sign-in page");
    assert.match(await statusText(ui), /connected/, "the terminal must stay open");
    assert.equal((await getJson(`sp_sid=${sid}`, "/api/me")).status, 200);
  } finally {
    await ui.unroute("**/auth/logout");
  }
});

test("UI: signing out lands on the sign-in page and the session is dead", async () => {
  const sid = (await sidOf(uiCtx))!;
  await chooseSignOut(ui);
  await ui.locator("#signout-confirm").click();
  await ui.getByRole("heading", { name: /Sign in to Shellport/ }).waitFor();
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: `sp_sid=${sid}` } })).status, 401);
  assert.equal(await wsStatus(`sp_sid=${sid}`, "plain", base), 401);
});

test("the black-box smoke script passes against this instance, rate limit included", async () => {
  const child = spawn(process.execPath, ["scripts/smoke.mjs", base, "--rate-limit"], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (d) => (output += d));
  child.stderr.on("data", (d) => (output += d));
  const code = await new Promise<number | null>((r) => child.on("close", r));
  assert.equal(code, 0, output.split("\n").filter((l) => /FAIL|failed|limited/.test(l)).join("\n") || output.slice(-1500));
  assert.match(output, /Rate limiting \(opt-in\)/);
  assert.match(output, /limited after \d+ requests/);
});
