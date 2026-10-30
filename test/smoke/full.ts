import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
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
  assert.doesNotMatch(text, new RegExp(targets.plain.fingerprint.slice(7, 20)));
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
  await ctx.route((url) => url.origin !== base, (route) => {
    if (route.request().url().startsWith("https://avatars.githubusercontent.com/"))
      return route.fulfill({ status: 200, contentType: "image/gif", body: Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64") });
    return route.abort();
  });
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

const statusText = (page: Page) => page.locator("#status").innerText();

async function closeAllTabs(page: Page) {
  while ((await page.locator("#tab-scroll .tab").count()) > 0) {
    await page.locator("#tab-scroll .tab .x").first().click();
    await sleep(80);
  }
}

let uiCtx: BrowserContext;
let ui: Page;

test("UI: GitHub sign-in, TOTP page, wrong then right code, session rotation", async () => {
  uiCtx = await newContext("ui-user");
  ui = await uiSignIn(uiCtx);
  assert.match(await ui.locator("#me-sub").innerText(), /ui-user/);
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

test("UI: resizing the browser resizes the remote terminal", async () => {
  const dims = async () => {
    const m = /(\d+)×(\d+)/.exec(await statusText(ui))!;
    return `${m[2]} ${m[1]}`;
  };
  await typeLine(ui, "echo sz1:$(stty size)");
  const before = await dims();
  await waitTerm(ui, new RegExp(`sz1:${before}`));
  await ui.setViewportSize({ width: 800, height: 520 });
  await until("size change", async () => (await dims()) !== before);
  const after = await dims();
  await sleep(300);
  await typeLine(ui, "echo sz2:$(stty size)");
  await waitTerm(ui, new RegExp(`sz2:${after}`));
  await ui.setViewportSize({ width: 1100, height: 720 });
});

test("UI: a second tab to the same host is independent, and tabs close", async () => {
  await ui.locator('button.host-new[data-new="plain"]').click({ force: true });
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
  await ui.locator("#signout-others").click();
  await ui.locator("#notice:not([hidden])").waitFor();
  assert.match(await ui.locator("#notice").innerText(), /Could not sign out the other sessions \(status 500\)/);
  assert.equal((await getJson(`sp_sid=${peerSid}`, "/api/me")).status, 200, "a failed request must leave the other session alone");
  await ui.unroute("**/api/signins/signout-others");
  await ui.locator("#signout-others").click();
  await until("peer terminal closed", async () => /closed|Disconnected/.test(await statusText(peer)), 10_000);
  await peer.reload();
  await peer.getByRole("heading", { name: /Sign in to Shellport/ }).waitFor();
  await until("no other sessions", async () => !(await ui.locator("#signins").innerText()).includes("other session"));
  await peerCtx.close();
});

test("UI: a failed sign out says so and keeps the page and session", async () => {
  const sid = (await sidOf(uiCtx))!;
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await ui.route("**/auth/logout", (route) => route.fulfill({ status: 403, contentType: "application/json", body: '{"error":"bad_origin"}' }));
  await ui.locator("#signout").click();
  await ui.locator("#notice:not([hidden])").waitFor();
  assert.match(await ui.locator("#notice").innerText(), /Sign out failed \(status 403\)\. You are still signed in/);
  assert.equal(await ui.getByRole("heading", { name: /Sign in to Shellport/ }).count(), 0, "the page must not reload to the sign-in page");
  assert.match(await statusText(ui), /connected/, "the terminal must stay open");
  assert.equal((await getJson(`sp_sid=${sid}`, "/api/me")).status, 200);
  await ui.unroute("**/auth/logout");
});

test("UI: signing out lands on the sign-in page and the session is dead", async () => {
  const sid = (await sidOf(uiCtx))!;
  await ui.locator("#signout").click();
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
