import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";
import { validateConfig } from "../../src/server/config.js";
import { base32Encode, hotp } from "../../src/server/totp.js";
import { createApp } from "../../src/server/app.js";

const USERS = { "page-admin": 5101, "page-member": 5202 };
const TOTP_KEY = crypto.randomBytes(20);
const FINGERPRINT = "SHA256:" + Buffer.alloc(32).toString("base64").replace(/=+$/, "");

let base = "";
let app: ReturnType<typeof createApp>;
let browser: Browser;
let clock = Date.now();
const contexts: BrowserContext[] = [];
let admin: Page;
let member: Page;
let auditCalls = 0;

const code = () => hotp(TOTP_KEY, Math.floor(clock / 30_000));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until(what: string, fn: () => unknown | Promise<unknown>, ms = 8_000) {
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
    github: { clientId: "page-links", clientSecret: "page-links" },
    users: [
      { github: USERS["page-admin"], totpSecret: base32Encode(TOTP_KEY), admin: true },
      { github: USERS["page-member"], totpSecret: base32Encode(TOTP_KEY) },
    ],
    hosts: [
      { id: "web1", name: "web1", group: "Test", host: "127.0.0.1", port: 9, username: "demo",
        auth: { type: "password", password: "unused" }, hostKeyFingerprints: [FINGERPRINT] },
    ],
  }, process.cwd());
}

async function signedIn(login: string): Promise<Page> {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
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
  const page = await ctx.newPage();
  await page.goto(base + "/");
  await page.getByRole("link", { name: /Continue with GitHub/ }).click();
  await page.waitForSelector("#code", { timeout: 8000 });
  clock += 30_000;
  await page.fill("#code", code());
  await page.waitForSelector("#hosts .host");
  return page;
}

const search = (page: Page) => page.evaluate(() => location.search);
const pageTabs = (page: Page) => page.$$eval("#tab-scroll .tab.ptab", (els) => els.map((e) => e.getAttribute("data-page")));

async function open(page: Page, query = "") {
  await page.goto(`${base}/${query}`);
  await page.waitForSelector("#hosts .host");
}

before(async () => {
  for (let attempt = 0; ; attempt++) {
    const port = await freePort();
    base = `http://127.0.0.1:${port}`;
    app = createApp(buildConfig(port), {
      publicDir: path.resolve("dist/public"),
      now: () => clock,
      exchange: async (c) => {
        const id = USERS[c as keyof typeof USERS];
        if (!id) throw new Error("unknown test user");
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
  browser = await chromium.launch({ headless: true });
  admin = await signedIn("page-admin");
  member = await signedIn("page-member");
  member.on("request", (r) => {
    if (new URL(r.url()).pathname === "/api/audit") auditCalls++;
  });
});

after(async () => {
  for (const c of contexts) await c.close().catch(() => {});
  await browser?.close().catch(() => {});
  app?.server.closeAllConnections?.();
  app?.server.close();
  setTimeout(() => process.exit(process.exitCode ?? 0), 100).unref();
});

test("admin: ?page=account opens the Account tab on load and the address keeps it", async () => {
  await open(admin, "?page=account");
  await admin.locator("#page-account").waitFor({ state: "visible" });
  assert.equal(await admin.locator("#page-audit").isVisible(), false);
  assert.deepEqual(await pageTabs(admin), ["account"]);
  assert.equal(await admin.locator('#tab-scroll .ptab[data-page="account"]').getAttribute("aria-selected"), "true");
  assert.equal(await search(admin), "?page=account");
});

test("admin: ?page=audit opens the Audit log and loads its events", async () => {
  const loaded = admin.waitForResponse((r) => new URL(r.url()).pathname === "/api/audit");
  await open(admin, "?page=audit");
  assert.equal((await loaded).status(), 200);
  await admin.locator("#page-audit").waitFor({ state: "visible" });
  assert.deepEqual(await pageTabs(admin), ["audit"]);
  assert.equal(await search(admin), "?page=audit");
});

test("admin: several page links keep their order, drop repeats and focus the first", async () => {
  await open(admin, "?page=audit&page=account&page=audit");
  await admin.locator("#page-audit").waitFor({ state: "visible" });
  assert.deepEqual(await pageTabs(admin), ["audit", "account"]);
  assert.equal(await search(admin), "?page=audit&page=account");
});

test("admin: a host tab and a page link open together and the page is focused", async () => {
  await open(admin, "?open=web1&page=account");
  await admin.locator("#page-account").waitFor({ state: "visible" });
  assert.equal(await admin.locator("#tab-scroll .tab[data-tab]").count(), 1);
  assert.deepEqual(await pageTabs(admin), ["account"]);
  assert.equal(await search(admin), "?open=web1&page=account");
});

test("admin: the address follows the Account tab as it opens and closes", async () => {
  await open(admin);
  await admin.locator("#account-btn").click();
  await admin.locator("#page-account").waitFor({ state: "visible" });
  await until("the address to name the account", async () => (await search(admin)) === "?page=account");
  await admin.locator("#acct-close").click();
  await until("the address to drop the account", async () => (await search(admin)) === "");
  await admin.locator("#account-btn").click();
  await until("the address to name the account again", async () => (await search(admin)) === "?page=account");
  assert.deepEqual(await pageTabs(admin), ["account"]);
});

test("member: ?page=audit is ignored, makes no audit request and is dropped from the address", async () => {
  auditCalls = 0;
  await open(member, "?page=audit");
  await until("the address to drop the audit link", async () => (await search(member)) === "");
  assert.deepEqual(await pageTabs(member), []);
  assert.equal(await member.locator("#page-audit").isVisible(), false);
  assert.equal(auditCalls, 0);
});

test("member: ?page=account opens the Account tab", async () => {
  await open(member, "?page=account");
  await member.locator("#page-account").waitFor({ state: "visible" });
  assert.deepEqual(await pageTabs(member), ["account"]);
  assert.equal(await search(member), "?page=account");
});

test("unknown page names are ignored", async () => {
  await open(member, "?page=settings");
  await until("the address to drop the unknown page", async () => (await search(member)) === "");
  assert.deepEqual(await pageTabs(member), []);
});
