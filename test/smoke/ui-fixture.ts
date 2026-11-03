import assert from "node:assert/strict";
import type { BrowserContext, Page } from "playwright-core";
import { browser, contexts } from "./browser.js";
import { useApp, base, code, advanceClock } from "./app-fixture.js";
import { sleep } from "./helpers.js";

export async function newContext(login: string): Promise<BrowserContext> {
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

export const sidOf = async (ctx: BrowserContext) => (await ctx.cookies()).find((c) => c.name === "sp_sid")?.value;

export async function uiSignIn(ctx: BrowserContext): Promise<Page> {
  const page = await ctx.newPage();
  page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
  await page.goto(base + "/");
  await page.getByRole("link", { name: /Continue with GitHub/ }).click();
  await page.waitForSelector("#code", { timeout: 8000 }).catch(async (e) => {
    throw new Error(`TOTP page did not appear: at ${page.url()}: ${(await page.locator("body").innerText()).slice(0, 200)} (${String(e.message).split("\n")[0]})`);
  });
  const pending = await sidOf(ctx);
  assert.ok(pending, "a pending session cookie should exist on the TOTP page");
  advanceClock();
  await page.fill("#code", code() === "000000" ? "111111" : "000000");
  await page.waitForSelector("#error:not([hidden])");
  assert.match(await page.textContent("#error") ?? "", /didn't work/);
  await page.fill("#code", code());
  await page.waitForSelector("#hosts .host");
  const full = await sidOf(ctx);
  assert.ok(full && full !== pending, "the session cookie must rotate after the second factor");
  return page;
}

export const termText = (page: Page) => page.locator(".pane:not([hidden]) .xterm-rows").innerText();

export async function typeLine(page: Page, line: string) {
  await page.locator(".pane:not([hidden]) .xterm-helper-textarea").focus();
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
}

export const flatten = (s: string) => s.split(/\s+/).join(" ");

export async function waitTerm(page: Page, pattern: RegExp, ms = 15_000) {
  const t0 = Date.now();
  while (!pattern.test(await termText(page))) {
    if (Date.now() - t0 > ms) {
      throw new Error(`timed out waiting for terminal text ${pattern}; screen: ${JSON.stringify(flatten(await termText(page)).slice(-300))}; status: ${JSON.stringify(flatten(await statusText(page)))}`);
    }
    await sleep(60);
  }
}

export const statusText = async (page: Page) => (await page.locator(".tab.active").getAttribute("data-state", { timeout: 1500 }).catch(() => null)) ?? "no session";

export async function closeAllTabs(page: Page) {
  while ((await page.locator("#tab-scroll .tab").count()) > 0) {
    if (await page.locator("#drawer").evaluate((el) => el.classList.contains("closed"))) await page.locator("#drawer-toggle").click();
    await page.locator("#close-session").click();
    await sleep(80);
  }
}

export let uiCtx: BrowserContext;
export let ui: Page;

export function useUi() {
  useApp({
    browser: true,
    ready: async () => {
      uiCtx = await newContext("ui-user");
      ui = await uiSignIn(uiCtx);
    },
  });
}
