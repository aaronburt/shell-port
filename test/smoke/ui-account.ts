import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import type { Page } from "playwright-core";
import { useUi, ui, uiCtx, sidOf, typeLine, waitTerm, flatten, statusText, closeAllTabs } from "./ui-fixture.js";
import { browser, contexts } from "./browser.js";
import { base, code, advanceClock, getJson, wsStatus } from "./app-fixture.js";
import { until, sleep } from "./helpers.js";

useUi();

const openAccount = async (page: Page) => {
  await page.locator("#account-btn").click();
  await page.locator("#page-account").waitFor({ state: "visible" });
};

const closeAccount = async (page: Page) => {
  await page.locator("#acct-close").click();
  await page.locator("#page-account").waitFor({ state: "hidden" });
};

const chooseSignOut = async (page: Page) => {
  await openAccount(page);
  await page.locator("#acct-signout").click();
  await page.locator("#signout-dialog").waitFor({ state: "visible" });
};

const isFocused = (page: Page, selector: string) => page.locator(selector).evaluate((el) => document.activeElement === el);

test("UI: the avatar opens the account as a tab with the display switch, the shortcuts, Close tab and Sign out", async () => {
  assert.equal(await ui.locator("#page-account").isVisible(), false);
  await openAccount(ui);
  const page = ui.locator("#page-account");
  assert.equal(await ui.locator("#acct-title").innerText(), "ui-user");
  assert.match(await page.innerText(), /Signed in with GitHub/);
  const about = (await getJson(`sp_sid=${(await sidOf(uiCtx))!}`, "/api/me")).body;
  assert.ok(about.version);
  assert.equal(await page.locator("#acct-version").innerText(), about.version);
  assert.equal(await page.locator("#acct-release-notes").getAttribute("href"), about.releaseNotesUrl);
  assert.equal(await page.locator("#acct-github").getAttribute("href"), "https://github.com/aaronburt/shell-port");
  for (const id of ["acct-release-notes", "acct-github"]) {
    assert.equal(await page.locator(`#${id}`).getAttribute("target"), "_blank");
    assert.match((await page.locator(`#${id}`).getAttribute("rel"))!, /noopener/);
  }
  const accountWidth = await page.evaluate((el) => ({
    available: el.clientWidth,
    content: el.querySelector(".acct-body")!.getBoundingClientRect().width,
  }));
  assert.ok(Math.abs(accountWidth.content - accountWidth.available) < 2, `account content fills the available width: ${JSON.stringify(accountWidth)}`);
  assert.equal(await ui.locator("#tabs .tab.ptab").count(), 1, "the account has a page tab");
  assert.match(await ui.locator("#tabs .tab.ptab").innerText(), /Account/);
  const text = flatten(await page.innerText());
  assert.match(text, /display/i);
  assert.match(text, /Hide host addresses/);
  assert.match(text, /shortcuts/i);
  for (const entry of ["Toggle sidebar", "Search hosts", "Copy / paste", "Previous / next tab"]) assert.ok(text.includes(entry), entry);
  assert.match(text, /Ctrl Shift B|⌘ B/);
  const toggle = page.locator("#addr-toggle");
  assert.equal(await toggle.getAttribute("role"), "switch");
  assert.equal(await toggle.getAttribute("aria-checked"), "false");
  assert.deepEqual(await page.locator(".acct-foot button").allInnerTexts(), ["Close tab", "Sign out"]);
  assert.equal(await ui.locator("#account-btn").getAttribute("aria-haspopup"), null);
  assert.equal(await ui.locator("#umenu").count(), 0, "the old popover menu is gone");
});

test("UI: the Close tab button closes the account tab, and the avatar opens it again without duplicating it", async () => {
  const page = ui.locator("#page-account");
  assert.equal(await page.isVisible(), true);
  await ui.locator("#acct-close").click();
  assert.equal(await page.isVisible(), false);
  assert.equal(await ui.locator("#tabs .tab.ptab").count(), 0);
  await openAccount(ui);
  await ui.locator("#account-btn").click();
  assert.equal(await ui.locator("#tabs .tab.ptab").count(), 1);
  await closeAccount(ui);
});

test("UI: the theme and terminal theme pickers change the page and open terminals, and reset to the defaults", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await openAccount(ui);
  const root = ui.locator("html");
  const uiBackground = () => ui.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--bg").trim());
  assert.equal(await root.getAttribute("data-theme"), null);
  assert.equal(await ui.locator('[data-ui-theme="system"]').getAttribute("aria-pressed"), "true");
  await ui.locator('[data-ui-theme="light"]').click();
  assert.equal(await root.getAttribute("data-theme"), "light");
  assert.equal(await ui.locator('[data-ui-theme="light"]').getAttribute("aria-pressed"), "true");
  assert.equal(await ui.locator('[data-ui-theme="system"]').getAttribute("aria-pressed"), "false");
  assert.equal(await uiBackground(), "#eef1f5");
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.theme")), "light");
  await ui.locator('[data-ui-theme="dark"]').click();
  assert.equal(await root.getAttribute("data-theme"), "dark");
  assert.equal(await uiBackground(), "#11151b");
  await ui.locator('[data-ui-theme="system"]').click();
  assert.equal(await root.getAttribute("data-theme"), null);
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.theme")), "system");
  await ui.locator("#term-theme").selectOption("paper");
  assert.equal(await root.getAttribute("data-term"), "paper");
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.termTheme")), "paper");
  const viewport = ui.locator(".pane .xterm-viewport").first();
  assert.equal(await viewport.evaluate((el) => getComputedStyle(el).backgroundColor), "rgb(251, 250, 246)");
  await ui.locator("#term-theme").selectOption("shellport");
  assert.equal(await root.getAttribute("data-term"), null);
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.termTheme")), "shellport");
  await closeAccount(ui);
});

test("UI: holding Shift turns the files button on a tab into a close button", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  const tabs = ui.locator("#tabs .tab:not(.ptab)");
  const before = await tabs.count();
  assert.ok(before >= 1);
  await ui.keyboard.down("Shift");
  assert.equal(await ui.evaluate(() => document.body.classList.contains("shift-held")), true);
  await tabs.last().locator(".tab-files").click();
  await ui.keyboard.up("Shift");
  await until("tab closed", async () => (await tabs.count()) === before - 1);
});

test("UI: the Audit log tab is not offered to members", async () => {
  await openAccount(ui);
  assert.equal(await ui.locator("#acct-audit-sec").isVisible(), false);
  await closeAccount(ui);
});

test("UI: the Hide host addresses switch hides the address line in the sidebar and is remembered", async () => {
  const addr = ui.locator('button.host[data-host="plain"] .addr');
  assert.equal(await addr.isVisible(), true);
  await openAccount(ui);
  const toggle = ui.locator("#addr-toggle");
  await toggle.click();
  assert.equal(await toggle.getAttribute("aria-checked"), "true");
  await closeAccount(ui);
  assert.equal(await addr.isVisible(), false, "the address line is hidden");
  assert.equal(await ui.locator('button.host[data-host="plain"] .name').isVisible(), true, "the host name stays");
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.hideAddr")), "1");
  await ui.goto(base + "/");
  await ui.waitForSelector("#hosts .host");
  assert.equal(await ui.locator('button.host[data-host="plain"] .addr').isVisible(), false, "the setting survives a reload");
  await openAccount(ui);
  assert.equal(await ui.locator("#addr-toggle").getAttribute("aria-checked"), "true");
  await ui.locator("#addr-toggle").click();
  await closeAccount(ui);
  assert.equal(await ui.locator('button.host[data-host="plain"] .addr').isVisible(), true);
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.hideAddr")), "0");
});

test("UI: the Interface zoom stepper scales the page, is remembered, and resets", async () => {
  await openAccount(ui);
  await ui.locator("#zoom-in").click();
  await ui.locator("#zoom-in").click();
  assert.equal(await ui.locator("#zoom-reset").textContent(), "120%");
  assert.equal(await ui.evaluate(() => document.documentElement.style.zoom), "1.2");
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.zoom")), "120");
  await closeAccount(ui);
  await ui.goto(base + "/");
  await ui.waitForSelector("#hosts .host");
  assert.equal(await ui.evaluate(() => document.documentElement.style.zoom), "1.2", "the zoom survives a reload");
  await openAccount(ui);
  await ui.locator("#zoom-reset").click();
  assert.equal(await ui.locator("#zoom-reset").textContent(), "100%");
  assert.equal(await ui.evaluate(() => document.documentElement.style.zoom), "");
  assert.equal(await ui.evaluate(() => localStorage.getItem("sp.zoom")), "100");
  await closeAccount(ui);
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

  await ui.locator("#signout-cancel").click();
  assert.equal(await dialog.isVisible(), false);

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
  await closeAccount(ui);

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
  advanceClock();
  await page.fill("#code", code());
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
  await closeAccount(ui);
  await sleep(200);
  await shot(ui, "5-desktop-host-addresses-hidden.png");
  await openAccount(ui);
  await ui.locator("#addr-toggle").click();
  await ui.locator("#acct-signout").click();
  await ui.locator("#signout-dialog").waitFor({ state: "visible" });
  await shot(ui, "6-desktop-sign-out-dialog.png");
  await ui.keyboard.press("Escape");
  await closeAccount(ui);
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
    await closeAccount(ui);
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
