import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { useUi, ui, newContext, uiSignIn, sidOf, termText, typeLine, waitTerm, flatten, statusText, closeAllTabs } from "./ui-fixture.js";
import { base, targets, getJson, remoteExec } from "./app-fixture.js";
import { until, sleep } from "./helpers.js";

useUi();

test("UI: GitHub sign-in, TOTP page, wrong then right code, session rotation", async () => {
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
  assert.equal(await ui.locator("#ai-open").isHidden(), true, "AI suggestions are hidden when disabled");
  assert.deepEqual(await ui.locator(".tab-tools button:visible").evaluateAll((els) => els.map((e) => e.id)), ["lock-btn", "layout-btn", "drawer-toggle"]);
});

test("UI: the sidebar footer is pinned to the bottom and shows only the avatar and login", async () => {
  const foot = ui.locator(".rail-foot");
  const rail = await ui.locator(".rail").boundingBox();
  const box = await foot.boundingBox();
  assert.ok(rail && box && Math.abs(rail.y + rail.height - (box.y + box.height)) < 2, "the footer touches the bottom of the sidebar");
  assert.match(flatten(await foot.innerText()), /^(UI )?ui-user$/);
  assert.equal(await foot.locator("svg, button:not(#account-btn):visible").count(), 0);
  assert.equal(await foot.locator("#add-host").isHidden(), true);
  assert.equal(await foot.locator("#account-btn #me-avatar").count(), 1);
  assert.equal(await ui.locator("#account-btn").getAttribute("aria-haspopup"), null);
  assert.equal(await ui.locator("#account-btn").getAttribute("aria-label"), "Account menu");
  assert.equal(await ui.locator("#signout, #umenu").count(), 0);
});

test("UI: the host list shows permitted hosts and no secret anywhere on the page", async () => {
  const names = await ui.locator("#hosts .host .name").allInnerTexts();
  assert.deepEqual(names.sort(), ["demo-locked", "demo-mismatch", "demo-nofiles", "demo-plain"]);
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

test("UI: the folder icon on an SSH tab switches that tab between the terminal and its files", async () => {
  await ui.locator('button.host[data-host="plain"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  await remoteExec("mkdir -p ~/fx-ui/sub && echo hello-ui > ~/fx-ui/note.txt && echo bye > ~/fx-ui/gone.txt");

  const icon = ui.locator(".tab.active .tab-files");
  assert.equal(await icon.getAttribute("aria-pressed"), "false");
  await icon.click();
  const files = ui.locator("#terms .files:not([hidden])");
  await files.locator(".files-row").first().waitFor();
  assert.equal(await ui.locator(".pane:not([hidden])").count(), 0, "the terminal is hidden while files are showing");
  assert.equal(await icon.getAttribute("aria-pressed"), "true");
  assert.match(await files.locator(".crumbs").innerText(), /home\s*demo/);
  assert.match(await files.locator(".files-foot").innerText(), /SFTP · demo@/);
  const bar = await files.locator(".files-bar").innerText();
  assert.doesNotMatch(bar, /Upload/);
  for (const label of ["Up", "Refresh", "View", "Download", "Delete"]) assert.match(bar, new RegExp(label));
  assert.equal(await files.locator('[data-view]').isDisabled(), true, "nothing is selected yet");

  await files.locator('.files-row[data-name="fx-ui"]').click();
  assert.equal(await files.locator('.files-row[data-name="fx-ui"]').getAttribute("class").then((c) => /sel/.test(c ?? "")), true, "one click selects");
  assert.equal(await files.locator('[data-view]').isDisabled(), true, "a folder cannot be viewed");
  await files.locator('.files-row[data-name="fx-ui"]').dblclick();
  await files.locator('.files-row[data-name="note.txt"]').waitFor();
  assert.match(await files.locator(".crumbs").innerText(), /fx-ui/);

  await files.locator('.files-row[data-name="note.txt"]').dblclick();
  await files.locator(".files-view").waitFor();
  assert.match(await files.locator(".files-view").innerText(), /hello-ui/);
  assert.match(await files.locator(".files-foot").innerText(), /read only/);
  await files.locator("[data-back]").click();
  await files.locator('.files-row[data-name="note.txt"]').waitFor();

  await files.locator('.files-row[data-name="note.txt"]').click({ button: "right" });
  const menu = ui.locator(".ctxmenu:not([hidden])");
  assert.deepEqual((await menu.locator("button").allInnerTexts()).map((x) => x.trim()), ["View", "Download", "Delete"]);
  const [download] = await Promise.all([ui.waitForEvent("download"), menu.locator("[data-download]").click()]);
  assert.equal(download.suggestedFilename(), "note.txt");
  const path = await download.path();
  assert.equal(fs.readFileSync(path!, "utf8"), "hello-ui\n");

  await files.locator('.files-row[data-name="sub"]').click({ button: "right" });
  assert.deepEqual((await ui.locator(".ctxmenu:not([hidden]) button").allInnerTexts()).map((x) => x.trim()), ["Open", "Download", "Delete"]);
  await ui.keyboard.press("Escape");
  assert.equal(await ui.locator(".ctxmenu:not([hidden])").count(), 0);

  await files.locator('.files-row[data-name="gone.txt"]').click({ button: "right" });
  await ui.locator(".ctxmenu:not([hidden]) [data-delete]").click();
  const dialog = ui.getByRole("alertdialog");
  assert.match(await dialog.innerText(), /Delete gone\.txt\?/);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  assert.equal(await files.locator('.files-row[data-name="gone.txt"]').count(), 1, "cancelling keeps the file");
  await files.locator('.files-row[data-name="gone.txt"]').click();
  await files.locator("[data-delete]").click();
  await ui.getByRole("alertdialog").getByRole("button", { name: "Delete", exact: true }).click();
  await until("file removed", async () => (await files.locator('.files-row[data-name="gone.txt"]').count()) === 0);
  assert.equal(await files.locator('.files-row[data-name="note.txt"]').count(), 1);

  await files.locator("[data-up]").click();
  await files.locator('.files-row[data-name="fx-ui"]').waitFor();
  await files.locator("[data-refresh]").click();
  await files.locator('.files-row[data-name="fx-ui"]').waitFor();

  await icon.click();
  await ui.locator(".pane:not([hidden])").waitFor();
  assert.equal(await ui.locator("#terms .files:not([hidden])").count(), 0);
  await remoteExec("test ! -e ~/fx-ui/gone.txt && test -e ~/fx-ui/note.txt && rm -rf ~/fx-ui");
});

test("UI: the folder icon is hidden for hosts with files turned off", async () => {
  await ui.locator('button.host[data-host="nofiles"]').click();
  await until("connected", async () => /connected/.test(await statusText(ui)), 20_000);
  assert.equal(await ui.locator(".tab.active .tab-files:not(.tab-x)").count(), 0);
  await ui.locator("#close-session").click();
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
  const btn = await close.boundingBox();
  const body = await ui.locator("#drawer .drawer-body").boundingBox();
  const signins = await ui.locator("#signins").boundingBox();
  assert.ok(btn && body && signins, "the panel is laid out");
  assert.ok(btn.y >= signins.y + signins.height - 1, "Close session sits below the sign-ins list");
  assert.ok(Math.abs(btn.y + btn.height + 14 - (body.y + body.height)) < 3, `Close session sits at the bottom of the panel (button ends at ${btn.y + btn.height}, panel at ${body.y + body.height})`);
  assert.ok(btn.width > 230, `Close session is a full-width button (${btn.width}px)`);
  assert.equal(await ui.locator("#drawer .drawer-head .tool").count(), 0, "no small text actions are left in the panel headings");
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
  const diagnostic = ui.locator(".pane:not([hidden]) .diagnostic");
  await diagnostic.waitFor();
  assert.match(await diagnostic.innerText(), /Host · Check the host key/);
  assert.match(await diagnostic.innerText(), /verify the host key independently/);
  await diagnostic.getByRole("button", { name: "Show terminal" }).click();
  assert.equal(await diagnostic.count(), 0);
  await ui.locator(".pane:not([hidden]) .banner").getByRole("button", { name: "Reconnect" }).click();
  await diagnostic.waitFor();
  assert.match(await diagnostic.innerText(), /Host · Check the host key/);
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
  await until("peer terminal closed or signed out", async () => {
    try {
      return /closed|Disconnected/.test(await statusText(peer)) || (await peer.getByRole("heading", { name: /Sign in to Shellport/ }).count()) > 0;
    } catch {
      return false;
    }
  }, 10_000);
  await peer.goto(base + "/").catch(() => {});
  await peer.getByRole("heading", { name: /Sign in to Shellport/ }).waitFor();
  await until("no other sessions", async () => !(await ui.locator("#signins").innerText()).includes("other session"));
  await peerCtx.close();
});
