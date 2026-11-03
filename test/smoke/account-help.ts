import assert from "node:assert/strict";
import fs from "node:fs";
import { build } from "esbuild";
import { chromium } from "playwright-core";

const browser = await chromium.launch({ channel: process.env.SMOKE_BROWSER || "chrome", headless: true });
try {
  const compiled = await build({
    stdin: { contents: 'import { initAccountHelp } from "./src/client/account-help.ts"; initAccountHelp(document.getElementById("page-account"));', resolveDir: process.cwd() },
    bundle: true, write: false,
  });
  const html = fs.readFileSync("public/app.html", "utf8").replace(/<script[^>]*>[\s\S]*?<\/script>/g, "");
  const cssFile = fs.readdirSync("dist/public/assets").find((f) => /^app-.*\.css$/.test(f))!;
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route("**/*", (route) => route.abort());
  await page.setContent(html);
  await page.addStyleTag({ content: fs.readFileSync(`dist/public/assets/${cssFile}`, "utf8") });
  await page.evaluate(() => {
    document.querySelectorAll<HTMLElement>("#page-account, #page-account section").forEach((el) => { el.hidden = false; });
    document.getElementById("empty")!.hidden = true;
    document.getElementById("drawer")!.classList.add("closed");
    document.getElementById("ws")!.classList.add("collapsed");
  });
  await page.addScriptTag({ content: compiled.outputFiles[0].text });
  const button = page.getByRole("button", { name: "About Hide host addresses", exact: true });
  const tip = page.locator("#help-addr");
  assert.equal(await tip.isVisible(), false);
  await button.hover();
  await tip.waitFor({ state: "visible" });
  await page.keyboard.press("Escape");
  await tip.waitFor({ state: "hidden" });
  await page.mouse.move(1200, 850);
  await button.focus();
  await tip.waitFor({ state: "visible" });
  await page.keyboard.press("Tab");
  await tip.waitFor({ state: "hidden" });

  await button.hover();
  await tip.hover();
  assert.equal(await tip.isVisible(), true);
  await page.mouse.move(1200, 850);
  await tip.waitFor({ state: "hidden" });

  for (const width of [1280, 375]) {
    await page.setViewportSize({ width, height: 900 });
    for (const zoom of [1, 1.5]) {
      await page.evaluate((z) => { document.documentElement.style.zoom = String(z); }, zoom);
      await button.focus();
      await button.click();
      const box = (await tip.boundingBox())!;
      assert.ok(box.x >= 0 && box.x + box.width <= width + 1, `tooltip stays inside viewport at width ${width}, zoom ${zoom}: ${JSON.stringify(box)}`);
      await page.keyboard.press("Escape");
    }
  }
  const touch = await browser.newPage({ viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true });
  await touch.route("**/*", (route) => route.abort());
  await touch.setContent(await page.content());
  await touch.addScriptTag({ content: compiled.outputFiles[0].text });
  await touch.getByRole("button", { name: "About Hide host addresses", exact: true }).tap();
  await touch.locator("#help-addr").waitFor({ state: "visible" });
  await touch.locator("#zoom-reset").tap();
  await touch.locator("#help-addr").waitFor({ state: "hidden" });
  console.log("Account help checks passed: hover, focus, Escape, pointer travel, narrow screens, zoom, and touch.");
} finally {
  await browser.close();
}
