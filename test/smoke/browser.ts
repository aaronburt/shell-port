import { before, after } from "node:test";
import { chromium, type Browser, type BrowserContext } from "playwright-core";

export let browser: Browser;
export const contexts: BrowserContext[] = [];

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

export async function startBrowser() {
  browser = await launchBrowser();
}

export async function closeBrowser() {
  for (const context of contexts) await context.close().catch(() => {});
  await browser?.close();
}

export function useBrowser() {
  before(startBrowser);
  after(closeBrowser);
}
