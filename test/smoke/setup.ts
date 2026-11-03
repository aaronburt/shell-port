import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { createSetupApp } from "../../src/server/setup.js";
import { openVault } from "../../src/server/vault.js";
import { generateEd25519 } from "../keys.js";
import { browser, useBrowser } from "./browser.js";
import { until } from "./helpers.js";

useBrowser();
const privateKey = generateEd25519().private;

for (const auth of ["password", "key"]) {
test(`UI: first-run setup stores ${auth} credentials in the vault without persisting the code`, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-setup-ui-"));
  const file = path.join(dir, "config.json");
  const vault = path.join(dir, "vault.sealed");
  const passphrase = "synthetic setup passphrase";
  const token = crypto.randomBytes(32).toString("hex");
  const setup = createSetupApp({ token, configPath: file, vaultPath: vault, publicDir: path.resolve("dist/public") });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors: string[] = [];
  page.on("pageerror", e => errors.push(e.message));
  try {
    await new Promise<void>(r => setup.server.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(setup.server.address() as AddressInfo).port}`;
    await page.goto(url);
    assert.equal(await page.locator("#setup-workspace").isVisible(), false);
    await page.locator("#setup-code").fill("wrong");
    await page.getByRole("button", { name: "Continue to setup" }).click();
    await page.locator("#setup-unlock-error").waitFor({ state: "visible" });
    assert.equal(fs.existsSync(file), false);
    await page.locator("#setup-code").fill(token);
    await page.getByRole("button", { name: "Continue to setup" }).click();
    await page.locator("#setup-form").waitFor({ state: "visible" });
    await page.locator("#gh-client-id").fill("synthetic-client");
    await page.locator("#gh-secret-lit").fill("synthetic-secret");
    await page.locator(".user-github").fill("setup-tester");
    await page.getByRole("button", { name: "Generate Key & QR" }).click();
    await until("generated setup TOTP", () => page.locator(".user-secret-val").inputValue().then(v => v.length >= 26));
    if (auth === "password") {
      await page.locator('input[name^="host-auth-type-"][value="password"]').check();
      await page.locator(".host-password-type").selectOption("literal");
      await page.locator(".host-password-val").fill("synthetic-only");
    } else {
      await page.locator(".host-key-upload").setInputFiles({ name: "synthetic.key", mimeType: "text/plain", buffer: Buffer.from(privateKey) });
      await page.getByText("synthetic.key", { exact: true }).waitFor();
      await page.locator(".host-key-pass").selectOption("unencrypted");
    }
    await page.locator(".host-fingerprints").fill("SHA256:synthetic");
    assert.equal(await page.locator("#seal-enable").count(), 0);
    await page.locator("#seal-pass").fill(passphrase);
    await page.locator("#seal-pass2").fill(passphrase);
    await page.getByRole("button", { name: "Save & Start Shellport" }).click();
    await until("setup vault saved", () => fs.existsSync(vault));
    const saved = openVault(fs.readFileSync(vault), passphrase).toString("utf8");
    assert.equal(fs.existsSync(file), false);
    assert.ok(!saved.includes(token));
    assert.equal(JSON.parse(saved).users[0].github, "setup-tester");
    const storedAuth = JSON.parse(saved).hosts[0].auth;
    if (auth === "password") assert.equal(storedAuth.password, "synthetic-only");
    else assert.equal(storedAuth.privateKey, privateKey);
    const replay = await fetch(url + "/api/setup/save", { method: "POST", headers: { origin: url, "x-shellport-setup-code": token, "content-type": "application/json" }, body: saved });
    assert.equal(replay.status, 409);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.deepEqual(errors, []);
  } finally {
    await ctx.close();
    await setup.shutdown();
    assert.equal(path.dirname(dir), path.resolve(os.tmpdir()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
}
