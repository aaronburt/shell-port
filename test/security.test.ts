import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import net, { type AddressInfo } from "node:net";
import { createApp } from "../src/server/app.js";
import { validateConfig } from "../src/server/config.js";
import { createSetupApp } from "../src/server/setup.js";

const TOKEN = "test-only-setup-code";
const config = () => ({
  server: { port: 8080, host: "127.0.0.1", publicUrl: "http://localhost:8080" },
  github: { clientId: "test", clientSecret: "synthetic" },
  users: [{ github: "tester", totpSecret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" }],
  hosts: [{ id: "h", host: "127.0.0.1", username: "demo", auth: { type: "password", password: "synthetic" }, hostKeyFingerprints: ["SHA256:a"] }],
});

async function setup(trustProxy: boolean | number = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sp-setup-security-"));
  const configPath = path.join(dir, "config.json");
  const app = createSetupApp({ token: TOKEN, configPath, vaultPath: path.join(dir, "vault.sealed"), publicDir: path.resolve("dist/public"), trustProxy });
  await new Promise<void>(r => app.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  const headers = { "content-type": "application/json", "x-shellport-setup-code": TOKEN, origin: base };
  return { ...app, configPath, base, headers, cleanup: async () => {
    await app.shutdown();
    assert.equal(path.dirname(dir), path.resolve(os.tmpdir()));
    fs.rmSync(dir, { recursive: true, force: true });
  } };
}

test("every setup API requires the bootstrap code, including local requests", async () => {
  const s = await setup();
  try {
    assert.equal((await fetch(s.base + "/healthz")).status, 200);
    for (const [route, method] of [["status", "GET"], ["totp", "POST"], ["validate", "POST"], ["save", "POST"]]) {
      for (const token of ["", "wrong", "é".repeat(TOKEN.length)]) {
        const r = await fetch(`${s.base}/api/setup/${route}`, { method, headers: { ...s.headers, "x-shellport-setup-code": token }, ...(method === "POST" ? { body: JSON.stringify(config()) } : {}) });
        assert.equal(r.status, 401, `${method} ${route}`);
        assert.ok(!(await r.text()).includes(TOKEN));
      }
    }
    assert.equal(fs.existsSync(s.configPath), false);
    const status = await fetch(s.base + "/api/setup/status", { headers: s.headers });
    assert.equal(status.status, 200);
    assert.ok(!(await status.text()).includes(TOKEN));
  } finally { await s.cleanup(); }
});

test("setup writes reject missing, foreign and wrong-scheme origins even with the code", async () => {
  const s = await setup();
  try {
    for (const origin of [undefined, "https://evil.example", s.base.replace("http:", "https:")]) {
      const headers: Record<string, string> = { ...s.headers };
      if (origin === undefined) delete headers.origin; else headers.origin = origin;
      const r = await fetch(s.base + "/api/setup/save", { method: "POST", headers, body: JSON.stringify(config()) });
      assert.equal(r.status, 403);
      assert.equal((await r.json()).error, "bad_origin");
    }
    assert.equal(fs.existsSync(s.configPath), false);
  } finally { await s.cleanup(); }
});

test("setup refuses remote plaintext transport and accepts a configured HTTPS proxy", async () => {
  const s = await setup(1);
  const request = (proto: string) => new Promise<number>((resolve, reject) => {
    const req = http.request(s.base + "/api/setup/status", { headers: { host: "ssh.example.com", "x-forwarded-proto": proto, "x-shellport-setup-code": TOKEN } }, res => { res.resume(); resolve(res.statusCode!); });
    req.on("error", reject); req.end();
  });
  try { assert.equal(await request("http"), 403); assert.equal(await request("https"), 200); }
  finally { await s.cleanup(); }
});

test("invalid setup cannot persist a config, and a successful save consumes the code", async () => {
  const s = await setup();
  const save = (config: unknown) => fetch(s.base + "/api/setup/save", { method: "POST", headers: s.headers, body: JSON.stringify({ config, passphrase: "synthetic vault passphrase" }) });
  try {
    const invalid = config(); invalid.users[0].totpSecret = "invalid";
    assert.equal((await save(invalid)).status, 400);
    assert.equal(fs.existsSync(s.configPath), false);
    const invalidKey = config() as any;
    invalidKey.hosts[0].auth = { type: "key", privateKey: "not a key" };
    assert.equal((await save(invalidKey)).status, 400);
    assert.equal(fs.existsSync(s.configPath), false);
    assert.equal((await fetch(s.base + "/api/setup/save", { method: "POST", headers: s.headers, body: JSON.stringify(config()) })).status, 400);
    assert.equal(fs.existsSync(s.configPath), false);
    const replies = await Promise.all([save(config()), save(config())]);
    assert.deepEqual(replies.map(r => r.status).sort(), [200, 409]);
    const saved = fs.readFileSync(path.join(path.dirname(s.configPath), "vault.sealed"), "utf8");
    assert.ok(!saved.includes(TOKEN));
    if (process.platform !== "win32") assert.equal(fs.statSync(path.join(path.dirname(s.configPath), "vault.sealed")).mode & 0o777, 0o600);
    assert.equal((await save(config())).status, 409);
    assert.equal(fs.readFileSync(path.join(path.dirname(s.configPath), "vault.sealed"), "utf8"), saved);
  } finally { await s.cleanup(); }
});

test("incorrect setup codes are rate limited without locking out the owner", async () => {
  const s = await setup();
  try {
    for (let i = 0; i < 30; i++) assert.equal((await fetch(s.base + "/api/setup/status", { headers: { "x-shellport-setup-code": "wrong" } })).status, 401);
    assert.equal((await fetch(s.base + "/api/setup/status", { headers: { "x-shellport-setup-code": "wrong" } })).status, 429);
    assert.equal((await fetch(s.base + "/api/setup/status", { headers: s.headers })).status, 200);
  } finally { await s.cleanup(); }
});

test("malformed unauthenticated upgrade targets return 400 and the server stays alive", async () => {
  const cfg = validateConfig(config(), process.cwd());
  const app = createApp(cfg, { publicDir: path.resolve("dist/public") });
  await new Promise<void>(r => app.server.listen(0, "127.0.0.1", r));
  const port = (app.server.address() as AddressInfo).port;
  try {
    for (const target of ["//[/ws", "/\\[/ws", "http://[/ws", "//evil.example/ws"]) {
      const response = await new Promise<string>((resolve, reject) => {
        let data = "";
        const socket = net.connect(port, "127.0.0.1", () => socket.write(`GET ${target} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: c21va2UtdGVzdC1rZXktMTY=\r\n\r\n`));
        socket.setTimeout(3000, () => socket.destroy(new Error("Upgrade response timed out")));
        socket.on("data", chunk => { data += chunk.toString(); });
        socket.on("end", () => resolve(data));
        socket.on("error", reject);
      });
      assert.match(response, /^HTTP\/1\.1 400 /, target);
      assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
    }
  } finally { await app.shutdown(); }
});


test("legacy plaintext config cannot bypass migration with SHELLPORT_MIGRATE=off", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sp-mandatory-vault-"));
  const listener = net.createServer();
  await new Promise<void>(resolve => listener.listen(0, "127.0.0.1", resolve));
  const port = (listener.address() as AddressInfo).port;
  await new Promise<void>(resolve => listener.close(() => resolve()));
  const cfg = config();
  cfg.server.port = port;
  const configPath = path.join(dir, "config.json");
  fs.writeFileSync(configPath, JSON.stringify(cfg));
  const child = spawn(process.execPath, [path.resolve("dist/server.js")], {
    env: { ...process.env, HOST: "127.0.0.1", PORT: String(port), SHELLPORT_CONFIG: configPath,
      SHELLPORT_VAULT: path.join(dir, "vault.sealed"), SHELLPORT_MIGRATE: "off", SHELLPORT_SETUP: "0" },
    stdio: "ignore",
  });
  const exited = once(child, "exit");
  try {
    let health: any;
    for (let i = 0; i < 100; i++) {
      try { health = await (await fetch(`http://127.0.0.1:${port}/healthz`)).json(); break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(health?.migrate, true);
    assert.equal((await fetch(`http://127.0.0.1:${port}/auth/github`)).status, 404);
    assert.equal(fs.existsSync(path.join(dir, "vault.sealed")), false);
  } finally {
    child.kill();
    await exited;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
