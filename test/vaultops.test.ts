import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { inlineSecrets, migrateToVault, plainConfigToSealedJson, socketPathFor, writeFileAtomic } from "../src/server/vaultops.js";
import { loadSealedConfig } from "../src/server/config.js";
import { createUnsealApp, UnsealLockout } from "../src/server/unseal.js";
import { base32Encode } from "../src/server/totp.js";
import { openVault, sealVault } from "../src/server/vault.js";
import { createMigrateApp } from "../src/server/migrate.js";
import type { LoadedConfig } from "../src/server/config.js";
import { createSetupApp } from "../src/server/setup.js";
import type { AddressInfo } from "node:net";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-ops-"));
const FAST = { N: 1 << 10, r: 8, p: 1 };
const PASS = "correct horse battery staple";

test("references to env vars and files are inlined, keeping a key's trailing newline", () => {
  fs.writeFileSync(path.join(dir, "pw.txt"), "from-file\n");
  fs.writeFileSync(path.join(dir, "id_key"), "KEY-BODY\n");
  process.env.OPS_TEST_SECRET = "from-env";
  const out = inlineSecrets(
    { a: { env: "OPS_TEST_SECRET" }, hosts: [{ auth: { password: { file: "pw.txt" }, privateKey: { file: "id_key" } } }], keep: "x" },
    dir,
  ) as any;
  assert.equal(out.a, "from-env");
  assert.equal(out.hosts[0].auth.password, "from-file");
  assert.equal(out.hosts[0].auth.privateKey, "KEY-BODY\n");
  assert.equal(out.keep, "x");
});

test("a plain config converts into a sealed config that loads", () => {
  process.env.OPS_TEST_TOTP = base32Encode(Buffer.alloc(20, 3));
  const cfgFile = path.join(dir, "config.json");
  fs.writeFileSync(cfgFile, JSON.stringify({
    server: { publicUrl: "https://ssh.example.com" },
    github: { clientId: "id", clientSecret: { env: "OPS_TEST_TOTP" } },
    users: [{ github: 1, totpSecret: { env: "OPS_TEST_TOTP" } }],
    hosts: [{ id: "h", host: "h", username: "u", auth: { type: "password", password: { file: "pw.txt" } }, hostKeyFingerprints: ["SHA256:a"] }],
  }));
  const json = plainConfigToSealedJson(cfgFile);
  assert.ok(!/"env"|"file"/.test(json));
  assert.equal(loadSealedConfig(json).hosts[0].id, "h");
});

test("atomic writes replace the file with owner-only permissions", () => {
  const f = path.join(dir, "out.txt");
  writeFileAtomic(f, "one");
  writeFileAtomic(f, "two");
  assert.equal(fs.readFileSync(f, "utf8"), "two");
  if (process.platform !== "win32") assert.equal(fs.statSync(f).mode & 0o777, 0o600);
});

test("the local socket unseals without touching the web lockout", async (t) => {
  if (process.platform === "win32") return t.skip("unix sockets");
  const vault = path.join(dir, "vault.sealed");
  const plain = JSON.stringify({ ok: true });
  fs.writeFileSync(vault, sealVault(plain, PASS, FAST));
  const pub = path.join(dir, "public");
  fs.mkdirSync(pub, { recursive: true });
  const lockout = new UnsealLockout(1, [60_000]);
  const got: string[] = [];
  const { server, shutdown, listenSocket } = createUnsealApp({
    vaultPath: vault,
    publicDir: pub,
    socketPath: socketPathFor(vault),
    lockout,
    onUnsealed: (p) => { got.push(p.toString("utf8")); return () => {}; },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  await listenSocket();
  const post = (passphrase: string) =>
    new Promise<number>((resolve, reject) => {
      const body = JSON.stringify({ passphrase });
      const req = http.request(
        { socketPath: socketPathFor(vault), method: "POST", path: "/api/unseal", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), Host: "localhost", Origin: "http://localhost" } },
        (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
      );
      req.on("error", reject);
      req.end(body);
    });
  try {
    lockout.fail();
    assert.ok(lockout.retryAfterMs() > 0);
    assert.equal(await post("wrong passphrase here"), 401);
    assert.equal(await post(PASS), 204);
    assert.deepEqual(got, [plain]);
  } finally {
    await shutdown(500, "test");
  }
  assert.equal(fs.existsSync(socketPathFor(vault)), false);
});

test("the setup wizard can seal the configuration instead of writing config.json", async () => {
  const sub = fs.mkdtempSync(path.join(dir, "setup-"));
  const configPath = path.join(sub, "config.json");
  const vaultPath = path.join(sub, "vault.sealed");
  process.env.OPS_SETUP_PW = "pw-from-env";
  let sealedWith: string | undefined;
  const { server, shutdown } = createSetupApp({
    configPath,
    vaultPath,
    publicDir: path.join(dir, "public"),
    onSaved: (_cfg, v) => { sealedWith = v; },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/setup/save`;
  const config = {
    server: { port: 8080, host: "127.0.0.1", publicUrl: "https://ssh.example.com", trustProxy: false },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: "alice", totpSecret: base32Encode(Buffer.alloc(20, 5)) }],
    hosts: [{ id: "h", host: "h", username: "u", auth: { type: "password", password: { env: "OPS_SETUP_PW" } }, hostKeyFingerprints: ["SHA256:a"] }],
  };
  const send = (body: unknown) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  try {
    const weak = await send({ config, passphrase: "short" });
    assert.equal(weak.status, 400);
    assert.equal(fs.existsSync(vaultPath), false);

    const ok = await send({ config, passphrase: PASS });
    assert.equal(ok.status, 200, JSON.stringify(await ok.clone().json()));
    assert.equal((await ok.json()).sealed, true);
    assert.equal(fs.existsSync(configPath), false);
    const stored = JSON.parse(openVault(fs.readFileSync(vaultPath), PASS).toString("utf8"));
    assert.equal(stored.hosts[0].auth.password, "pw-from-env");
    await new Promise((r) => setTimeout(r, 600));
    assert.equal(sealedWith, vaultPath);

    const again = await send({ config, passphrase: PASS });
    assert.equal(again.status, 409);
  } finally {
    await shutdown(500, "test");
  }
});

test("migrating a plain install writes a vault the sealed loader accepts", () => {
  const sub = fs.mkdtempSync(path.join(dir, "migrate-"));
  fs.writeFileSync(path.join(sub, "pw.txt"), "file-password\n");
  process.env.OPS_MIG_TOTP = base32Encode(Buffer.alloc(20, 9));
  const configPath = path.join(sub, "config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    server: { publicUrl: "https://ssh.example.com" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: 1, totpSecret: { env: "OPS_MIG_TOTP" } }],
    hosts: [{ id: "h", host: "h", username: "u", auth: { type: "password", password: { file: "pw.txt" } }, hostKeyFingerprints: ["SHA256:a"] }],
  }));
  const vaultPath = path.join(sub, "out", "vault.sealed");

  assert.throws(() => migrateToVault({ configPath, vaultPath, passphrase: PASS }), /does not exist/);
  fs.mkdirSync(path.dirname(vaultPath));
  assert.throws(() => migrateToVault({ configPath, vaultPath, passphrase: "short" }), /at least/);
  assert.equal(fs.existsSync(vaultPath), false);

  const cfg = migrateToVault({ configPath, vaultPath, passphrase: PASS });
  assert.equal(cfg.hosts[0].id, "h");
  const stored = JSON.parse(openVault(fs.readFileSync(vaultPath), PASS).toString("utf8"));
  assert.equal(stored.hosts[0].auth.password, "file-password");
  assert.equal(stored.users[0].totpSecret, process.env.OPS_MIG_TOTP);
  assert.ok(fs.existsSync(configPath));
  assert.throws(() => migrateToVault({ configPath, vaultPath, passphrase: PASS }), /already exists/);
});

test("migration mode: needs the code, encrypts the config, and can be skipped", async () => {
  const sub = fs.mkdtempSync(path.join(dir, "mig-app-"));
  process.env.OPS_MIG2_TOTP = base32Encode(Buffer.alloc(20, 4));
  const configPath = path.join(sub, "config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    server: { publicUrl: "https://ssh.example.com" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: 1, totpSecret: { env: "OPS_MIG2_TOTP" } }],
    hosts: [{ id: "h", host: "h", username: "u", auth: { type: "password", password: "pw" }, hostKeyFingerprints: ["SHA256:a"] }],
  }));
  const vaultPath = path.join(sub, "vault.sealed");
  const pub = path.join(sub, "public");
  fs.mkdirSync(pub);
  fs.writeFileSync(path.join(pub, "migrate.html"), "<title>Migrate</title>");
  const events: string[] = [];
  let migrated: LoadedConfig | undefined;
  const { server, shutdown } = createMigrateApp({
    configPath,
    vaultPath,
    publicDir: pub,
    token: "tok-123",
    lockout: new UnsealLockout(3, [60_000]),
    onMigrated: (c) => { migrated = c; events.push("migrated"); },
    onSkip: () => events.push("skipped"),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (p: string, body: unknown, headers: Record<string, string> = { Origin: base }) =>
    fetch(base + p, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  try {
    assert.deepEqual(await (await fetch(base + "/healthz")).json(), { ok: true, migrate: true });
    assert.equal((await fetch(base + "/")).status, 200);
    assert.equal((await fetch(base + "/api/hosts")).status, 404);

    assert.equal((await post("/api/migrate", { token: "tok-123", passphrase: PASS }, {})).status, 403);
    assert.equal((await post("/api/migrate", { token: "wrong", passphrase: PASS })).status, 401);
    assert.equal(fs.existsSync(vaultPath), false);

    const weak = await post("/api/migrate", { token: "tok-123", passphrase: "short" });
    assert.equal(weak.status, 400);
    assert.equal((await weak.json()).error, "weak_passphrase");

    const ok = await post("/api/migrate", { token: "tok-123", passphrase: PASS });
    assert.equal(ok.status, 204);
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(events, ["migrated"]);
    assert.equal(migrated?.hosts[0].id, "h");
    const stored = JSON.parse(openVault(fs.readFileSync(vaultPath), PASS).toString("utf8"));
    assert.equal(stored.users[0].totpSecret, process.env.OPS_MIG2_TOTP);

    const skip = await post("/api/migrate/skip", { token: "tok-123" });
    assert.equal(skip.status, 204);
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(events, ["migrated", "skipped"]);
  } finally {
    await shutdown(500, "test");
  }
});

test("migration mode locks out repeated wrong codes", async () => {
  const sub = fs.mkdtempSync(path.join(dir, "mig-lock-"));
  const { server, shutdown } = createMigrateApp({
    configPath: path.join(sub, "config.json"),
    vaultPath: path.join(sub, "vault.sealed"),
    publicDir: sub,
    token: "right",
    lockout: new UnsealLockout(2, [60_000]),
    onMigrated: () => {},
    onSkip: () => {},
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (token: string) =>
    fetch(base + "/api/migrate/skip", { method: "POST", headers: { "Content-Type": "application/json", Origin: base }, body: JSON.stringify({ token }) });
  try {
    assert.equal((await post("a")).status, 401);
    assert.equal((await post("b")).status, 401);
    assert.equal((await post("right")).status, 429);
  } finally {
    await shutdown(500, "test");
  }
});

test("migration mode accepts a passphrase from a trusted proxy that reports HTTPS, and refuses one that reports HTTP", async () => {
  const sub = fs.mkdtempSync(path.join(dir, "mig-proxy-"));
  fs.mkdirSync(path.join(sub, "v"));
  const configPath = path.join(sub, "config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    server: { publicUrl: "https://ssh.example.com" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: 1, totpSecret: base32Encode(Buffer.alloc(20, 2)) }],
    hosts: [{ id: "h", host: "h", username: "u", auth: { type: "password", password: "pw" }, hostKeyFingerprints: ["SHA256:a"] }],
  }));
  const { server, shutdown } = createMigrateApp({
    configPath,
    vaultPath: path.join(sub, "v", "vault.sealed"),
    publicDir: sub,
    token: "tok",
    trustProxy: 1,
    onMigrated: () => {},
    onSkip: () => {},
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const post = (headers: Record<string, string>) =>
    new Promise<number>((resolve, reject) => {
      const body = JSON.stringify({ token: "tok", passphrase: PASS });
      const req = http.request(
        { host: "127.0.0.1", port, method: "POST", path: "/api/migrate", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), Host: "ssh.example.com", Origin: "https://ssh.example.com", "X-Forwarded-For": "203.0.113.5", ...headers } },
        (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
      );
      req.on("error", reject);
      req.end(body);
    });
  try {
    assert.equal(await post({ "X-Forwarded-Proto": "http" }), 403);
    assert.equal(await post({ "X-Forwarded-Proto": "https" }), 204);
  } finally {
    await shutdown(500, "test");
  }
});
