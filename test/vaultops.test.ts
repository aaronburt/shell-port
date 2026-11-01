import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { inlineSecrets, plainConfigToSealedJson, socketPathFor, writeFileAtomic } from "../src/server/vaultops.js";
import { loadSealedConfig } from "../src/server/config.js";
import { createUnsealApp, UnsealLockout } from "../src/server/unseal.js";
import { base32Encode } from "../src/server/totp.js";
import { sealVault } from "../src/server/vault.js";

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
