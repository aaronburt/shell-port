import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { decideBoot } from "../src/server/boot.js";
import { loadSealedConfig } from "../src/server/config.js";
import { createUnsealApp, UnsealLockout } from "../src/server/unseal.js";
import { base32Encode } from "../src/server/totp.js";
import { sealVault } from "../src/server/vault.js";

const FAST = { N: 1 << 10, r: 8, p: 1 };
const PASS = "correct horse battery staple";
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-unseal-"));
const publicDir = path.join(dir, "public");
fs.mkdirSync(publicDir);
fs.writeFileSync(path.join(publicDir, "unseal.html"), "<title>Unseal</title>");

const sealedConfig = {
  server: { publicUrl: "https://ssh.example.com" },
  github: { clientId: "id", clientSecret: "client-secret-value" },
  users: [{ github: 1, totpSecret: base32Encode(Buffer.alloc(20, 7)) }],
  hosts: [{ id: "h", host: "h.example.com", username: "u", auth: { type: "password", password: "pw" }, hostKeyFingerprints: ["SHA256:abc"] }],
};
const PLAIN = JSON.stringify(sealedConfig);
const vaultFile = path.join(dir, "vault.sealed");
fs.writeFileSync(vaultFile, sealVault(PLAIN, PASS, FAST));

function request(port: number, method: string, urlPath: string, opts: { headers?: Record<string, string>; body?: unknown } = {}) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string; json: any }>((resolve, reject) => {
    const body = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    const req = http.request(
      { host: "127.0.0.1", port, method, path: urlPath, headers: { ...(body ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } : {}), ...opts.headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: any;
          try { json = JSON.parse(text); } catch {}
          resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

interface Harness {
  port: number;
  unsealed: Buffer[];
  started: number;
  clock: { t: number };
  close: () => Promise<void>;
}

async function start(opts: { trustProxy?: boolean | number; failOnUnseal?: boolean; before?: number } = {}): Promise<Harness> {
  const clock = { t: 1_000_000 };
  const h: Harness = { port: 0, unsealed: [], started: 0, clock, close: async () => {} };
  const { server, shutdown } = createUnsealApp({
    vaultPath: vaultFile,
    publicDir,
    trustProxy: opts.trustProxy,
    lockout: new UnsealLockout(opts.before ?? 3, [60_000, 120_000], () => clock.t),
    onUnsealed: (plain) => {
      if (opts.failOnUnseal) throw new Error("config: bad thing");
      h.unsealed.push(Buffer.from(plain));
      return () => { h.started++; };
    },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  h.port = (server.address() as AddressInfo).port;
  h.close = () => shutdown(500, "test");
  return h;
}

const origin = (h: Harness) => ({ Origin: `http://127.0.0.1:${h.port}` });
const unseal = (h: Harness, passphrase: unknown, headers: Record<string, string> = origin(h)) =>
  request(h.port, "POST", "/api/unseal", { headers, body: { passphrase } });

let main: Harness;
before(async () => { main = await start(); });
after(async () => { await main.close(); });

test("a sealed server reports its state and serves the unseal page", async () => {
  const health = await request(main.port, "GET", "/healthz");
  assert.equal(health.status, 200);
  assert.deepEqual(health.json, { ok: true, sealed: true });
  const page = await request(main.port, "GET", "/");
  assert.equal(page.status, 200);
  assert.match(page.text, /Unseal/);
  assert.equal(page.headers["cache-control"], "no-store");
  assert.match(String(page.headers["content-security-policy"]), /default-src 'self'/);
});

test("a sealed server serves nothing else", async () => {
  for (const p of ["/api/hosts", "/api/me", "/auth/github", "/auth/totp", "/ws"]) {
    const r = await request(main.port, "GET", p);
    assert.equal(r.status, 404, p);
  }
  const post = await request(main.port, "POST", "/auth/totp", { headers: origin(main), body: { code: "123456" } });
  assert.equal(post.status, 404);
});

test("unsealing needs a same-origin request", async () => {
  const none = await unseal(main, PASS, {});
  assert.equal(none.status, 403);
  assert.equal(none.json.error, "bad_origin");
  const other = await unseal(main, PASS, { Origin: "https://evil.example.com" });
  assert.equal(other.status, 403);
  assert.equal(main.unsealed.length, 0);
});

test("malformed bodies are rejected before the vault is touched", async () => {
  for (const body of [undefined, "", 12, ["a"], "x".repeat(2000)]) {
    const r = await unseal(main, body);
    assert.equal(r.status, 400, JSON.stringify(body)?.slice(0, 20));
  }
});

test("unsealing needs HTTPS unless the request comes from the local machine", async () => {
  const h = await start({ trustProxy: 1 });
  try {
    const remote = { ...origin(h), "X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "http" };
    const plain = await unseal(h, PASS, remote);
    assert.equal(plain.status, 403);
    assert.equal(plain.json.error, "https_required");
    const secure = await unseal(h, PASS, { ...remote, "X-Forwarded-Proto": "https" });
    assert.equal(secure.status, 204);
    const local = await unseal(h, PASS, origin(h));
    assert.equal(local.status, 204);
  } finally {
    await h.close();
  }
});

test("a wrong passphrase is refused and counted", async () => {
  const h = await start();
  try {
    const first = await unseal(h, "not the passphrase");
    assert.equal(first.status, 401);
    assert.equal(first.json.error, "invalid_passphrase");
    assert.equal(first.json.remaining, 2);
    const second = await unseal(h, "still not the passphrase");
    assert.equal(second.json.remaining, 1);
    assert.equal(h.unsealed.length, 0);
  } finally {
    await h.close();
  }
});

test("too many failures lock unsealing for everyone, even with the right passphrase, until the lock expires", async () => {
  const h = await start();
  try {
    for (let i = 0; i < 2; i++) await unseal(h, "wrong passphrase " + i);
    const third = await unseal(h, "wrong passphrase 3");
    assert.equal(third.status, 401);
    assert.equal(third.json.retryAfter, 60);
    assert.equal(third.headers["retry-after"], "60");

    const locked = await unseal(h, PASS);
    assert.equal(locked.status, 429);
    assert.equal(locked.json.error, "locked");
    assert.equal(h.unsealed.length, 0);

    h.clock.t += 30_000;
    assert.equal((await unseal(h, PASS)).status, 429);

    h.clock.t += 31_000;
    const ok = await unseal(h, PASS);
    assert.equal(ok.status, 204);
    assert.equal(h.unsealed.length, 1);
  } finally {
    await h.close();
  }
});

test("repeated lockouts last longer", async () => {
  const h = await start();
  try {
    for (let i = 0; i < 3; i++) await unseal(h, "wrong passphrase " + i);
    h.clock.t += 61_000;
    let last: any;
    for (let i = 0; i < 3; i++) last = await unseal(h, "wrong passphrase again " + i);
    assert.equal(last.json.retryAfter, 120);
  } finally {
    await h.close();
  }
});

test("the right passphrase hands the decrypted config over and starts the app after the reply", async () => {
  const h = await start();
  try {
    const r = await unseal(h, PASS);
    assert.equal(r.status, 204);
    assert.equal(h.unsealed[0].toString("utf8"), PLAIN);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(h.started, 1);
  } finally {
    await h.close();
  }
});

test("a vault that unlocks into an invalid config is reported, not counted as a wrong passphrase", async () => {
  const h = await start({ failOnUnseal: true });
  try {
    const r = await unseal(h, PASS);
    assert.equal(r.status, 422);
    assert.equal(r.json.error, "config_invalid");
    assert.match(r.json.message, /bad thing/);
    assert.equal(h.started, 0);
    const again = await unseal(h, "wrong passphrase");
    assert.equal(again.json.remaining, 2);
  } finally {
    await h.close();
  }
});

test("the lockout counter resets after a successful unseal", () => {
  const clock = { t: 0 };
  const l = new UnsealLockout(2, [1000, 2000], () => clock.t);
  l.fail(); l.fail();
  assert.equal(l.retryAfterMs(), 1000);
  clock.t = 1500;
  l.succeed();
  assert.equal(l.retryAfterMs(), 0);
  assert.equal(l.remaining(), 2);
  l.fail(); l.fail();
  assert.equal(l.retryAfterMs(), 1000);
});

test("a sealed config is loaded with secrets given inline", () => {
  const cfg = loadSealedConfig(PLAIN);
  assert.equal(cfg.github.resolvedSecret, "client-secret-value");
  assert.equal(cfg.hosts[0].id, "h");
});

test("a sealed config refuses env and file references", () => {
  const withEnv = { ...sealedConfig, github: { clientId: "id", clientSecret: { env: "SOME_SECRET" } } };
  assert.throws(() => loadSealedConfig(JSON.stringify(withEnv)), /github\.clientSecret: a sealed config cannot use env or file references/);
  const withFile = { ...sealedConfig, hosts: [{ ...sealedConfig.hosts[0], auth: { type: "password", password: { file: "pw.txt" } } }] };
  assert.throws(() => loadSealedConfig(JSON.stringify(withFile)), /hosts\[0\]\.auth\.password: a sealed config cannot use env or file references/);
  assert.throws(() => loadSealedConfig("not json"), /valid JSON/);
});

test("boot: setup, plain, sealed and the error cases", () => {
  const sub = fs.mkdtempSync(path.join(dir, "boot-"));
  const configPath = path.join(sub, "config.json");
  const vault = path.join(sub, "vault.sealed");
  const mode = (forceSetup = false) => decideBoot({ configPath, vaultPath: vault, forceSetup });

  assert.equal(mode().mode, "setup");

  fs.writeFileSync(configPath, "{}");
  assert.equal(mode().mode, "plain");
  assert.equal(mode(true).mode, "setup");

  fs.writeFileSync(vault, sealVault(PLAIN, PASS, FAST));
  const both = mode();
  assert.equal(both.mode, "error");
  assert.match((both as { message: string }).message, /Both a vault/);

  fs.rmSync(configPath);
  assert.deepEqual(mode(), { mode: "sealed", vaultPath: vault });
  assert.equal(mode(true).mode, "error");

  fs.writeFileSync(vault, "garbage");
  const broken = mode();
  assert.equal(broken.mode, "error");
  assert.match((broken as { message: string }).message, /cannot be used/);

  const tampered = JSON.parse(sealVault(PLAIN, PASS, FAST));
  tampered.kdf.N = 1 << 30;
  fs.writeFileSync(vault, JSON.stringify(tampered));
  assert.equal(mode().mode, "error");
});
