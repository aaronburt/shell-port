import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { feedPassphrase } from "../src/client/passphrase.js";
import { resolveSecret, validateConfig } from "../src/server/config.js";
import { RateLimiter } from "../src/server/sessions.js";
import { base32Encode } from "../src/server/totp.js";
import { validateSetupConfig, isPathWritable, createSetupApp } from "../src/server/setup.js";
import { generateEd25519 } from "./keys.js";

const type = (current: string, ...chunks: string[]) => {
  let value = current;
  for (const c of chunks) value = feedPassphrase(value, c).value;
  return value;
};

test("passphrase input appends printable characters, including astral ones", () => {
  assert.equal(type("", "hunter2"), "hunter2");
  assert.equal(type("", "pa", "ss", " word"), "pass word");
  assert.equal(type("", "a😀b"), "a😀b");
});

test("passphrase input ignores CSI escape sequences such as arrows, Home, End and Delete", () => {
  for (const seq of ["\x1b[D", "\x1b[C", "\x1b[A", "\x1b[B", "\x1b[3~", "\x1b[H", "\x1b[F", "\x1b[1;5C", "\x1b[5~", "\x1b[200~", "\x1b[201~"]) {
    assert.equal(type("abc", seq), "abc", JSON.stringify(seq));
    assert.equal(type("", "ab" + seq + "cd"), "abcd", JSON.stringify(seq));
  }
});

test("passphrase input ignores SS3 sequences, lone escapes and Alt chords", () => {
  for (const seq of ["\x1bOA", "\x1bOH", "\x1bOP", "\x1b", "\x1bb", "\x1bf"]) {
    assert.equal(type("abc", seq), "abc", JSON.stringify(seq));
    if (seq !== "\x1b") assert.equal(type("", "x" + seq + "y"), "xy", JSON.stringify(seq));
  }
  assert.equal(type("abc", "\x1b[", "D"), "abcD");
  assert.equal(type("", "x\x1b"), "x");
});

test("passphrase input ignores other control characters", () => {
  assert.equal(type("", "a\x00b\x01c\x1fd\x9be"), "abcde");
});

test("passphrase backspace removes one Unicode code point, not one UTF-16 unit", () => {
  assert.equal(type("", "a😀", "\x7f"), "a");
  assert.equal(type("", "😀😀", "\x7f"), "😀");
  assert.equal(type("ab", "\x7f\x7f\x7f"), "");
  assert.equal(type("", "ab", "\b"), "a");
  assert.equal(type("", "𠮷", "\x7f"), "");
});

test("passphrase input supports clear-line, submit and cancel", () => {
  assert.equal(type("secret", "\x15"), "");
  assert.deepEqual(feedPassphrase("pass", "word\r"), { value: "password", action: "submit" });
  assert.deepEqual(feedPassphrase("pass", "word\n"), { value: "password", action: "submit" });
  assert.deepEqual(feedPassphrase("pass", "\x03").action, "cancel");
  assert.deepEqual(feedPassphrase("pass", "\x04").action, "cancel");
  assert.deepEqual(feedPassphrase("", "ab\x1b[Dc\r"), { value: "abc", action: "submit" });
  assert.equal(feedPassphrase("", "abc").action, "none");
});

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-unit-"));
const write = (name: string, content: string) => {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return p;
};

test("file secrets lose exactly one trailing newline and nothing else", () => {
  const read = (content: string, keep = false) => resolveSecret({ file: write("s.txt", content) }, dir, "test", keep);
  assert.equal(read("secret"), "secret");
  assert.equal(read("secret\n"), "secret");
  assert.equal(read("secret\r\n"), "secret");
  assert.equal(read("secret\n\n"), "secret\n");
  assert.equal(read("secret\r\n\r\n"), "secret\r\n");
  assert.equal(read("secret \n"), "secret ");
  assert.equal(read(" secret"), " secret");
  assert.equal(read("a\nb\n"), "a\nb");
  assert.equal(read("secret\n", true), "secret\n");
  assert.equal(read(""), "");
});

test("inline and environment secrets are left alone", () => {
  process.env.UNIT_SECRET = "value\n";
  assert.equal(resolveSecret("inline\n", dir, "test"), "inline\n");
  assert.equal(resolveSecret({ env: "UNIT_SECRET" }, dir, "test"), "value\n");
});

const secret = base32Encode(crypto.randomBytes(20));
const baseConfig = (hosts: object[], github: object = { clientId: "a", clientSecret: "b" }) => ({
  server: { publicUrl: "https://x.example" },
  github,
  users: [{ github: "a", totpSecret: secret }],
  security: { allowUnpinnedHostKeys: true },
  hosts,
});
const keyHost = (auth: object) => ({ id: "h", host: "h", username: "u", auth: { type: "key", ...auth } });

test("the GitHub client secret can come from a file with a trailing newline", () => {
  const file = write("github.txt", "client-secret-value\r\n");
  const cfg = validateConfig(baseConfig([keyHost({ privateKey: generateEd25519().private, passphrase: false })], { clientId: "a", clientSecret: { file } }), dir);
  assert.equal(cfg.github.resolvedSecret, "client-secret-value");
});

test("a password host can use a file secret with a trailing newline", () => {
  const file = write("password.txt", "s3cret\n");
  const cfg = validateConfig(baseConfig([{ id: "h", host: "h", username: "u", auth: { type: "password", password: { file } } }]), dir);
  assert.equal(resolveSecret((cfg.hosts[0].auth as { password: { file: string } }).password, dir, "t"), "s3cret");
});

test("a server-held key passphrase is verified at startup", () => {
  const key = generateEd25519("correct horse");
  assert.doesNotThrow(() => validateConfig(baseConfig([keyHost({ privateKey: key.private, passphrase: "correct horse" })]), dir));
  assert.throws(() => validateConfig(baseConfig([keyHost({ privateKey: key.private, passphrase: "wrong horse" })]), dir), /passphrase does not unlock/);
  const good = write("pp-good.txt", "correct horse\n");
  const bad = write("pp-bad.txt", "wrong horse\n");
  assert.doesNotThrow(() => validateConfig(baseConfig([keyHost({ privateKey: key.private, passphrase: { file: good } })]), dir));
  assert.throws(() => validateConfig(baseConfig([keyHost({ privateKey: key.private, passphrase: { file: bad } })]), dir), /passphrase does not unlock/);
  process.env.UNIT_PASSPHRASE = "wrong horse";
  assert.throws(() => validateConfig(baseConfig([keyHost({ privateKey: key.private, passphrase: { env: "UNIT_PASSPHRASE" } })]), dir), /passphrase does not unlock/);
});

test("a private key file keeps working with a trailing newline", () => {
  const key = generateEd25519("correct horse");
  const file = write("key.pem", key.private.endsWith("\n") ? key.private : key.private + "\n");
  assert.doesNotThrow(() => validateConfig(baseConfig([keyHost({ privateKey: { file }, passphrase: "correct horse" })]), dir));
  assert.doesNotThrow(() => validateConfig(baseConfig([keyHost({ privateKey: { file } })]), dir));
});

test("an unreadable or truncated private key fails fast", () => {
  const key = generateEd25519();
  const truncated = key.private.slice(0, Math.floor(key.private.length / 2));
  assert.throws(() => validateConfig(baseConfig([keyHost({ privateKey: truncated, passphrase: false })]), dir), /readable private key/);
  assert.throws(() => validateConfig(baseConfig([keyHost({ privateKey: "not a key", passphrase: false })]), dir), /readable private key/);
  assert.throws(() => validateConfig(baseConfig([keyHost({ privateKey: { file: path.join(dir, "missing.pem") }, passphrase: false })]), dir), /cannot read/);
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("the rate limiter allows the limit, then refuses until the window ends", async () => {
  const limiter = new RateLimiter(3, 80);
  assert.deepEqual([1, 2, 3, 4, 5].map(() => limiter.hit("k")), [true, true, true, false, false]);
  assert.equal(limiter.hit("other"), true);
  await sleep(120);
  assert.equal(limiter.hit("k"), true);
});

test("the rate limiter never holds more than its maximum number of keys", () => {
  const limiter = new RateLimiter(5, 60_000, 50);
  for (let i = 0; i < 500; i++) limiter.hit(`ip-${i}`);
  assert.ok(limiter.size <= 50, `size ${limiter.size}`);
  assert.equal(limiter.size, 50);
});

test("the rate limiter evicts expired keys before live ones, then the oldest", async () => {
  const limiter = new RateLimiter(1, 100, 3);
  limiter.hit("old-a");
  limiter.hit("old-b");
  await sleep(140);
  limiter.hit("live-1");
  limiter.hit("live-2");
  limiter.hit("live-3");
  assert.equal(limiter.size, 3);
  assert.equal(limiter.hit("live-1"), false, "a live key must keep its count when expired ones can be evicted");
  assert.equal(limiter.hit("live-2"), false);
  limiter.hit("live-4");
  assert.equal(limiter.size, 3);
  assert.equal(limiter.hit("live-1"), true, "the oldest live key is the one evicted");
  assert.equal(limiter.hit("live-3"), false);
});

test("a blocked key stays blocked while other keys churn", () => {
  const limiter = new RateLimiter(1, 60_000, 20);
  limiter.hit("victim");
  assert.equal(limiter.hit("victim"), false);
  for (let i = 0; i < 10; i++) limiter.hit(`noise-${i}`);
  assert.equal(limiter.hit("victim"), false);
});

test("validateSetupConfig validates correct and incorrect configurations", () => {
  const valid = {
    server: { port: 8080, host: "0.0.0.0", publicUrl: "http://localhost:8080", trustProxy: false },
    github: { clientId: "id", clientSecret: { env: "SEC" } },
    users: [{ github: "user1", totpSecret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" }],
    hosts: [{ id: "srv", name: "srv", host: "127.0.0.1", port: 22, username: "admin", auth: { type: "password", password: "pwd" } }],
    security: { allowUnpinnedHostKeys: true },
  };
  assert.equal(validateSetupConfig(valid).valid, true);

  const invalid = {
    server: { port: 99999, host: "", publicUrl: "bad-url" },
    github: {},
    users: [{ github: "bad user name!", totpSecret: "short" }],
    hosts: [
      { id: "h1", host: "127.0.0.1", username: "u", auth: { type: "invalid" } },
      { id: "h1", host: "127.0.0.1", username: "u", auth: { type: "password" } },
    ],
  };
  const res = validateSetupConfig(invalid);
  assert.equal(res.valid, false);
  assert.ok(res.errors.length >= 6);
});

test("createSetupApp endpoints operate as expected", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sp-setup-test-"));
  const cfgPath = path.join(tmpDir, "config.json");
  const publicDir = path.resolve("dist/public");

  let savedTriggered = false;
  const { server, shutdown } = createSetupApp({
    configPath: cfgPath,
    publicDir,
    onSaved: () => {
      savedTriggered = true;
    },
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as any;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    const health = await fetch(`${baseUrl}/healthz`);
    assert.equal(health.status, 200);
    const healthBody = await health.json();
    assert.deepEqual(healthBody, { ok: true, setup: true });

    const status = await fetch(`${baseUrl}/api/setup/status`);
    assert.equal(status.status, 200);
    const statusBody = await status.json();
    assert.equal(statusBody.exists, false);
    assert.equal(statusBody.writable, true);

    const totpRes = await fetch(`${baseUrl}/api/setup/totp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account: "tester" }),
    });
    assert.equal(totpRes.status, 200);
    const totpBody = await totpRes.json();
    assert.ok(typeof totpBody.secret === "string" && totpBody.secret.length >= 26);
    assert.ok(typeof totpBody.qr === "string" && totpBody.qr.startsWith("data:image/png;base64,"));

    const valRes = await fetch(`${baseUrl}/api/setup/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server: { port: 8080 } }),
    });
    assert.equal(valRes.status, 200);
    const valBody = await valRes.json();
    assert.equal(valBody.valid, false);

    const validPayload = {
      server: { port: 8080, host: "0.0.0.0", publicUrl: "http://localhost:8080", trustProxy: false },
      github: { clientId: "test-id", clientSecret: "test-sec" },
      users: [{ github: "testuser", totpSecret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" }],
      hosts: [{ id: "srv", name: "srv", host: "127.0.0.1", port: 22, username: "admin", auth: { type: "password", password: "pwd" } }],
      security: { allowUnpinnedHostKeys: true },
    };

    const saveRes = await fetch(`${baseUrl}/api/setup/save`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validPayload),
    });
    assert.equal(saveRes.status, 200);
    const saveBody = await saveRes.json();
    assert.equal(saveBody.ok, true);
    assert.equal(saveBody.saved, true);
    assert.equal(fs.existsSync(cfgPath), true);

    await new Promise((r) => setTimeout(r, 600));
    assert.equal(savedTriggered, true);
  } finally {
    await shutdown(1000);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

