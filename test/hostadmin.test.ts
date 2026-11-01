import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { loadConfig, loadSealedConfig, promoteFirstAdmin, type LoadedConfig } from "../src/server/config.js";
import crypto from "node:crypto";
import ssh2 from "ssh2";
import { addHost, fileStore, listKeys, probeHostKey, vaultStore, HostAdminError } from "../src/server/hostadmin.js";
import { openVault, openVaultKeyed, sealVaultKeyed, type ScryptParams } from "../src/server/vault.js";
import { createApp } from "../src/server/app.js";
import { base32Encode, hotp } from "../src/server/totp.js";
import { generateEd25519 } from "./keys.js";

const FAST: ScryptParams = { N: 1 << 10, r: 8, p: 1 };
const PASS = "correct horse battery";
const FP = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const TOTP_KEY = Buffer.alloc(20, 9);
const locked = generateEd25519("hunter2 hunter2");
const bare = generateEd25519();
const probe = async () => FP;

function rawConfig(extra: Record<string, unknown> = {}, privateKey: unknown = locked.private) {
  return {
    server: { port: 8080, publicUrl: "http://127.0.0.1:1" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [
      { github: "admin", totpSecret: base32Encode(TOTP_KEY), admin: true },
      { github: "member", totpSecret: base32Encode(TOTP_KEY) },
    ],
    hosts: [{ id: "first", name: "first", host: "10.0.0.1", username: "deploy", auth: { type: "key", privateKey, keyName: "deploy_ed25519" }, hostKeyFingerprints: [FP] }],
    ...extra,
  };
}

function plainSetup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-hostadmin-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(file, JSON.stringify(rawConfig(), null, 2));
  return { dir, file, cfg: loadConfig(file) };
}

const base = { name: "web 03", group: "Production", host: "10.0.1.14", port: 22, username: "deploy", allowNoPassphrase: false };

async function rejects(p: Promise<unknown>, status: number, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof HostAdminError && e.status === status && e.code === code, `expected ${status} ${code}`);
}

test("users can be flagged admin and the flag is validated", () => {
  const { cfg } = plainSetup();
  assert.deepEqual(cfg.users.map((u) => u.admin), [true, false]);
  assert.throws(() => loadSealedConfig(JSON.stringify(rawConfig({ users: [{ github: "a", totpSecret: base32Encode(TOTP_KEY), admin: "yes" }] }))), /admin must be true or false/);
});

test("a sealed config with no admin treats the first user as admin, and one with an admin is left alone", () => {
  const none = loadSealedConfig(JSON.stringify(rawConfig({ users: [{ github: "a", totpSecret: base32Encode(TOTP_KEY) }, { github: "b", totpSecret: base32Encode(TOTP_KEY) }] })));
  assert.equal(promoteFirstAdmin(none), "a");
  assert.deepEqual(none.users.map((u) => u.admin), [true, false]);
  const some = loadSealedConfig(JSON.stringify(rawConfig({ users: [{ github: "a", totpSecret: base32Encode(TOTP_KEY) }, { github: "b", totpSecret: base32Encode(TOTP_KEY), admin: true }] })));
  assert.equal(promoteFirstAdmin(some), undefined);
  assert.deepEqual(some.users.map((u) => u.admin), [false, true]);
});

test("adding a host with an uploaded key writes the key file and pins the host key", async () => {
  const { dir, file, cfg } = plainSetup();
  const host = await addHost(cfg, fileStore(file), { ...base, key: { upload: { name: "web_ed25519", pem: locked.private } } }, probe);
  assert.equal(host.id, "web-03");
  assert.deepEqual(host.hostKeyFingerprints, [FP]);
  assert.equal(cfg.hosts.length, 2);
  const keyFile = path.join(dir, "keys", "web-03.key");
  assert.equal(fs.readFileSync(keyFile, "utf8").trim(), locked.private.trim());
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
  const saved = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(saved.hosts.length, 2);
  assert.deepEqual(saved.hosts[1].auth.privateKey, { file: "keys/web-03.key" });
  assert.equal(saved.hosts[1].auth.keyName, "web_ed25519");
  assert.ok(!JSON.stringify(saved.hosts[1]).includes("PRIVATE KEY"));
  assert.doesNotThrow(() => loadConfig(file));
});

test("a key without a passphrase needs an explicit confirmation and is stored as passphrase: false", async () => {
  const { file, cfg } = plainSetup();
  const input = { ...base, key: { upload: { name: "bare", pem: bare.private } } };
  await rejects(addHost(cfg, fileStore(file), input, probe), 400, "needs_confirmation");
  assert.equal(cfg.hosts.length, 1);
  const host = await addHost(cfg, fileStore(file), { ...input, allowNoPassphrase: true }, probe);
  assert.equal((host.auth as { passphrase?: unknown }).passphrase, false);
  assert.doesNotThrow(() => loadConfig(file));
});

test("an existing key can be reused and shows up once in the key list", async () => {
  const { file, cfg } = plainSetup();
  const [key] = listKeys(cfg);
  assert.equal(key.name, "deploy_ed25519");
  assert.equal(key.encrypted, true);
  assert.equal(key.hosts, 1);
  const host = await addHost(cfg, fileStore(file), { ...base, key: { existing: key.id } }, probe);
  assert.equal((host.auth as { keyName?: string }).keyName, "deploy_ed25519");
  const after = listKeys(cfg);
  assert.equal(after.length, 1);
  assert.equal(after[0].hosts, 2);
  await rejects(addHost(cfg, fileStore(file), { ...base, name: "other", key: { existing: "key-nope" } }, probe), 400, "unknown_key");
});

test("bad input, duplicates and unreachable hosts are refused without changing anything", async () => {
  const { file, cfg } = plainSetup();
  const store = fileStore(file);
  const good = { ...base, key: { upload: { name: "k", pem: locked.private } } };
  await rejects(addHost(cfg, store, { ...good, name: "" }, probe), 400, "invalid");
  await rejects(addHost(cfg, store, { ...good, host: "bad host;rm" }, probe), 400, "invalid");
  await rejects(addHost(cfg, store, { ...good, username: "-oProxyCommand=x" }, probe), 400, "invalid");
  await rejects(addHost(cfg, store, { ...good, port: 70000 }, probe), 400, "invalid");
  await rejects(addHost(cfg, store, { ...good, key: { upload: { name: "k", pem: "not a key" } } }, probe), 400, "invalid_key");
  await rejects(addHost(cfg, store, { ...good, name: "FIRST" }, probe), 409, "duplicate");
  await rejects(addHost(cfg, store, good, async () => { throw Object.assign(new Error("x"), { code: "ECONNREFUSED" }); }), 422, "unreachable");
  assert.equal(cfg.hosts.length, 1);
  assert.equal(JSON.parse(fs.readFileSync(file, "utf8")).hosts.length, 1);
  assert.equal(fs.existsSync(path.join(path.dirname(file), "keys")), false);
});

test("a read-only config reports a storage error and leaves no key file behind", async () => {
  const { dir, file, cfg } = plainSetup();
  fs.chmodSync(file, 0o444);
  fs.mkdirSync(path.join(dir, "keys"), { mode: 0o700 });
  fs.rmSync(path.join(dir, "keys"), { recursive: true });
  fs.writeFileSync(path.join(dir, "keys"), "in the way");
  await rejects(addHost(cfg, fileStore(file), { ...base, key: { upload: { name: "k", pem: locked.private } } }, probe), 500, "storage_failed");
  assert.equal(cfg.hosts.length, 1);
});

test("the vault store re-encrypts the vault with the held key and keeps the key inline", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-hostadmin-vault-"));
  const vault = path.join(dir, "vault.sealed");
  const json = JSON.stringify(rawConfig({}, locked.private));
  const { file, dek } = sealVaultKeyed(json, PASS, FAST);
  fs.writeFileSync(vault, file);
  const cfg: LoadedConfig = loadSealedConfig(openVault(file, PASS));
  const host = await addHost(cfg, vaultStore(vault, dek), { ...base, key: { upload: { name: "up", pem: bare.private } }, allowNoPassphrase: true }, probe);
  assert.equal(cfg.hosts.length, 2);
  assert.equal(host.id, "web-03");
  assert.ok(!fs.readFileSync(vault, "utf8").includes("PRIVATE KEY"));
  const reopened = openVaultKeyed(fs.readFileSync(vault), PASS);
  const stored = JSON.parse(reopened.plain.toString("utf8"));
  assert.equal(stored.hosts.length, 2);
  assert.equal(stored.hosts[1].auth.privateKey.trim(), bare.private.trim());
  assert.deepEqual(reopened.dek, dek);
  assert.doesNotThrow(() => loadSealedConfig(reopened.plain));
});

test("the vault store refuses to write with a key that does not match the vault", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-hostadmin-vault-"));
  const vault = path.join(dir, "vault.sealed");
  const { file } = sealVaultKeyed(JSON.stringify(rawConfig({}, locked.private)), PASS, FAST);
  fs.writeFileSync(vault, file);
  const cfg = loadSealedConfig(openVault(file, PASS));
  await rejects(addHost(cfg, vaultStore(vault, Buffer.alloc(32, 1)), { ...base, key: { existing: listKeys(cfg)[0].id } }, probe), 500, "storage_failed");
  assert.equal(cfg.hosts.length, 1);
  assert.equal(fs.readFileSync(vault, "utf8"), file);
});

test("only admins can list keys or add hosts over the API", async () => {
  const { file, cfg } = plainSetup();
  const clock = Date.now();
  const app = createApp(cfg, {
    publicDir: path.resolve("dist/public"),
    now: () => clock,
    hostStore: fileStore(file),
    probeHostKey: probe,
    exchange: async () => ({ id: who === "admin" ? 1 : 2, login: who, name: who }),
  });
  let who = "admin";
  await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  (cfg.server as { publicUrl: string }).publicUrl = origin;
  const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  try {
    const login = async (user: string) => {
      who = user;
      const start = await fetch(`${origin}/auth/github`, { redirect: "manual" });
      const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
      const cb = await fetch(`${origin}/auth/github/callback?code=x&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
      const pending = cb.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
      const ok = await fetch(`${origin}/auth/totp`, {
        method: "POST",
        headers: { cookie: pending, origin, "content-type": "application/json" },
        body: JSON.stringify({ code: hotp(TOTP_KEY, Math.floor(clock / 30_000)) }),
      });
      assert.equal(ok.status, 204);
      return ok.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
    };
    const body = JSON.stringify({ ...base, key: { existing: listKeys(cfg)[0].id } });
    const post = (cookie: string, o = origin) => fetch(`${origin}/api/hosts`, { method: "POST", headers: { cookie, origin: o, "content-type": "application/json" }, body });

    const member = await login("member");
    assert.equal((await (await fetch(`${origin}/api/me`, { headers: { cookie: member } })).json() as { admin: boolean }).admin, false);
    assert.equal((await fetch(`${origin}/api/keys`, { headers: { cookie: member } })).status, 403);
    assert.equal((await post(member)).status, 403);
    assert.equal(cfg.hosts.length, 1);

    const admin = await login("admin");
    const me = await (await fetch(`${origin}/api/me`, { headers: { cookie: admin } })).json() as { admin: boolean; canAddHosts: boolean };
    assert.deepEqual([me.admin, me.canAddHosts], [true, true]);
    const keys = await (await fetch(`${origin}/api/keys`, { headers: { cookie: admin } })).json() as Array<{ name: string }>;
    assert.equal(keys[0].name, "deploy_ed25519");
    assert.equal((await fetch(`${origin}/api/keys`)).status, 401);
    assert.equal((await post(admin, "http://evil.example")).status, 403);
    assert.equal((await fetch(`${origin}/api/hosts`, { method: "POST", headers: { origin, "content-type": "application/json" }, body })).status, 401);

    const added = await post(admin);
    assert.equal(added.status, 201);
    assert.equal((await post(admin)).status, 409);
    const list = await (await fetch(`${origin}/api/hosts`, { headers: { cookie: member } })).json() as Array<{ id: string; group: string; addr: string }>;
    assert.deepEqual(list.map((h) => h.id), ["first", "web-03"]);
    assert.equal(list[1].group, "Production");
    assert.equal(list[1].addr, "deploy@10.0.1.14");
  } finally {
    await app.shutdown(200, "test");
  }
});

test("without a store the API says hosts cannot be added", async () => {
  const { cfg } = plainSetup();
  const app = createApp(cfg, { publicDir: path.resolve("dist/public") });
  await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  (cfg.server as { publicUrl: string }).publicUrl = origin;
  const s = app.sessions.create({ githubId: 1, login: "admin", name: "admin" }, "full");
  try {
    const me = await (await fetch(`${origin}/api/me`, { headers: { cookie: `sp_sid=${s.id}` } })).json() as { canAddHosts: boolean };
    assert.equal(me.canAddHosts, false);
    const r = await fetch(`${origin}/api/hosts`, { method: "POST", headers: { cookie: `sp_sid=${s.id}`, origin, "content-type": "application/json" }, body: "{}" });
    assert.equal(r.status, 409);
  } finally {
    await app.shutdown(200, "test");
  }
});

test("probeHostKey reads the SHA256 fingerprint of the host key without logging in", async () => {
  const hostKey = generateEd25519();
  const pub = ssh2.utils.parseKey(hostKey.private) as any;
  let authAttempts = 0;
  const sshd = new ssh2.Server({ hostKeys: [hostKey.private] }, (c) => {
    c.on("authentication", (ctx) => { authAttempts++; ctx.reject(); });
    c.on("error", () => {});
  });
  await new Promise<void>((r) => sshd.listen(0, "127.0.0.1", () => r()));
  const port = (sshd.address() as AddressInfo).port;
  try {
    const expected = "SHA256:" + crypto.createHash("sha256").update(pub.getPublicSSH()).digest("base64").replace(/=+$/, "");
    assert.equal(await probeHostKey("127.0.0.1", port), expected);
    assert.equal(authAttempts, 0);
  } finally {
    sshd.close();
  }
  await assert.rejects(probeHostKey("127.0.0.1", port, 1500));
});
