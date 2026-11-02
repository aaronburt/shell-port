import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { loadConfig } from "../src/server/config.js";
import { createApp } from "../src/server/app.js";
import { fileStore } from "../src/server/hostadmin.js";
import { AuditLog, auditCsv, fileSink, type AuditEntry } from "../src/server/auditlog.js";
import { base32Encode, hotp } from "../src/server/totp.js";
import { generateEd25519 } from "./keys.js";

const DAY = 86_400_000;
const TOTP_KEY = Buffer.alloc(20, 9);
const FP = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const locked = generateEd25519("hunter2 hunter2");

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "shellport-audit-"));
}

const entry = (over: Partial<AuditEntry> = {}): AuditEntry => ({ id: "a1", at: Date.now(), kind: "signin", user: "aaron", ip: "203.0.113.7", host: "", detail: "GitHub + authenticator code", ...over });

test("the plain sink appends, reloads, rewrites and counts unreadable lines", () => {
  const file = path.join(tmp(), "audit.log");
  const sink = fileSink(file);
  sink.append(entry({ id: "a1" }));
  sink.append(entry({ id: "a2", kind: "ssh_connect", host: "prod-web-01" }));
  fs.appendFileSync(file, "not json\n{\"id\":1}\n");
  const loaded = sink.load();
  assert.deepEqual(loaded.entries.map((e) => e.id), ["a1", "a2"]);
  assert.equal(loaded.unreadable, 2);
  sink.rewrite(loaded.entries.slice(1));
  assert.deepEqual(sink.load().entries.map((e) => e.id), ["a2"]);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fileSink(path.join(tmp(), "missing.log")).load(), { entries: [], unreadable: 0 });
});

test("the sealed sink encrypts every line and rejects other keys and injected plaintext", () => {
  const file = path.join(tmp(), "audit.log");
  const dek = Buffer.alloc(32, 7);
  const sink = fileSink(file, dek);
  sink.append(entry({ id: "s1", host: "secret-host-name", detail: "As deploy" }));
  const raw = fs.readFileSync(file, "utf8");
  assert.ok(!raw.includes("secret-host-name"));
  assert.ok(!raw.includes("aaron"));
  assert.deepEqual(fileSink(file, dek).load().entries.map((e) => e.id), ["s1"]);
  const other = fileSink(file, Buffer.alloc(32, 8)).load();
  assert.deepEqual([other.entries.length, other.unreadable], [0, 1]);
  const plain = fileSink(file).load();
  assert.deepEqual([plain.entries.length, plain.unreadable], [0, 1]);
  fs.appendFileSync(file, JSON.stringify(entry({ id: "forged" })) + "\n");
  const again = fileSink(file, dek).load();
  assert.deepEqual(again.entries.map((e) => e.id), ["s1"]);
  assert.equal(again.unreadable, 1);
  sink.close();
});

test("retention drops old entries from memory and from the file, and filters work", () => {
  const file = path.join(tmp(), "audit.log");
  const now = Date.now();
  const sink = fileSink(file);
  sink.append(entry({ id: "old", at: now - 100 * DAY }));
  sink.append(entry({ id: "keep1", at: now - 5 * DAY, user: "mira", kind: "ssh_connect", host: "db" }));
  sink.append(entry({ id: "keep2", at: now - DAY, user: "aaron", kind: "totp_failed" }));
  const log = new AuditLog({ sink, retentionDays: 90, now: () => now });
  assert.deepEqual(sink.load().entries.map((e) => e.id), ["keep1", "keep2"]);
  assert.deepEqual(log.query({}).items.map((e) => e.id), ["keep2", "keep1"]);
  assert.deepEqual(log.query({ user: "mira" }).items.map((e) => e.id), ["keep1"]);
  assert.deepEqual(log.query({ host: "db" }).items.map((e) => e.id), ["keep1"]);
  assert.deepEqual(log.query({ type: "fail" }).items.map((e) => e.id), ["keep2"]);
  assert.deepEqual(log.query({ type: "SSH connections" }).items.map((e) => e.id), ["keep1"]);
  assert.deepEqual(log.query({ from: now - 2 * DAY }).items.map((e) => e.id), ["keep2"]);
  assert.equal(log.query({ limit: 1, offset: 1 }).items[0].id, "keep1");
  assert.equal(log.query({ limit: 1 }).total, 2);
  assert.deepEqual(log.choices(), { users: ["aaron", "mira"], hosts: ["db"] });
  assert.equal(log.status().stored, true);
  log.stop();
});

test("a sink that cannot write leaves the log in memory and reports it once", () => {
  const errors: string[] = [];
  const dir = tmp();
  const log = new AuditLog({ sink: fileSink(path.join(dir, "missing-folder", "audit.log")), onError: (m) => errors.push(m) });
  log.add({ kind: "signin", user: "a", ip: "1.1.1.1" });
  log.add({ kind: "signin", user: "b", ip: "1.1.1.1" });
  assert.equal(errors.length, 1);
  assert.equal(log.query({}).total, 2);
  assert.equal(log.status().stored, false);
  assert.ok(log.status().error);
  log.stop();
});

test("CSV export quotes cells and neutralises spreadsheet formulas", () => {
  const csv = auditCsv([entry({ user: "=cmd|' /C calc'!A0", detail: 'He said "hi", twice', host: "+host" })]);
  const lines = csv.trim().split("\r\n");
  assert.equal(lines[0], '"time","user","event","host","from","details"');
  assert.ok(lines[1].includes(`"'=cmd|' /C calc'!A0"`));
  assert.ok(lines[1].includes(`"'+host"`));
  assert.ok(lines[1].includes('"He said ""hi"", twice"'));
});

test("the API records sign-ins and host changes and only admins can read it", async () => {
  const dir = tmp();
  const file = path.join(dir, "config.json");
  fs.writeFileSync(file, JSON.stringify({
    server: { port: 8080, publicUrl: "http://127.0.0.1:1" },
    github: { clientId: "id", clientSecret: "secret" },
    users: [
      { github: "admin", totpSecret: base32Encode(TOTP_KEY), admin: true },
      { github: "member", totpSecret: base32Encode(TOTP_KEY) },
    ],
    hosts: [{ id: "first", name: "first", host: "10.0.0.1", username: "deploy", auth: { type: "key", privateKey: locked.private, keyName: "deploy_ed25519" }, hostKeyFingerprints: [FP] }],
  }));
  const cfg = loadConfig(file);
  const clock = Date.now();
  let who = "admin";
  const auditLog = new AuditLog({ sink: fileSink(path.join(dir, "audit.log")) });
  const app = createApp(cfg, {
    publicDir: path.resolve("dist/public"),
    now: () => clock,
    auditLog,
    hostStore: fileStore(file),
    probeHostKey: async () => FP,
    exchange: async () => ({ id: who === "admin" ? 1 : who === "member" ? 2 : 3, login: who, name: who }),
  });
  await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  (cfg.server as { publicUrl: string }).publicUrl = origin;
  const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const github = async (user: string) => {
    who = user;
    const start = await fetch(`${origin}/auth/github`, { redirect: "manual" });
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    return fetch(`${origin}/auth/github/callback?code=x&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  };
  const login = async (user: string, code = hotp(TOTP_KEY, Math.floor(clock / 30_000))) => {
    const cb = await github(user);
    const pending = cb.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
    const ok = await fetch(`${origin}/auth/totp`, { method: "POST", headers: { cookie: pending, origin, "content-type": "application/json" }, body: JSON.stringify({ code }) });
    return ok.status === 204 ? ok.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0] : undefined;
  };
  try {
    assert.equal((await fetch(`${origin}/api/audit`)).status, 401);
    assert.equal((await github("stranger")).headers.get("location"), "/?error=denied");
    assert.equal(await login("member", "000000"), undefined);
    const member = (await login("member"))!;
    assert.equal((await fetch(`${origin}/api/audit`, { headers: { cookie: member } })).status, 403);
    assert.equal((await fetch(`${origin}/api/audit/export`, { headers: { cookie: member } })).status, 403);

    const admin = (await login("admin"))!;
    const res = await fetch(`${origin}/api/hosts`, {
      method: "POST",
      headers: { cookie: admin, origin, "content-type": "application/json" },
      body: JSON.stringify({ name: "web 03", group: "Production", host: "10.0.1.14", port: 22, username: "deploy", key: { upload: { name: "ci-key", pem: locked.private } } }),
    });
    assert.equal(res.status, 201);

    const all = await (await fetch(`${origin}/api/audit?limit=100`, { headers: { cookie: admin } })).json() as {
      items: AuditEntry[]; total: number; users: string[]; hosts: string[]; groups: string[]; status: { stored: boolean; file: string; encrypted: boolean; retentionDays: number };
    };
    const kinds = all.items.map((e) => e.kind);
    for (const k of ["signin_denied", "totp_failed", "signin", "host_added", "key_uploaded"]) assert.ok(kinds.includes(k as never), `missing ${k}`);
    assert.equal(all.items[0].kind, "key_uploaded");
    const added = all.items.find((e) => e.kind === "host_added")!;
    assert.deepEqual([added.user, added.host, added.detail], ["admin", "web 03", "deploy@10.0.1.14"]);
    assert.equal(all.items.find((e) => e.kind === "key_uploaded")!.detail, "ci-key");
    assert.equal(all.items.find((e) => e.kind === "signin_denied")!.user, "stranger");
    assert.ok(all.hosts.includes("web 03"));
    assert.deepEqual([all.status.stored, all.status.file, all.status.encrypted, all.status.retentionDays], [true, "audit.log", false, 90]);
    assert.ok(!JSON.stringify(all).includes("PRIVATE KEY"));
    assert.ok(!fs.readFileSync(path.join(dir, "audit.log"), "utf8").includes("PRIVATE KEY"));

    const fails = await (await fetch(`${origin}/api/audit?type=fail`, { headers: { cookie: admin } })).json() as { items: AuditEntry[] };
    assert.deepEqual([...new Set(fails.items.map((e) => e.kind))].sort(), ["signin_denied", "totp_failed"]);
    const mine = await (await fetch(`${origin}/api/audit?user=member&days=1`, { headers: { cookie: admin } })).json() as { items: AuditEntry[] };
    assert.ok(mine.items.length >= 2 && mine.items.every((e) => e.user === "member"));

    const csv = await fetch(`${origin}/api/audit/export?type=Host%20changes`, { headers: { cookie: admin } });
    assert.equal(csv.status, 200);
    assert.match(csv.headers.get("content-type")!, /text\/csv/);
    assert.match(csv.headers.get("content-disposition")!, /attachment/);
    const text = await csv.text();
    assert.ok(text.startsWith('"time","user","event","host","from","details"'));
    assert.ok(text.includes('"Host added"') && !text.includes('"Signed in"'));
    assert.equal((await fetch(`${origin}/api/audit/export`, { headers: { cookie: admin, "sec-fetch-site": "cross-site" } })).status, 403);
  } finally {
    auditLog.stop();
    await app.shutdown(200, "test");
  }
});
