import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { useApp, base, targets, SECRET_PASSWORD, code, advanceClock, githubStep, postCode, signIn, getJson, connect, wsStatus } from "./app-fixture.js";

useApp();

test("the signed-out instance serves only the sign-in page", async () => {
  const r = await fetch(base + "/");
  const html = await r.text();
  assert.match(html, /Sign in to Shellport/);
  assert.doesNotMatch(html, /\/assets\/app-/);
  for (const p of ["/api/me", "/api/hosts", "/api/signins"]) assert.equal((await fetch(base + p)).status, 401, p);
});

test("GitHub step alone leaves a pending session that only sees the TOTP page", async () => {
  const pending = await githubStep("smoke-user");
  const page = await (await fetch(base + "/", { headers: { cookie: pending } })).text();
  assert.match(page, /Two-factor authentication/);
  assert.doesNotMatch(page, /\/assets\/app-/);
  for (const p of ["/api/me", "/api/hosts", "/api/signins"]) assert.equal((await fetch(base + p, { headers: { cookie: pending } })).status, 401, p);
  assert.equal(await wsStatus(pending, "plain", base), 401);
});

test("a wrong TOTP code is refused and counted down", async () => {
  const pending = await githubStep("smoke-user");
  advanceClock();
  const wrong = code() === "123456" ? "654321" : "123456";
  const r = await postCode(pending, wrong);
  assert.equal(r.status, 400);
  const body: any = await r.json();
  assert.equal(body.error, "invalid_code");
  assert.equal(body.remaining, 4);
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: pending } })).status, 401);
});

test("a correct TOTP code signs in and the session id rotates", async () => {
  const pending = await githubStep("smoke-user");
  advanceClock();
  const r = await postCode(pending, code());
  assert.equal(r.status, 204);
  const full = r.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!;
  assert.match(full, /HttpOnly/i);
  assert.match(full, /SameSite=Lax/i);
  assert.notEqual(full.split(";")[0], pending, "the pending session id must not survive the second factor");
  assert.equal((await fetch(base + "/api/me", { headers: { cookie: pending } })).status, 401, "the pending cookie must stop working");
  assert.equal((await getJson(full.split(";")[0], "/api/me")).status, 200);
});

test("a TOTP code cannot be replayed", async () => {
  const first = await githubStep("smoke-user");
  advanceClock();
  const used = code();
  assert.equal((await postCode(first, used)).status, 204);
  const second = await githubStep("smoke-user");
  const replay = await postCode(second, used);
  assert.equal(replay.status, 400);
  assert.equal(((await replay.json()) as any).error, "invalid_code");
  advanceClock();
  assert.equal((await postCode(second, code())).status, 204);
});

test("five wrong TOTP codes destroy the pending login", async () => {
  const pending = await githubStep("lockout-user");
  advanceClock();
  const wrong = code() === "111111" ? "222222" : "111111";
  let last: Response | undefined;
  for (let i = 0; i < 5; i++) last = await postCode(pending, wrong);
  assert.equal(last!.status, 401);
  assert.equal(((await last!.json()) as any).error, "too_many_attempts");
  const after = await postCode(pending, code());
  assert.equal(after.status, 401);
  assert.equal(((await after.json()) as any).error, "no_pending_login");
});

test("the host list shows only permitted hosts and never a secret", async () => {
  const cookie = await signIn("smoke-user");
  const { status, body } = await getJson(cookie, "/api/hosts");
  assert.equal(status, 200);
  assert.deepEqual(body.map((h: any) => h.id).sort(), ["locked", "mismatch", "nofiles", "plain"]);
  for (const h of body) assert.deepEqual(Object.keys(h).sort(), ["addr", "group", "id", "name", "tag", "via"]);
  const text = JSON.stringify(body);
  assert.doesNotMatch(text, /SHA256:|PRIVATE KEY|OPENSSH|never-send|password|privateKey/i);
  assert.ok(!text.includes(targets.plain.fingerprint.slice(7, 20)), "the host list must not carry the host key fingerprint");
  const other = await getJson(await signIn("other-user"), "/api/hosts");
  assert.ok(other.body.some((h: any) => h.id === "restricted"), "the allowed user should see the restricted host");
  assert.ok(!JSON.stringify(other.body).includes(SECRET_PASSWORD));
});

test("sign-ins lists sessions and failures, and signing out others ends them and their terminals", async () => {
  const first = await signIn("session-user");
  const bad = await githubStep("session-user");
  advanceClock();
  await postCode(bad, code() === "999999" ? "888888" : "999999");
  const second = await signIn("session-user");
  const secondTerm = await connect(second, "plain");

  const list = await getJson(first, "/api/signins");
  assert.equal(list.status, 200);
  const kinds = list.body.items.map((i: any) => i.kind);
  assert.ok(kinds.includes("signin") && kinds.includes("totp_failed"));
  assert.equal(list.body.others, 1);
  const current = list.body.items.filter((i: any) => i.kind === "signin" && i.current);
  assert.equal(current.length, 1);
  assert.ok(list.body.items.some((i: any) => i.kind === "signin" && i.active && !i.current));

  const cross = await fetch(`${base}/api/signins/signout-others`, { method: "POST", headers: { cookie: first, origin: "https://evil.example" } });
  assert.equal(cross.status, 403);
  const r = await fetch(`${base}/api/signins/signout-others`, { method: "POST", headers: { cookie: first, origin: base } });
  assert.equal(r.status, 200);
  assert.equal(((await r.json()) as any).ended, 1);

  await secondTerm.waitFor("second session's terminal closed", () => secondTerm.closed());
  assert.match(secondTerm.closed().reason, /Signed out/);
  assert.equal((await getJson(second, "/api/me")).status, 401);
  assert.equal((await getJson(first, "/api/me")).status, 200);
  const after = await getJson(first, "/api/signins");
  assert.equal(after.body.others, 0);
});

test("one user cannot see another user's sign-in activity", async () => {
  const mine = await getJson(await signIn("smoke-user"), "/api/signins");
  const theirs = await getJson(await signIn("other-user"), "/api/signins");
  const ids = new Set(mine.body.items.map((i: any) => i.id));
  assert.ok(!theirs.body.items.some((i: any) => ids.has(i.id)));
});

test("signing out closes the session's terminals and kills the session", async () => {
  const cookie = await signIn("logout-user");
  const t = await connect(cookie, "plain");
  const cross = await fetch(`${base}/auth/logout`, { method: "POST", headers: { cookie, origin: "https://evil.example" } });
  assert.equal(cross.status, 403);
  assert.equal((await getJson(cookie, "/api/me")).status, 200);
  const out = await fetch(`${base}/auth/logout`, { method: "POST", headers: { cookie, origin: base } });
  assert.equal(out.status, 204);
  await t.waitFor("terminal closed", () => t.closed());
  assert.match(t.closed().reason, /Signed out/);
  assert.equal((await getJson(cookie, "/api/me")).status, 401);
  assert.equal(await wsStatus(cookie, "plain", base), 401);
});

test("the black-box smoke script passes against this instance, rate limit included", async () => {
  const child = spawn(process.execPath, ["scripts/smoke.mjs", base, "--rate-limit"], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (d) => (output += d));
  child.stderr.on("data", (d) => (output += d));
  const code = await new Promise<number | null>((r) => child.on("close", r));
  assert.equal(code, 0, output.split("\n").filter((l) => /FAIL|failed|limited/.test(l)).join("\n") || output.slice(-1500));
  assert.match(output, /Rate limiting \(opt-in\)/);
  assert.match(output, /limited after \d+ requests/);
});
