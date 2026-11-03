import { test } from "node:test";
import assert from "node:assert/strict";
import { useApp, base, targets, timing, signIn, connect, openWs, settle, sftpFixture, remoteExec, wsStatus } from "./app-fixture.js";
import { sleep } from "./helpers.js";

useApp();

test("a real terminal runs commands and returns their output", async () => {
  const cookie = await signIn("smoke-user");
  const t = await connect(cookie, "plain");
  const info = t.json.find((m) => m.state === "connected").info;
  assert.equal(info.hostKey, "pinned");
  assert.match(info.auth, /server-managed key/);
  t.type("echo smoke-$((6*7)) && whoami\n");
  await t.waitFor("command output", () => /smoke-42/.test(t.out));
  await t.waitFor("whoami output", () => /\r?\ndemo\r?\n/.test(t.out));
  await settle(t);
});

test("resizing the terminal reaches the remote pty", async () => {
  const cookie = await signIn("smoke-user");
  const t = await connect(cookie, "plain", { cols: 90, rows: 25 });
  t.type("echo size:$(stty size)\n");
  await t.waitFor("initial size", () => /size:25 90/.test(t.out));
  t.send({ t: "resize", cols: 132, rows: 43 });
  await sleep(200);
  t.type("echo size:$(stty size)\n");
  await t.waitFor("resized", () => /size:43 132/.test(t.out));
  await settle(t);
});

test("several terminals on one session are independent", async () => {
  const cookie = await signIn("smoke-user");
  const a = await connect(cookie, "plain");
  const b = await connect(cookie, "plain");
  a.type("echo only-in-a\n");
  b.type("echo only-in-b\n");
  await a.waitFor("a output", () => /only-in-a/.test(a.out));
  await b.waitFor("b output", () => /only-in-b/.test(b.out));
  assert.ok(!/only-in-b/.test(a.out) && !/only-in-a/.test(b.out));
  await settle(a, b);
});

test("files: a real OpenSSH host lists, views, downloads and deletes through SFTP, and refuses unsafe paths", async () => {
  const cookie = await signIn("smoke-user");
  const t = await connect(cookie, "plain");
  const info = t.json.find((m) => m.state === "connected").info;
  assert.equal(info.files, true);
  await sftpFixture("api");
  const call = (route: string, query: Record<string, string> = {}, init: RequestInit = {}, c = cookie) =>
    fetch(`${base}/api/terminals/${info.id}/files${route}${Object.keys(query).length ? "?" + new URLSearchParams(query) : ""}`, { ...init, headers: { cookie: c, ...(init.headers as object) } });

  const home = await (await call("")).json();
  assert.equal(home.path, "/home/demo");
  const names = home.entries.map((e: any) => e.name);
  assert.ok(names.includes("fx-api"), `home lists the fixture folder: ${names}`);
  assert.equal(home.entries.find((e: any) => e.name === "fx-api").kind, "dir");

  const dir = "/home/demo/fx-api";
  const inside = await (await call("", { path: dir })).json();
  assert.deepEqual(inside.entries.map((e: any) => e.name).sort(), ["blob.bin", "gone.txt", "long.txt", "note.txt", "sub"]);

  const view = await (await call("/view", { path: `${dir}/note.txt` })).json();
  assert.equal(view.text, "hello-api\n");
  const long = await (await call("/view", { path: `${dir}/long.txt` })).json();
  assert.deepEqual([long.truncated, long.text.length, long.size], [true, 256 * 1024, 300000]);
  assert.equal((await (await call("/view", { path: `${dir}/blob.bin` })).json()).binary, true);

  const dl = await call("/download", { path: `${dir}/note.txt` });
  assert.equal(dl.status, 200);
  assert.match(dl.headers.get("content-disposition")!, /^attachment; filename="note\.txt"/);
  assert.equal(await dl.text(), "hello-api\n");

  for (const p of ["relative", "/home/demo/../../etc/passwd", "/tmp/a\u0000b"]) assert.equal((await call("/view", { path: p })).status, 400, p);
  assert.equal((await call("/view", { path: "/root/.profile" })).status, 403, "the SSH account's own permissions still apply");
  assert.equal((await call("", { path: "/no/such/dir" })).status, 404);

  const post = (p: string, headers: Record<string, string> = { origin: base }) =>
    call("/delete", {}, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ path: p }) });
  assert.equal((await post(`${dir}/gone.txt`, {})).status, 403);
  assert.equal((await post(`${dir}/gone.txt`, { origin: "https://evil.example" })).status, 403);
  assert.equal((await post(`${dir}/gone.txt`)).status, 200);
  assert.equal((await call("/view", { path: `${dir}/gone.txt` })).status, 404);
  assert.equal((await post(dir)).status, 409, "a folder with files in it is not deleted");
  assert.equal((await post(`${dir}/sub`)).status, 200);

  const other = await signIn("other-user");
  assert.equal((await call("", {}, {}, other)).status, 404, "another user cannot reach this terminal's files");
  assert.equal((await fetch(`${base}/api/terminals/${info.id}/files`)).status, 401);

  await remoteExec("rm -rf ~/fx-api");
  await settle(t);
});

test("files: a host with files turned off refuses SFTP even though the terminal works", async () => {
  const cookie = await signIn("smoke-user");
  const t = await connect(cookie, "nofiles");
  const info = t.json.find((m) => m.state === "connected").info;
  assert.equal(info.files, false);
  const r = await fetch(`${base}/api/terminals/${info.id}/files`, { headers: { cookie } });
  assert.equal(r.status, 403);
  t.type("echo still-works\n");
  await t.waitFor("terminal output", () => /still-works/.test(t.out));
  await settle(t);
});

test("the per-user terminal cap refuses the fourth terminal", async () => {
  const cookie = await signIn("cap-user");
  const open = [await connect(cookie, "plain"), await connect(cookie, "plain"), await connect(cookie, "plain")];
  assert.equal(await wsStatus(cookie, "plain", base), 429);
  await settle(...open);
  await sleep(300);
  const again = await connect(cookie, "plain");
  await settle(again);
});

test("a host key that does not match the pin is refused", async () => {
  const cookie = await signIn("smoke-user");
  const t = openWs(cookie, "mismatch");
  await t.waitFor("closed", () => t.closed(), 15_000);
  assert.match(t.json.find((m) => m.t === "error").message, /Host key did not match/);
  assert.ok(!t.json.some((m) => m.state === "connected"));
});

test("a host the user may not open is refused at the WebSocket", async () => {
  const cookie = await signIn("smoke-user");
  assert.equal(await wsStatus(cookie, "restricted", base), 404);
  assert.equal(await wsStatus(cookie, "plain", "https://evil.example"), 403);
  assert.equal(await wsStatus(undefined, "plain", base), 401);
});

test("a passphrase host prompts, counts wrong, empty and oversized tries, and closes after three", async () => {
  const cookie = await signIn("smoke-user");
  const t = openWs(cookie, "locked");
  const prompts = () => t.json.filter((m) => m.t === "passphrase");
  await t.waitFor("first prompt", () => prompts().length === 1);
  assert.equal(prompts()[0].retry, false);
  assert.equal(prompts()[0].remaining, 3);
  t.send({ t: "passphrase", value: "wrong" });
  await t.waitFor("second prompt", () => prompts().length === 2);
  assert.deepEqual([prompts()[1].retry, prompts()[1].remaining], [true, 2]);
  t.send({ t: "passphrase", value: "" });
  await t.waitFor("third prompt", () => prompts().length === 3);
  assert.equal(prompts()[2].remaining, 1);
  t.send({ t: "passphrase", value: "x".repeat(4000) });
  await t.waitFor("closed", () => t.closed());
  assert.match(t.json.find((m) => m.t === "error").message, /Incorrect passphrase/);
  assert.ok(!t.json.some((m) => m.state === "connected"));
});

test("a passphrase host connects with the right passphrase and never echoes it", async () => {
  const cookie = await signIn("smoke-user");
  const t = openWs(cookie, "locked");
  await t.waitFor("prompt", () => t.json.some((m) => m.t === "passphrase"));
  t.send({ t: "passphrase", value: "nope" });
  await t.waitFor("retry prompt", () => t.json.filter((m) => m.t === "passphrase").length === 2);
  t.send({ t: "passphrase", value: targets.locked.passphrase });
  await t.waitFor("connected", () => t.json.some((m) => m.state === "connected"), 20_000);
  assert.match(t.json.find((m) => m.state === "connected").info.auth, /passphrase entered in browser/);
  t.type("echo locked-$((5*5))\n");
  await t.waitFor("output", () => /locked-25/.test(t.out));
  assert.doesNotMatch(JSON.stringify(t.json) + t.out, new RegExp(targets.locked.passphrase));
  await settle(t);
});

test("a rejected passphrase does not restart the 120 second timer (shortened for the run)", async () => {
  timing.passphraseWaitMs = 1500;
  try {
    const cookie = await signIn("smoke-user");
    const t = openWs(cookie, "locked");
    await t.waitFor("prompt", () => t.json.some((m) => m.t === "passphrase"));
    const asked = Date.now();
    await sleep(900);
    t.send({ t: "passphrase", value: "" });
    await t.waitFor("closed", () => t.closed(), 5000);
    const elapsed = Date.now() - asked;
    assert.match(t.closed().reason, /Passphrase timeout/);
    assert.ok(elapsed < 2100, `closed after ${elapsed} ms; a restarted timer would take about 2400 ms`);
  } finally {
    timing.passphraseWaitMs = undefined;
  }
});

test("idle terminals are closed after the idle timeout (shortened for the run)", async () => {
  timing.idleTimeoutMs = 1500;
  try {
    const cookie = await signIn("smoke-user");
    const t = await connect(cookie, "plain");
    await t.waitFor("idle close", () => t.closed(), 6000);
    assert.match(t.closed().reason, /idle/);
  } finally {
    timing.idleTimeoutMs = undefined;
  }
});

