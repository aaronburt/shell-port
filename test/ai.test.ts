import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/server/app.js";
import { validateConfig } from "../src/server/config.js";
import { base32Encode } from "../src/server/totp.js";

test("LiteLLM suggestions require admin enablement and send only the request", async () => {
  let received: any;
  const gateway = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received = { url: req.url, auth: req.headers.authorization, session: req.headers["x-litellm-session-id"], body: JSON.parse(Buffer.concat(chunks).toString()) };
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ choices: [{ message: { content: "du -sh /tmp — Show the size." } }] }));
    });
  });
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const gatewayUrl = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}/v1`;
  const origin = "http://localhost:8080";
  const cfg = validateConfig({ server: { publicUrl: origin }, github: { clientId: "x", clientSecret: "x" }, users: [
    { github: "admin", admin: true, totpSecret: base32Encode(Buffer.alloc(20, 1)) },
    { github: "user", totpSecret: base32Encode(Buffer.alloc(20, 2)) },
  ], security: { allowUnpinnedHostKeys: true }, hosts: [{ id: "host", host: "localhost", username: "u", auth: { type: "password", password: "x" } }] }, process.cwd());
  let raw: Record<string, unknown> = {};
  const app = createApp(cfg, { publicDir: process.cwd(), aiStore: { read: () => structuredClone(raw), write: (v) => { raw = structuredClone(v as Record<string, unknown>); } } });
  await new Promise<void>((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  const admin = app.sessions.create({ githubId: 1, login: "admin", name: "Admin" }, "full");
  const user = app.sessions.create({ githubId: 2, login: "user", name: "User" }, "full");
  const headers = (id: string, o = origin) => ({ cookie: `sp_sid=${id}`, origin: o, "content-type": "application/json" });
  const put = (id: string, value: unknown, o = origin) => fetch(`${base}/api/ai/settings`, { method: "PUT", headers: headers(id, o), body: JSON.stringify(value) });
  const ask = (id: string) => fetch(`${base}/api/ai/suggest`, { method: "POST", headers: headers(id), body: JSON.stringify({ prompt: "size of /tmp" }) });
  try {
    assert.equal((await fetch(`${base}/api/ai/status`)).status, 401);
    assert.equal((await ask(user.id)).status, 404);
    const settings = { enabled: true, baseUrl: gatewayUrl, model: "example", apiKey: "gateway-secret", acknowledge: true };
    assert.equal((await put(user.id, settings)).status, 403);
    assert.equal((await put(admin.id, settings, "http://evil.test")).status, 403);
    assert.equal((await put(admin.id, { ...settings, acknowledge: false })).status, 400);
    assert.equal((await put(admin.id, settings)).status, 200);
    const info = await (await fetch(`${base}/api/ai/settings`, { headers: headers(admin.id) })).text();
    assert.doesNotMatch(info, /gateway-secret/);
    assert.equal((await fetch(`${base}/api/ai/settings`, { headers: headers(user.id) })).status, 403);
    const response = await ask(user.id);
    assert.equal(response.status, 200);
    assert.match((await response.json()).suggestion, /du -sh/);
    assert.equal(received.url, "/v1/chat/completions");
    assert.equal(received.auth, "Bearer gateway-secret");
    assert.notEqual(received.session, user.id);
    assert.equal(received.body.messages[1].content, "size of /tmp");
    assert.equal((await put(admin.id, { ...settings, enabled: false, apiKey: "", acknowledge: false })).status, 200);
    assert.equal((await ask(user.id)).status, 404);
  } finally {
    await app.shutdown();
    await new Promise<void>((resolve) => gateway.close(() => resolve()));
  }
});
