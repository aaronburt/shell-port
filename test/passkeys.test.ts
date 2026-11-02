import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { validateConfig, type PasskeyRecord } from "../src/server/config.js";
import { base32Decode, base32Encode, hotp } from "../src/server/totp.js";
import { createApp } from "../src/server/app.js";
import type { PasskeyStore } from "../src/server/passkeys.js";

const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");
const sha = (b: Buffer | string) => crypto.createHash("sha256").update(b).digest();

const head = (major: number, n: number) => (n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]));
const cbText = (s: string) => Buffer.concat([head(3, s.length), Buffer.from(s)]);
const cbBytes = (b: Buffer) => Buffer.concat([head(2, b.length), b]);

class SoftKey {
  id = crypto.randomBytes(32);
  pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  counter = 0;

  constructor(private origin: string, private rpId: string) {}

  private cose(): Buffer {
    const jwk = this.pair.publicKey.export({ format: "jwk" });
    return Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]), cbBytes(Buffer.from(jwk.x!, "base64url")), Buffer.from([0x22]), cbBytes(Buffer.from(jwk.y!, "base64url"))]);
  }

  create(options: any, over: { origin?: string; flags?: number } = {}) {
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin: over.origin ?? this.origin, crossOrigin: false }));
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.id.length);
    const authData = Buffer.concat([sha(this.rpId), Buffer.from([over.flags ?? 0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, this.id, this.cose()]);
    const att = Buffer.concat([Buffer.from([0xa3]), cbText("fmt"), cbText("none"), cbText("attStmt"), Buffer.from([0xa0]), cbText("authData"), cbBytes(authData)]);
    return {
      id: b64u(this.id), rawId: b64u(this.id), type: "public-key", clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(att), transports: ["internal"] },
    };
  }

  get(options: any, over: { origin?: string; flags?: number; counter?: number } = {}) {
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin: over.origin ?? this.origin, crossOrigin: false }));
    this.counter = over.counter ?? this.counter + 1;
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(this.counter);
    const authData = Buffer.concat([sha(this.rpId), Buffer.from([over.flags ?? 0x05]), ctr]);
    const signature = crypto.sign("sha256", Buffer.concat([authData, sha(clientData)]), this.pair.privateKey);
    return {
      id: b64u(this.id), rawId: b64u(this.id), type: "public-key", clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature) },
    };
  }
}

let base = "";
let app: ReturnType<typeof createApp>;
let saved: PasskeyRecord[] = [];
let saves = 0;
let failSave = false;
let nextUser = "aaronburt";
let totpSecret = "";
const store: PasskeyStore = {
  kind: "file",
  save: (_match, list) => {
    if (failSave) throw Object.assign(new Error("read-only"), { status: 500 });
    saved = list;
    saves++;
  },
};

before(async () => {
  const probe = (await import("node:net")).createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r()));
  const port = (probe.address() as AddressInfo).port;
  await new Promise((r) => probe.close(r));
  base = `http://127.0.0.1:${port}`;
  const secret = base32Encode(crypto.randomBytes(20));
  totpSecret = secret;
  const cfg = validateConfig({
    server: { port, publicUrl: base },
    github: { clientId: "id", clientSecret: "secret" },
    users: [{ github: "AaronBurt", totpSecret: secret }, { github: "other", totpSecret: secret }],
    limits: { loginAttemptsPer15Min: 500 },
    hosts: [{ id: "h", host: "127.0.0.1", port: 22, username: "deploy", auth: { type: "password", password: "x" }, hostKeyFingerprints: ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] }],
  }, process.cwd());
  app = createApp(cfg, {
    publicDir: path.resolve("dist/public"),
    passkeyStore: store,
    exchange: async () => ({ id: nextUser === "other" ? 11 : 42388542, login: nextUser, name: nextUser }),
  });
  await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
});

after(() => {
  app.server.close();
  setTimeout(() => process.exit(0), 50).unref();
});

const cookiesOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const json = (cookie: string, body?: unknown, method = "POST") =>
  ({ method, headers: { cookie, origin: base, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });

async function githubPending(user: string): Promise<string> {
  nextUser = user;
  const start = await fetch(`${base}/auth/github`, { redirect: "manual" });
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const cb = await fetch(`${base}/auth/github/callback?code=good&state=${state}`, { redirect: "manual", headers: { cookie: cookiesOf(start) } });
  return cb.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0];
}

async function fullSession(user: string): Promise<string> {
  const pending = await githubPending(user);
  const s = [...(app.sessions as any).sessions.values()].find((x: any) => `sp_sid=${x.id}` === pending);
  const full = app.sessions.promote(s);
  return `sp_sid=${full.id}`;
}

async function register(cookie: string, key: SoftKey, name: string, over?: Parameters<SoftKey["create"]>[1]) {
  const o = await fetch(`${base}/api/passkeys/register/options`, json(cookie));
  assert.equal(o.status, 200);
  const options = await o.json();
  return { options, res: await fetch(`${base}/api/passkeys/register/verify`, json(cookie, { name, response: key.create(options, over) })) };
}

async function passkeyLogin(key: SoftKey, over?: Parameters<SoftKey["get"]>[1], tamper?: (b: any) => void) {
  const o = await fetch(`${base}/auth/passkey/options`, { method: "POST", headers: { origin: base } });
  assert.equal(o.status, 200);
  const { challengeId, options } = await o.json();
  assert.equal(options.userVerification, "required");
  assert.deepEqual(options.allowCredentials ?? [], []);
  const body: any = { challengeId, response: key.get(options, over) };
  tamper?.(body);
  return fetch(`${base}/auth/passkey/verify`, json("", body));
}

const rp = () => new URL(base).hostname;

test("Permissions-Policy lets this origin use passkeys and nothing else", async () => {
  const r = await fetch(`${base}/healthz`);
  const pp = r.headers.get("permissions-policy")!;
  assert.match(pp, /publickey-credentials-get=\(self\)/);
  assert.match(pp, /publickey-credentials-create=\(self\)/);
  assert.match(pp, /camera=\(\)/);
});

test("passkeys cannot be registered without a signed-in session or from a pending one", async () => {
  const o = await fetch(`${base}/api/passkeys/register/options`, json(""));
  assert.equal(o.status, 401);
  const pending = await githubPending("aaronburt");
  const o2 = await fetch(`${base}/api/passkeys/register/options`, json(pending));
  assert.equal(o2.status, 401);
  const o3 = await fetch(`${base}/api/passkeys`, { headers: { cookie: pending } });
  assert.equal(o3.status, 401);
});

test("registration needs a same-origin request", async () => {
  const cookie = await fullSession("aaronburt");
  const r = await fetch(`${base}/api/passkeys/register/options`, { method: "POST", headers: { cookie, origin: "https://evil.example" } });
  assert.equal(r.status, 403);
});

test("a signed-in user registers a passkey, then signs in with it alone", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  const { options, res } = await register(cookie, key, "Laptop");
  assert.equal(options.authenticatorSelection.residentKey, "required");
  assert.equal(options.authenticatorSelection.userVerification, "required");
  assert.equal(options.rp.id, rp());
  assert.equal(options.user.name, "aaronburt");
  assert.equal(res.status, 201);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].name, "Laptop");
  assert.equal(saved[0].githubId, 42388542);

  const list = await (await fetch(`${base}/api/passkeys`, { headers: { cookie } })).json();
  assert.equal(list.length, 1);
  assert.equal(list[0].name, "Laptop");
  assert.equal(list[0].publicKey, undefined);

  const login = await passkeyLogin(key);
  assert.equal(login.status, 204);
  const sid = login.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!;
  assert.match(sid, /HttpOnly/i);
  const fresh = sid.split(";")[0];
  const me = await (await fetch(`${base}/api/me`, { headers: { cookie: fresh } })).json();
  assert.equal(me.login, "aaronburt");
  assert.equal(me.via, "passkey");
  assert.equal(me.canManagePasskeys, true);
  const hosts = await fetch(`${base}/api/hosts`, { headers: { cookie: fresh } });
  assert.equal(hosts.status, 200);
  const signins = await (await fetch(`${base}/api/signins`, { headers: { cookie: fresh } })).json();
  assert.equal(signins.items[0].method, "passkey");
  const page = await (await fetch(`${base}/`, { headers: { cookie: fresh } })).text();
  assert.match(page, /id="ws"/);
});

test("a login challenge works once and a replayed response is refused", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  await register(cookie, key, "Replay key");
  const o = await (await fetch(`${base}/auth/passkey/options`, { method: "POST", headers: { origin: base } })).json();
  const body = { challengeId: o.challengeId, response: key.get(o.options) };
  const first = await fetch(`${base}/auth/passkey/verify`, json("", body));
  assert.equal(first.status, 204);
  const again = await fetch(`${base}/auth/passkey/verify`, json("", body));
  assert.equal(again.status, 401);
});

test("passkey sign-in refuses unknown credentials, wrong origins, missing user verification and bad signatures", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  await register(cookie, key, "Strict key");
  assert.equal((await passkeyLogin(new SoftKey(base, rp()))).status, 401);
  assert.equal((await passkeyLogin(key, { origin: "https://evil.example" })).status, 401);
  assert.equal((await passkeyLogin(key, { flags: 0x01 })).status, 401);
  assert.equal((await passkeyLogin(key, undefined, (b) => { b.response.response.signature = b64u(crypto.randomBytes(70)); })).status, 401);
  assert.equal((await passkeyLogin(key, undefined, (b) => { b.challengeId = "nope"; })).status, 401);
  assert.equal((await passkeyLogin(key)).status, 204);
});

test("a passkey assertion replaying an old counter is refused", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  await register(cookie, key, "Counter key");
  assert.equal((await passkeyLogin(key, { counter: 5 })).status, 204);
  assert.equal((await passkeyLogin(key, { counter: 5 })).status, 401);
  assert.equal((await passkeyLogin(key, { counter: 6 })).status, 204);
});

test("registration rejects a missing user-verification flag, a foreign origin, duplicate names and a re-used credential", async () => {
  const cookie = await fullSession("aaronburt");
  const k1 = new SoftKey(base, rp());
  assert.equal((await register(cookie, k1, "No UV", { flags: 0x41 })).res.status, 400);
  assert.equal((await register(cookie, k1, "Evil", { origin: "https://evil.example" })).res.status, 400);
  assert.equal((await register(cookie, k1, "First dup")).res.status, 201);
  const k2 = new SoftKey(base, rp());
  const dup = await register(cookie, k2, "first DUP");
  assert.equal(dup.res.status, 409);
  assert.equal((await dup.res.json()).error, "duplicate_name");
  assert.equal((await register(cookie, k1, "Same credential")).res.status, 409);
  assert.equal((await register(cookie, k2, "   ")).res.status, 400);
});

test("registration verify needs a fresh challenge", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  const options = await (await fetch(`${base}/api/passkeys/register/options`, json(cookie))).json();
  const response = key.create(options);
  assert.equal((await fetch(`${base}/api/passkeys/register/verify`, json(cookie, { name: "Once", response }))).status, 201);
  const second = await fetch(`${base}/api/passkeys/register/verify`, json(cookie, { name: "Twice", response: new SoftKey(base, rp()).create(options) }));
  assert.equal(second.status, 400);
});

test("registered passkeys are excluded from the next registration and each user only sees their own", async () => {
  const a = await fullSession("aaronburt");
  const ka = new SoftKey(base, rp());
  await register(a, ka, "Mine");
  const next = await (await fetch(`${base}/api/passkeys/register/options`, json(a))).json();
  assert.ok(next.excludeCredentials.some((c: any) => c.id === b64u(ka.id)));
  const other = await fullSession("other");
  const kb = new SoftKey(base, rp());
  await register(other, kb, "Theirs");
  const theirs = await (await fetch(`${base}/api/passkeys`, { headers: { cookie: other } })).json();
  assert.deepEqual(theirs.map((p: any) => p.name), ["Theirs"]);
  const del = await fetch(`${base}/api/passkeys/${b64u(kb.id)}`, { method: "DELETE", headers: { cookie: a, origin: base } });
  assert.equal(del.status, 404);
  const login = await passkeyLogin(kb);
  assert.equal(login.status, 204);
  const me = await (await fetch(`${base}/api/me`, { headers: { cookie: login.headers.getSetCookie().find((c) => c.startsWith("sp_sid="))!.split(";")[0] } })).json();
  assert.equal(me.login, "other");
});

test("removing a passkey stops it signing in", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  await register(cookie, key, "Doomed");
  const noOrigin = await fetch(`${base}/api/passkeys/${b64u(key.id)}`, { method: "DELETE", headers: { cookie } });
  assert.equal(noOrigin.status, 403);
  const del = await fetch(`${base}/api/passkeys/${b64u(key.id)}`, { method: "DELETE", headers: { cookie, origin: base } });
  assert.equal(del.status, 204);
  assert.ok(!saved.some((p) => p.id === b64u(key.id)));
  assert.equal((await passkeyLogin(key)).status, 401);
});

test("a storage failure leaves the passkey unregistered", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  failSave = true;
  try {
    const r = await register(cookie, key, "Unsaved");
    assert.equal(r.res.status, 500);
  } finally { failSave = false; }
  assert.equal((await passkeyLogin(key)).status, 401);
  const list = await (await fetch(`${base}/api/passkeys`, { headers: { cookie } })).json();
  assert.ok(!list.some((p: any) => p.name === "Unsaved"));
});

test("passkey sign-in records the method and signing in again replaces any stale session", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  await register(cookie, key, "Stale");
  const o = await (await fetch(`${base}/auth/passkey/options`, { method: "POST", headers: { origin: base } })).json();
  const r = await fetch(`${base}/auth/passkey/verify`, json(cookie, { challengeId: o.challengeId, response: key.get(o.options) }));
  assert.equal(r.status, 204);
  assert.equal((await fetch(`${base}/api/me`, { headers: { cookie } })).status, 401);
});

const codeNow = (offset = 0) => hotp(base32Decode(totpSecret), Math.floor(Date.now() / 30_000) + offset);
const lockPost = (path: string, cookie: string, body?: unknown) => fetch(`${base}/api/lock/${path}`, json(cookie, body ?? {}));

test("lock endpoints need a fully signed-in session and a same-origin request", async () => {
  assert.equal((await lockPost("totp", "", { code: "123456" })).status, 401);
  assert.equal((await lockPost("passkey/options", "")).status, 401);
  assert.equal((await lockPost("passkey/verify", "", {})).status, 401);
  const pending = await githubPending("aaronburt");
  assert.equal((await lockPost("totp", pending, { code: codeNow() })).status, 401);
  const cookie = await fullSession("aaronburt");
  const cross = await fetch(`${base}/api/lock/totp`, { method: "POST", headers: { cookie, origin: "https://evil.example", "content-type": "application/json" }, body: JSON.stringify({ code: codeNow() }) });
  assert.equal(cross.status, 403);
});

test("unlocking with the authenticator code works once per code and rejects wrong codes", async () => {
  const cookie = await fullSession("aaronburt");
  const bad = await lockPost("totp", cookie, { code: "000000" });
  assert.equal(bad.status, 400);
  assert.deepEqual(await bad.json(), { error: "invalid_code", remaining: 4 });
  const letters = await lockPost("totp", cookie, { code: "abcdef" });
  assert.equal(letters.status, 400);
  const good = codeNow();
  const ok = await lockPost("totp", cookie, { code: ` ${good.slice(0, 3)} ${good.slice(3)} ` });
  assert.equal(ok.status, 204);
  const replay = await lockPost("totp", cookie, { code: good });
  assert.equal(replay.status, 400);
  assert.equal((await fetch(`${base}/api/me`, { headers: { cookie } })).status, 200);
  const signins = await (await fetch(`${base}/api/signins`, { headers: { cookie } })).json();
  assert.ok(signins.items.some((i: any) => i.kind === "totp_failed"));
});

test("five wrong unlock codes end the session", async () => {
  const cookie = await fullSession("other");
  for (let i = 4; i >= 1; i--) {
    const r = await lockPost("totp", cookie, { code: "000000" });
    assert.equal(r.status, 400);
    assert.equal((await r.json()).remaining, i);
  }
  const last = await lockPost("totp", cookie, { code: "000000" });
  assert.equal(last.status, 401);
  assert.equal((await last.json()).error, "too_many_attempts");
  assert.equal((await fetch(`${base}/api/me`, { headers: { cookie } })).status, 401);
});

test("a correct unlock resets the failure count", async () => {
  const cookie = await fullSession("other");
  for (let i = 0; i < 3; i++) assert.equal((await lockPost("totp", cookie, { code: "000000" })).status, 400);
  assert.equal((await lockPost("totp", cookie, { code: codeNow() })).status, 204);
  const r = await lockPost("totp", cookie, { code: "000000" });
  assert.equal((await r.json()).remaining, 4);
});

test("unlocking with a passkey only accepts that user's own passkeys, once per challenge", async () => {
  const cookie = await fullSession("aaronburt");
  const key = new SoftKey(base, rp());
  const { res } = await register(cookie, key, "Lock key");
  assert.equal(res.status, 201);

  const o = await lockPost("passkey/options", cookie);
  assert.equal(o.status, 200);
  const options = await o.json();
  assert.equal(options.userVerification, "required");
  assert.ok(options.allowCredentials.some((c: any) => c.id === b64u(key.id)));
  const ok = await lockPost("passkey/verify", cookie, { response: key.get(options) });
  assert.equal(ok.status, 204);
  const again = await lockPost("passkey/verify", cookie, { response: key.get(options) });
  assert.equal(again.status, 400);

  const o2 = await (await lockPost("passkey/options", cookie)).json();
  const stranger = new SoftKey(base, rp());
  const forged = await lockPost("passkey/verify", cookie, { response: stranger.get(o2) });
  assert.equal(forged.status, 400);
  const wrongOrigin = await lockPost("passkey/verify", cookie, { response: key.get(o2, { origin: "https://evil.example" }) });
  assert.equal(wrongOrigin.status, 400);

  const otherCookie = await fullSession("other");
  const theirs = await lockPost("passkey/options", otherCookie);
  assert.ok(![...(await theirs.json()).allowCredentials ?? []].some((c: any) => c.id === b64u(key.id)));
  const o3 = await (await lockPost("passkey/options", cookie)).json();
  const crossUser = await lockPost("passkey/verify", otherCookie, { response: key.get(o3) });
  assert.equal(crossUser.status, 400);
});
