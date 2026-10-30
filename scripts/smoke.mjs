import http from "node:http";
import https from "node:https";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const positional = args.filter((a) => !a.startsWith("--"));

if (!positional[0] || flags.has("--help")) {
  console.error("usage: npm run smoke -- <baseUrl> [--rate-limit] [--insecure]");
  console.error("  --rate-limit  also exhaust the sign-in rate limit (locks your IP out of sign-in for 15 minutes)");
  console.error("  --insecure    accept a self-signed TLS certificate");
  process.exit(2);
}

let base;
try {
  base = new URL(positional[0]);
} catch {
  console.error(`not a URL: ${positional[0]}`);
  process.exit(2);
}
const origin = base.origin;
const secure = base.protocol === "https:";
const lib = secure ? https : http;
const agent = new lib.Agent({ keepAlive: false, ...(secure ? { rejectUnauthorized: !flags.has("--insecure") } : {}) });
const EVIL = "https://evil.example";

function request(method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = lib.request(
      { protocol: base.protocol, hostname: base.hostname, port: base.port || undefined, method, path, headers, agent, timeout: 10_000 },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("timeout", () => req.destroy(new Error(`timeout: ${method} ${path}`)));
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function upgrade(path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = lib.request({
      protocol: base.protocol,
      hostname: base.hostname,
      port: base.port || undefined,
      method: "GET",
      path,
      agent,
      timeout: 10_000,
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "c21va2UtdGVzdC1rZXktMTY=",
        ...headers,
      },
    });
    req.on("response", (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("upgrade", (_res, socket) => {
      socket.destroy();
      resolve(101);
    });
    req.on("timeout", () => req.destroy(new Error(`timeout: upgrade ${path}`)));
    req.on("error", reject);
    req.end();
  });
}

const results = [];

async function check(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`  ok    ${name}`);
  } catch (e) {
    results.push({ name, ok: false, error: e.message });
    console.log(`  FAIL  ${name}\n          ${e.message}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

function expect(cond, message) {
  if (!cond) throw new Error(message);
}

function expectJson(res) {
  try {
    return JSON.parse(res.body);
  } catch {
    throw new Error(`expected a JSON body, got: ${res.body.slice(0, 80)}`);
  }
}

function expectNoLeak(res) {
  expect(!/\n\s+at\s|node_modules|\.ts:\d+|<html|<pre>/i.test(res.body), `response leaks internals: ${res.body.slice(0, 120)}`);
}

function directives(csp) {
  const map = new Map();
  for (const part of csp.split(";")) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) map.set(name, values);
  }
  return map;
}

function assertSecurityHeaders(res) {
  const h = res.headers;
  const csp = h["content-security-policy"];
  expect(csp, "missing Content-Security-Policy");
  const d = directives(csp);
  expect(d.get("default-src")?.join(" ") === "'self'", `default-src should be 'self', got ${d.get("default-src")}`);
  expect(d.get("script-src")?.join(" ") === "'self'", `script-src should be exactly 'self', got ${d.get("script-src")}`);
  expect(d.get("frame-ancestors")?.join(" ") === "'none'", "frame-ancestors should be 'none'");
  expect(d.get("base-uri")?.join(" ") === "'none'", "base-uri should be 'none'");
  expect(d.get("object-src")?.join(" ") === "'none'", "object-src should be 'none'");
  expect(d.get("form-action")?.join(" ") === "'self'", "form-action should be 'self'");
  expect(d.get("connect-src")?.includes("'self'"), "connect-src should include 'self'");
  expect(!/unsafe-eval/.test(csp), "CSP must not allow unsafe-eval");
  expect(!d.get("script-src").some((v) => /unsafe-inline|\*|https?:/.test(v)), "script-src must not allow inline or remote scripts");
  expect(d.has("upgrade-insecure-requests") === secure, secure ? "https instance should send upgrade-insecure-requests" : "http instance should not send upgrade-insecure-requests");
  expect(h["x-content-type-options"] === "nosniff", "X-Content-Type-Options should be nosniff");
  expect(h["referrer-policy"] === "no-referrer", "Referrer-Policy should be no-referrer");
  expect(h["x-frame-options"] === "DENY", "X-Frame-Options should be DENY");
  expect(h["cross-origin-opener-policy"] === "same-origin", "Cross-Origin-Opener-Policy should be same-origin");
  expect(h["cross-origin-resource-policy"] === "same-origin", "Cross-Origin-Resource-Policy should be same-origin");
  const pp = h["permissions-policy"] ?? "";
  for (const f of ["camera=()", "microphone=()", "geolocation=()"]) expect(pp.includes(f), `Permissions-Policy should contain ${f}`);
  const hsts = h["strict-transport-security"];
  if (secure) {
    expect(hsts, "https instance should send Strict-Transport-Security");
    expect(Number(/max-age=(\d+)/.exec(hsts)?.[1]) >= 31_536_000, `HSTS max-age should be at least one year, got ${hsts}`);
  } else {
    expect(!hsts, "http instance must not send Strict-Transport-Security");
  }
  expect(!("x-powered-by" in h), "X-Powered-By must not be sent");
}

function setCookieFor(res, name) {
  const cookies = res.headers["set-cookie"] ?? [];
  return cookies.find((c) => c.startsWith(`${name}=`));
}

console.log(`Shellport smoke test against ${origin}${flags.has("--rate-limit") ? " (including the rate-limit check)" : ""}`);

let reachable = true;
await request("GET", "/healthz").catch((e) => {
  reachable = false;
  console.error(`\ncannot reach ${origin}: ${e.message}`);
});
if (!reachable) process.exit(1);

section("Availability and pages");
await check("GET /healthz returns 200 {ok:true}", async () => {
  const r = await request("GET", "/healthz");
  expect(r.status === 200, `status ${r.status}`);
  expect(expectJson(r).ok === true, "body is not {ok:true}");
});

const home = await request("GET", "/").catch(() => ({ status: 0, headers: {}, body: "" }));

await check("logged-out / serves only the sign-in page", async () => {
  expect(home.status === 200, `status ${home.status}`);
  expect(/text\/html/.test(home.headers["content-type"] ?? ""), "not HTML");
  expect(/Sign in to Shellport/.test(home.body), "sign-in heading missing");
  expect(/href="\/auth\/github"/.test(home.body), "GitHub sign-in link missing");
  expect(!/\/assets\/app[-.]/.test(home.body), "logged-out page references the terminal app bundle");
  expect(!/id="terms"|id="hosts"/.test(home.body), "logged-out page contains app markup");
});

await check("GET /auth/totp without a pending login is 401", async () => {
  const r = await request("GET", "/auth/totp");
  expect(r.status === 401, `status ${r.status}`);
  expect(expectJson(r).error === "no_pending_login", "unexpected error code");
});

section("Authentication is enforced");
for (const p of ["/api/me", "/api/hosts", "/api/signins"]) {
  await check(`GET ${p} without a session is 401`, async () => {
    const r = await request("GET", p);
    expect(r.status === 401, `status ${r.status}`);
    expect(expectJson(r).error === "unauthenticated", "unexpected error code");
    expect(!/login|githubId|hostKey|password/i.test(r.body.replace('"unauthenticated"', "")), "body carries data");
  });
}

await check("a forged session cookie is rejected", async () => {
  for (const name of ["sp_sid", "__Host-sp_sid"]) {
    const r = await request("GET", "/api/me", { headers: { cookie: `${name}=${"A".repeat(43)}` } });
    expect(r.status === 401, `${name}: status ${r.status}`);
  }
});

section("Security headers");
const probes = [["/", home], ["/healthz", null], ["/api/me", null], ["/definitely-missing", null]];
for (const [p, known] of probes) {
  await check(`security headers on ${p}`, async () => {
    assertSecurityHeaders(known ?? (await request("GET", p)));
  });
}

section("Caching");
for (const [p, known] of probes) {
  await check(`Cache-Control no-store on ${p}`, async () => {
    const r = known ?? (await request("GET", p));
    expect(/no-store/.test(r.headers["cache-control"] ?? ""), `Cache-Control is ${JSON.stringify(r.headers["cache-control"])}`);
  });
}

const assetPath = /\/assets\/[A-Za-z0-9_-]+-[A-Z0-9]{8}\.(?:js|css)/.exec(home.body)?.[0];
await check("hashed assets are cached for a year and immutable", async () => {
  expect(assetPath, "no content-hashed asset referenced from the sign-in page");
  const r = await request("GET", assetPath);
  expect(r.status === 200, `status ${r.status}`);
  const cc = r.headers["cache-control"] ?? "";
  expect(/max-age=31536000/.test(cc) && /immutable/.test(cc), `Cache-Control is ${JSON.stringify(cc)}`);
  expect(!/no-store/.test(cc), "asset must not be no-store");
  expect(r.headers["x-content-type-options"] === "nosniff", "asset lacks nosniff");
  expect(/javascript|css/.test(r.headers["content-type"] ?? ""), `content-type ${r.headers["content-type"]}`);
});

await check("static assets also carry the security headers", async () => {
  expect(assetPath, "no asset to test");
  assertSecurityHeaders(await request("GET", assetPath));
});

section("Cross-origin behaviour");
await check("no CORS headers are echoed for a foreign Origin", async () => {
  for (const o of [EVIL, "null"]) {
    for (const p of ["/api/me", "/healthz", "/"]) {
      const r = await request("GET", p, { headers: { origin: o } });
      const leaked = Object.keys(r.headers).filter((k) => k.startsWith("access-control-"));
      expect(leaked.length === 0, `${p} with Origin ${o} returned ${leaked.join(", ")}`);
    }
  }
});

await check("a CORS preflight is not granted", async () => {
  const r = await request("OPTIONS", "/api/hosts", {
    headers: { origin: EVIL, "access-control-request-method": "GET", "access-control-request-headers": "content-type" },
  });
  const leaked = Object.keys(r.headers).filter((k) => k.startsWith("access-control-"));
  expect(leaked.length === 0, `preflight returned ${leaked.join(", ")}`);
});

section("GitHub sign-in start and callback");
let state;
let stateCookie;
await check("/auth/github redirects to github.com with a random state", async () => {
  const r = await request("GET", "/auth/github");
  expect(r.status === 302, `status ${r.status} (rate limited?)`);
  const loc = new URL(r.headers.location);
  expect(loc.host === "github.com" && loc.pathname === "/login/oauth/authorize", `redirects to ${loc.origin}${loc.pathname}`);
  expect(loc.searchParams.get("client_id"), "client_id missing");
  state = loc.searchParams.get("state");
  expect(state && state.length >= 20, "state is missing or too short");
  expect(/\/auth\/github\/callback$/.test(loc.searchParams.get("redirect_uri") ?? ""), `redirect_uri is ${loc.searchParams.get("redirect_uri")}`);
  expect(loc.searchParams.get("allow_signup") === "false", "allow_signup should be false");
  expect(!loc.searchParams.get("scope"), `no OAuth scope should be requested, got ${loc.searchParams.get("scope")}`);
  stateCookie = setCookieFor(r, secure ? "__Host-sp_state" : "sp_state");
  expect(stateCookie, `no ${secure ? "__Host-sp_state" : "sp_state"} cookie set`);
});

await check("the state cookie is HttpOnly, SameSite and, on https, Secure and __Host-", async () => {
  expect(stateCookie, "no state cookie to inspect");
  expect(/;\s*HttpOnly/i.test(stateCookie), "missing HttpOnly");
  expect(/;\s*SameSite=Lax/i.test(stateCookie), "missing SameSite=Lax");
  expect(/;\s*Path=\//i.test(stateCookie), "missing Path=/");
  expect(!/;\s*Domain=/i.test(stateCookie), "must not set a Domain");
  expect(stateCookie.split(";")[0].split("=")[1] === state, "cookie value does not match the state parameter");
  if (secure) expect(/;\s*Secure/i.test(stateCookie), "missing Secure on https");
});

await check("a forged callback state is rejected", async () => {
  const cookie = stateCookie?.split(";")[0] ?? "";
  const forged = "x".repeat(state?.length ?? 32);
  const r = await request("GET", `/auth/github/callback?code=anything&state=${forged}`, { headers: { cookie } });
  expect(r.status === 302 && r.headers.location === "/?error=state", `got ${r.status} ${r.headers.location}`);
  expect(!setCookieFor(r, secure ? "__Host-sp_sid" : "sp_sid"), "a session was created for a forged state");
});

await check("a callback without the state cookie is rejected", async () => {
  const r = await request("GET", `/auth/github/callback?code=anything&state=${state ?? "y".repeat(32)}`);
  expect(r.status === 302 && r.headers.location === "/?error=state", `got ${r.status} ${r.headers.location}`);
  expect(!setCookieFor(r, secure ? "__Host-sp_sid" : "sp_sid"), "a session was created without the state cookie");
});

await check("a callback with no code is rejected", async () => {
  const cookie = stateCookie?.split(";")[0] ?? "";
  const r = await request("GET", `/auth/github/callback?state=${state ?? ""}`, { headers: { cookie } });
  expect(r.status === 302 && r.headers.location === "/?error=state", `got ${r.status} ${r.headers.location}`);
});

section("Cross-site request protection");
for (const [method, p] of [["POST", "/auth/logout"], ["POST", "/auth/totp"]]) {
  await check(`${method} ${p} with a foreign Origin is 403`, async () => {
    const r = await request(method, p, { headers: { origin: EVIL, "content-type": "application/json" }, body: "{}" });
    expect(r.status === 403, `status ${r.status}`);
    expect(expectJson(r).error === "bad_origin", "unexpected error code");
  });
  await check(`${method} ${p} with no Origin is 403`, async () => {
    const r = await request(method, p, { headers: { "content-type": "application/json" }, body: "{}" });
    expect(r.status === 403, `status ${r.status}`);
  });
}

await check("POST /api/signins/signout-others without a session is refused", async () => {
  const r = await request("POST", "/api/signins/signout-others", { headers: { origin: EVIL } });
  expect(r.status === 401 || r.status === 403, `status ${r.status}`);
});

section("WebSocket gate");
await check("WebSocket upgrade without a session is 401", async () => {
  const s = await upgrade("/ws?host=x", { Origin: origin });
  expect(s === 401, `status ${s}${s === 403 ? " (is the instance's publicUrl different from the URL you passed?)" : ""}`);
});
await check("WebSocket upgrade with a foreign Origin is 403", async () => {
  expect((await upgrade("/ws?host=x", { Origin: EVIL })) === 403, "not 403");
});
await check("WebSocket upgrade with no Origin is 403", async () => {
  expect((await upgrade("/ws?host=x")) === 403, "not 403");
});
await check("WebSocket upgrade on any other path is 404", async () => {
  expect((await upgrade("/socket", { Origin: origin })) === 404, "not 404");
});
await check("a forged session cookie does not open a WebSocket", async () => {
  const name = secure ? "__Host-sp_sid" : "sp_sid";
  const s = await upgrade("/ws?host=x", { Origin: origin, Cookie: `${name}=${"B".repeat(43)}` });
  expect(s === 401, `status ${s}`);
});

section("Errors and exposed files");
await check("unknown paths return 404 JSON without internals", async () => {
  for (const p of ["/definitely-missing", "/api/nope", "/auth/nope"]) {
    const r = await request("GET", p);
    expect(r.status === 404, `${p}: status ${r.status}`);
    expect(/json/.test(r.headers["content-type"] ?? ""), `${p}: content-type ${r.headers["content-type"]}`);
    expect(expectJson(r).error === "not_found", `${p}: unexpected error code`);
    expectNoLeak(r);
  }
});
await check("malformed URLs return a JSON error without internals", async () => {
  const r = await request("GET", "/%E0%A4%A");
  expect(r.status >= 400 && r.status < 500, `status ${r.status}`);
  expectJson(r);
  expectNoLeak(r);
});
await check("malformed JSON bodies return a JSON error without internals", async () => {
  const r = await request("POST", "/auth/totp", { headers: { origin, "content-type": "application/json" }, body: "{not json" });
  expect(r.status >= 400 && r.status < 500, `status ${r.status}`);
  expectJson(r);
  expectNoLeak(r);
});
await check("oversized JSON bodies are refused", async () => {
  const r = await request("POST", "/auth/totp", { headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ code: "1".repeat(5000) }) });
  expect(r.status === 413 || r.status === 400 || r.status === 401, `status ${r.status}`);
  expectNoLeak(r);
});
await check("config, keys, source and traversal paths are not served", async () => {
  for (const p of ["/config.json", "/.env", "/package.json", "/dist/server.js", "/keys/demo_ed25519", "/src/server/config.ts", "/assets/..%2f..%2fconfig.json", "/assets/%2e%2e/%2e%2e/package.json", "/assets/../../config.json"]) {
    const r = await request("GET", p);
    expect(r.status !== 200, `${p} returned 200`);
    expect(!/clientSecret|PRIVATE KEY|totpSecret/.test(r.body), `${p} leaked secrets`);
    expectNoLeak(r);
  }
});
await check("TRACE and unusual methods are not handled", async () => {
  for (const m of ["TRACE", "PUT", "DELETE"]) {
    const r = await request(m, "/");
    expect(r.status >= 400, `${m} / returned ${r.status}`);
  }
});

if (flags.has("--rate-limit")) {
  section("Rate limiting (opt-in)");
  await check("repeated sign-in starts are rate limited", async () => {
    let limitedAfter = 0;
    for (let i = 1; i <= 400; i++) {
      const r = await request("GET", "/auth/github");
      if (r.status === 302 && r.headers.location === "/?error=rate") {
        limitedAfter = i;
        break;
      }
    }
    expect(limitedAfter > 0, "no rate limit after 400 requests");
    console.log(`          limited after ${limitedAfter} requests; this IP is locked out of sign-in for about 15 minutes`);
  });
} else {
  console.log("\nRate limiting: skipped (pass --rate-limit to include it; it locks your IP out of sign-in for 15 minutes)");
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed, ${results.length} checks`);
if (failed.length) {
  console.log("\nFailures:");
  for (const f of failed) console.log(`  - ${f.name}: ${f.error}`);
  process.exit(1);
}
