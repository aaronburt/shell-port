import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import express, { type Request, type Response, type NextFunction } from "express";
import { WebSocketServer } from "ws";
import { parseCookie, stringifySetCookie } from "cookie";
import { findUser, hostsForUser, isAdmin, type LoadedConfig } from "./config.js";
import { addHost, HostAdminError, listKeys, type HostStore, type KeyProbe } from "./hostadmin.js";
import { verifyTotp } from "./totp.js";
import { SessionStore, RateLimiter, type UserSession } from "./sessions.js";
import { authorizeUrl, exchangeCode, type GitHubUser } from "./github.js";
import { openTerminal, type TerminalInfo, type TerminalTiming } from "./proxy.js";
import { audit } from "./log.js";
import { ActivityLog, sidTag } from "./activity.js";
import * as files from "./sftp.js";

const PERMISSIONS_POLICY = [
  "accelerometer", "autoplay", "bluetooth", "camera", "display-capture", "geolocation", "gyroscope",
  "hid", "magnetometer", "microphone", "midi", "payment", "publickey-credentials-get", "serial", "usb", "xr-spatial-tracking",
].map((f) => `${f}=()`).join(", ");

export function clientIp(remote: string, xff: string | undefined, trustProxy: boolean | number): string {
  if (!trustProxy || !xff) return remote;
  const chain = [...xff.split(",").map((a) => a.trim()).filter(Boolean), remote];
  return trustProxy === true ? chain[0] : chain[Math.max(0, chain.length - 1 - Number(trustProxy))];
}

export interface AppOptions {
  publicDir: string;
  exchange?: (code: string) => Promise<GitHubUser>;
  now?: () => number;
  timing?: TerminalTiming;
  onSeal?: () => void;
  hostStore?: HostStore;
  probeHostKey?: KeyProbe;
}

export function createApp(cfg: LoadedConfig, opts: AppOptions) {
  const https = cfg.server.publicUrl.startsWith("https://");
  const SID = https ? "__Host-sp_sid" : "sp_sid";
  const STATE = https ? "__Host-sp_state" : "sp_state";
  const redirectUri = `${cfg.server.publicUrl}/auth/github/callback`;
  const wsOrigin = cfg.server.publicUrl.replace(/^http/, "ws");

  const sessions = new SessionStore(cfg.session.ttlHours * 3_600_000);
  const loginLimiter = new RateLimiter(cfg.limits.loginAttemptsPer15Min, 15 * 60_000);
  const apiLimiter = new RateLimiter(600, 60_000);
  const passphraseLimiter = new RateLimiter(10, 15 * 60_000);
  const hostAddLimiter = new RateLimiter(20, 15 * 60_000);
  const activity = new ActivityLog();
  const terminals = new Map<number, Set<TerminalInfo>>();
  const terminalsBySession = new Map<string, Set<TerminalInfo>>();

  sessions.onEnd((s) => {
    for (const t of terminalsBySession.get(s.id) ?? []) t.close("Signed out");
  });
  const who = (s: UserSession) => ({ login: s.login, id: s.githubId });

  const cookieOpts = (maxAge: number) => ({ httpOnly: true, secure: https, sameSite: "lax" as const, path: "/", maxAge });
  const serializeCookie = (name: string, value: string, opts: ReturnType<typeof cookieOpts>) =>
    stringifySetCookie({ name, value, ...opts });
  const cookieValue = (header: string | undefined, name: string) => parseCookie(header ?? "")[name];
  const ipOf = (req: Request) => req.ip ?? "";
  const anySession = (cookieHeader: string | undefined): UserSession | undefined =>
    sessions.get(cookieValue(cookieHeader, SID));
  const getSession = (cookieHeader: string | undefined): UserSession | undefined => {
    const s = anySession(cookieHeader);
    return s?.stage === "full" ? s : undefined;
  };
  const totpLimiter = new RateLimiter(cfg.limits.loginAttemptsPer15Min, 15 * 60_000);
  const lastTotpCounter = new Map<number, number>();
  const MAX_TOTP_FAILURES = 5;

  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", cfg.server.trustProxy);

  app.use((req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data: https://avatars.githubusercontent.com",
        `connect-src 'self' ${wsOrigin}`,
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
        ...(https ? ["upgrade-insecure-requests"] : []),
      ].join("; "),
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    res.setHeader("Permissions-Policy", PERMISSIONS_POLICY);
    if (https) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    if (!req.path.startsWith("/assets/")) res.setHeader("Cache-Control", "no-store");
    next();
  });

  const requireSession = (req: Request, res: Response, next: NextFunction) => {
    if (!apiLimiter.hit(ipOf(req))) return res.status(429).json({ error: "rate_limited" });
    const s = getSession(req.headers.cookie);
    if (!s) return res.status(401).json({ error: "unauthenticated" });
    res.locals.session = s;
    next();
  };

  const requireSameOrigin = (req: Request, res: Response, next: NextFunction) =>
    req.headers.origin === cfg.server.publicUrl ? next() : res.status(403).json({ error: "bad_origin" });

  const requireAdmin = (_req: Request, res: Response, next: NextFunction) =>
    isAdmin(cfg, who(res.locals.session)) ? next() : res.status(403).json({ error: "forbidden" });

  app.get("/healthz", (_req, res) => res.json({ ok: true }));

  app.get("/", (req, res) => {
    const s = anySession(req.headers.cookie);
    const page = s?.stage === "full" ? "app.html" : s?.stage === "totp" ? "totp.html" : "login.html";
    res.sendFile(path.join(opts.publicDir, page));
  });

  app.get("/auth/github", (req, res) => {
    if (!loginLimiter.hit(ipOf(req))) return res.redirect("/?error=rate");
    const state = crypto.randomBytes(24).toString("base64url");
    res.setHeader("Set-Cookie", serializeCookie(STATE, state, cookieOpts(600)));
    res.redirect(authorizeUrl(cfg.github.clientId, redirectUri, state));
  });

  app.get("/auth/github/callback", async (req, res) => {
    const clearState = serializeCookie(STATE, "", cookieOpts(0));
    if (!loginLimiter.hit(ipOf(req))) return res.redirect("/?error=rate");
    const expected = cookieValue(req.headers.cookie, STATE);
    const { state, code } = req.query as Record<string, string | undefined>;
    if (
      !expected || !state || !code ||
      expected.length !== state.length ||
      !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(state))
    ) {
      res.setHeader("Set-Cookie", clearState);
      return res.redirect("/?error=state");
    }
    let user: GitHubUser;
    try {
      user = opts.exchange
        ? await opts.exchange(code)
        : await exchangeCode(cfg.github.clientId, cfg.github.resolvedSecret, code, redirectUri);
    } catch (e) {
      audit("login.error", { ip: ipOf(req), error: (e as Error).message });
      res.setHeader("Set-Cookie", clearState);
      return res.redirect("/?error=failed");
    }
    const entry = findUser(cfg, user);
    if (!entry) {
      audit("login.denied", { ip: ipOf(req), user: user.login, githubId: user.id });
      res.setHeader("Set-Cookie", clearState);
      return res.redirect("/?error=denied");
    }
    const stale = cookieValue(req.headers.cookie, SID);
    if (stale) sessions.destroy(stale);
    const s = sessions.create({ githubId: user.id, login: user.login, name: user.name, avatarUrl: user.avatarUrl }, "totp");
    audit("login.github_ok", { ip: ipOf(req), user: user.login, githubId: user.id });
    res.setHeader("Set-Cookie", [clearState, serializeCookie(SID, s.id, cookieOpts(cfg.session.ttlHours * 3600))]);
    res.redirect("/");
  });

  app.get("/auth/totp", (req, res) => {
    const s = anySession(req.headers.cookie);
    if (s?.stage !== "totp") return res.status(401).json({ error: "no_pending_login" });
    res.json({ login: s.login, name: s.name, avatarUrl: s.avatarUrl });
  });

  app.post("/auth/totp", requireSameOrigin, express.json({ limit: "1kb" }), (req, res) => {
    const s = anySession(req.headers.cookie);
    if (s?.stage !== "totp") return res.status(401).json({ error: "no_pending_login" });
    if (!totpLimiter.hit(ipOf(req))) return res.status(429).json({ error: "rate_limited" });
    const entry = findUser(cfg, who(s));
    const code = String(req.body?.code ?? "").replace(/\s/g, "");
    const counter = entry ? verifyTotp(entry.totpKey, code, opts.now?.() ?? Date.now()) : undefined;
    if (counter === undefined || counter <= (lastTotpCounter.get(s.githubId) ?? -1)) {
      s.totpFailures++;
      audit("login.totp_failed", { ip: ipOf(req), user: s.login, githubId: s.githubId, failures: s.totpFailures });
      activity.add({ kind: "totp_failed", githubId: s.githubId, ip: ipOf(req) });
      if (s.totpFailures >= MAX_TOTP_FAILURES) {
        sessions.destroy(s.id);
        res.setHeader("Set-Cookie", serializeCookie(SID, "", cookieOpts(0)));
        return res.status(401).json({ error: "too_many_attempts" });
      }
      return res.status(400).json({ error: "invalid_code", remaining: MAX_TOTP_FAILURES - s.totpFailures });
    }
    lastTotpCounter.set(s.githubId, counter);
    const full = sessions.promote(s);
    audit("login.ok", { ip: ipOf(req), user: s.login, githubId: s.githubId });
    activity.add({ kind: "signin", githubId: s.githubId, ip: ipOf(req), sid: sidTag(full.id) });
    res.setHeader("Set-Cookie", serializeCookie(SID, full.id, cookieOpts(cfg.session.ttlHours * 3600)));
    res.status(204).end();
  });

  app.post("/auth/logout", requireSameOrigin, (req, res) => {
    const s = anySession(req.headers.cookie);
    if (s) {
      audit("logout", { ip: ipOf(req), user: s.login });
      sessions.destroy(s.id);
    }
    res.setHeader("Set-Cookie", serializeCookie(SID, "", cookieOpts(0)));
    res.status(204).end();
  });

  app.get("/api/me", requireSession, (_req, res) => {
    const s: UserSession = res.locals.session;
    res.json({ login: s.login, name: s.name, avatarUrl: s.avatarUrl, expiresAt: s.expiresAt, sealable: !!opts.onSeal, admin: isAdmin(cfg, who(s)), canAddHosts: !!opts.hostStore && isAdmin(cfg, who(s)) });
  });

  if (opts.onSeal) {
    app.post("/api/seal", requireSession, requireSameOrigin, (req, res) => {
      const s: UserSession = res.locals.session;
      audit("seal", { ip: ipOf(req), user: s.login, githubId: s.githubId });
      res.on("finish", () => setImmediate(opts.onSeal!));
      res.status(204).end();
    });
  }

  app.get("/api/signins", requireSession, (req, res) => {
    const s: UserSession = res.locals.session;
    const host = typeof req.query.host === "string" ? req.query.host : undefined;
    const live = new Map(sessions.forUser(s.githubId).map((x) => [sidTag(x.id), x]));
    const mine = sidTag(s.id);
    const items = activity
      .list(s.githubId, (a) => a.kind !== "passphrase_failed" || (host !== undefined && a.host === host))
      .map((a) => {
        const base = { id: a.id, kind: a.kind, ip: a.ip, at: a.at };
        if (a.kind !== "signin") return base;
        const l = live.get(a.sid ?? "");
        return { ...base, session: a.sid, current: a.sid === mine, active: !!l, expiresAt: l?.expiresAt };
      });
    res.json({ items, others: [...live.keys()].filter((k) => k !== mine).length });
  });

  app.post("/api/signins/signout-others", requireSession, requireSameOrigin, (req, res) => {
    const s: UserSession = res.locals.session;
    const others = sessions.forUser(s.githubId).filter((x) => x.id !== s.id);
    for (const o of others) sessions.destroy(o.id);
    audit("logout.others", { ip: ipOf(req), user: s.login, ended: others.length });
    res.json({ ended: others.length });
  });

  app.get("/api/hosts", requireSession, (_req, res) => {
    const s: UserSession = res.locals.session;
    res.json(
      hostsForUser(cfg, who(s)).map((h) => ({
        id: h.id,
        name: h.name,
        group: h.group ?? "Hosts",
        tag: h.tag ?? "",
        addr: `${h.username}@${h.host}${h.port !== 22 ? `:${h.port}` : ""}`,
      })),
    );
  });

  app.get("/api/keys", requireSession, requireAdmin, (_req, res) => {
    res.json(listKeys(cfg));
  });

  app.post("/api/hosts", requireSession, requireAdmin, requireSameOrigin, express.json({ limit: "32kb" }), async (req, res) => {
    const s: UserSession = res.locals.session;
    if (!opts.hostStore) return res.status(409).json({ error: "storage_unavailable", message: "Hosts cannot be added from the browser on this server." });
    if (!hostAddLimiter.hit(String(s.githubId))) return res.status(429).json({ error: "rate_limited" });
    const body = req.body && typeof req.body === "object" ? req.body : {};
    try {
      const host = await addHost(cfg, opts.hostStore, body, opts.probeHostKey);
      audit("host.add", {
        ip: ipOf(req), user: s.login, githubId: s.githubId, host: host.id, target: `${host.username}@${host.host}:${host.port}`,
        key: body.key && typeof body.key === "object" && "upload" in body.key ? "uploaded" : "existing", store: opts.hostStore.kind,
      });
      res.status(201).json({ id: host.id });
    } catch (e) {
      if (!(e instanceof HostAdminError)) throw e;
      audit("host.add_failed", { ip: ipOf(req), user: s.login, githubId: s.githubId, error: e.code });
      res.status(e.status).json({ error: e.code, message: e.message });
    }
  });

  const MAX_DOWNLOADS_PER_TERMINAL = 2;
  const downloading = new Map<string, number>();

  const fileRoute = (
    op: string,
    handler: (a: { req: Request; res: Response; term: TerminalInfo; sftp: Awaited<ReturnType<TerminalInfo["sftp"]>>; s: UserSession; log: Record<string, unknown> }) => Promise<void>,
  ) => async (req: Request, res: Response) => {
    const s: UserSession = res.locals.session;
    const fetchSite = req.headers["sec-fetch-site"];
    if (fetchSite !== undefined && fetchSite !== "same-origin" && fetchSite !== "none") return res.status(403).json({ error: "bad_origin" });
    const term = [...(terminalsBySession.get(s.id) ?? [])].find((t) => t.id === req.params.id);
    if (!term) return res.status(404).json({ error: "not_found" });
    const log = { user: s.login, host: term.hostId, ip: ipOf(req) };
    try {
      const sftp = await term.sftp();
      term.touch();
      await handler({ req, res, term, sftp, s, log });
    } catch (e) {
      const err = files.describeError(e);
      audit("sftp.error", { ...log, op, error: err.code });
      if (!res.headersSent) res.status(err.status).json({ error: err.code });
      else res.destroy();
    }
  };

  const queryPath = (req: Request) => files.cleanPath(typeof req.query.path === "string" ? req.query.path : undefined);

  app.get("/api/terminals/:id/files", requireSession, fileRoute("list", async ({ req, res, sftp, log }) => {
    const dir = typeof req.query.path === "string" && req.query.path ? queryPath(req) : await files.home(sftp);
    const { entries, truncated } = await files.list(sftp, dir);
    audit("sftp.list", { ...log, path: dir, entries: entries.length });
    res.json({ path: dir, entries, truncated, maxDownloadBytes: cfg.limits.maxDownloadMB * 1024 * 1024 });
  }));

  app.get("/api/terminals/:id/files/view", requireSession, fileRoute("view", async ({ req, res, sftp, log }) => {
    const file = queryPath(req);
    const p = await files.preview(sftp, file);
    audit("sftp.view", { ...log, path: file, size: p.size });
    res.json({ path: file, ...p });
  }));

  app.get("/api/terminals/:id/files/download", requireSession, fileRoute("download", async ({ req, res, term, sftp, log }) => {
    const file = queryPath(req);
    const size = await files.fileSize(sftp, file);
    if (size > cfg.limits.maxDownloadMB * 1024 * 1024) throw new files.FileError(413, "too_large");
    const active = downloading.get(term.id) ?? 0;
    if (active >= MAX_DOWNLOADS_PER_TERMINAL) throw new files.FileError(429, "too_many_downloads");
    downloading.set(term.id, active + 1);
    const name = files.downloadName(file);
    res.status(200);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", String(size));
    res.setHeader("Content-Disposition", `attachment; filename="${name.ascii}"; filename*=UTF-8''${name.utf8}`);
    audit("sftp.download", { ...log, path: file, size });
    const stream = sftp.createReadStream(file);
    let sent = 0;
    const done = () => {
      const left = (downloading.get(term.id) ?? 1) - 1;
      left > 0 ? downloading.set(term.id, left) : downloading.delete(term.id);
      stream.destroy();
    };
    res.once("close", () => {
      done();
      audit("sftp.download_end", { ...log, path: file, bytes: sent, complete: sent === size });
    });
    stream.on("data", (c: Buffer) => { sent += c.length; term.touch(); });
    stream.on("error", () => res.destroy());
    stream.pipe(res);
  }));

  app.post("/api/terminals/:id/files/delete", requireSession, requireSameOrigin, express.json({ limit: "8kb" }), fileRoute("delete", async ({ req, res, sftp, log }) => {
    const target = files.cleanPath(req.body?.path);
    const kind = await files.remove(sftp, target);
    audit("sftp.delete", { ...log, path: target, kind });
    res.json({ deleted: target });
  }));

  app.use("/assets", express.static(path.join(opts.publicDir, "assets"), {
    index: false,
    fallthrough: false,
    setHeaders: (res, file) =>
      res.setHeader("Cache-Control", /-[A-Z0-9]{8}\.[a-z0-9.]+$/.test(file) ? "public, max-age=31536000, immutable" : "public, no-cache"),
  }));
  app.use((_req, res) => res.status(404).json({ error: "not_found" }));
  app.use((err: { status?: number; statusCode?: number }, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status ?? err.statusCode ?? 500;
    res.status(status >= 400 && status < 600 ? status : 500).json({ error: status === 404 ? "not_found" : status < 500 ? "bad_request" : "server_error" });
  });

  const server = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

  server.on("upgrade", (req, socket, head) => {
    const reject = (code: number, msg: string) => {
      socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      socket.destroy();
    };
    if (stopping) return reject(503, "Service Unavailable");
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname !== "/ws") return reject(404, "Not Found");
    const ip = clientIp(req.socket.remoteAddress ?? "", String(req.headers["x-forwarded-for"] ?? ""), cfg.server.trustProxy);
    if (!apiLimiter.hit(ip)) return reject(429, "Too Many Requests");
    if (req.headers.origin !== cfg.server.publicUrl) return reject(403, "Forbidden");
    const s = getSession(req.headers.cookie);
    if (!s) return reject(401, "Unauthorized");
    const host = hostsForUser(cfg, who(s)).find((h) => h.id === url.searchParams.get("host"));
    if (!host) return reject(404, "Not Found");
    const mine = terminals.get(s.githubId) ?? new Set();
    if (mine.size >= cfg.limits.maxTerminalsPerUser) return reject(429, "Too Many Requests");

    wss.handleUpgrade(req, socket, head, (ws) => {
      const set = terminals.get(s.githubId) ?? new Set<TerminalInfo>();
      terminals.set(s.githubId, set);
      const bySess = terminalsBySession.get(s.id) ?? new Set<TerminalInfo>();
      terminalsBySession.set(s.id, bySess);
      const t = openTerminal({
        ws, cfg, host, session: s, activity, passphraseLimiter, ip, timing: opts.timing,
        cols: url.searchParams.get("cols"),
        rows: url.searchParams.get("rows"),
        onClose: () => {
          set.delete(t);
          bySess.delete(t);
          if (!set.size) terminals.delete(s.githubId);
          if (!bySess.size) terminalsBySession.delete(s.id);
        },
      });
      set.add(t);
      bySess.add(t);
    });
  });

  let stopping: Promise<void> | undefined;
  const shutdown = (deadlineMs = 5000, reason = "shutdown"): Promise<void> =>
    (stopping ??= new Promise<void>((resolve) => {
      const open = [...terminals.values()].flatMap((set) => [...set]);
      audit("server.stop", { reason, terminals: open.length });
      const done = () => {
        clearTimeout(deadline);
        resolve();
      };
      const deadline = setTimeout(() => {
        for (const c of wss.clients) c.terminate();
        server.closeAllConnections();
        done();
      }, deadlineMs);
      server.close(() => done());
      for (const t of open) t.close("Server is shutting down");
      for (const c of wss.clients) c.close(1001, "Server is shutting down");
      wss.close();
      server.closeIdleConnections();
    }));

  return { app, server, sessions, shutdown };
}
