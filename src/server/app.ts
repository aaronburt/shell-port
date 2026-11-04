import crypto from "node:crypto";
import { aiRoutes } from "./ai.js";
import type { StoreIoLike } from "./config.js";
import http from "node:http";
import path from "node:path";
import express, { type Request, type Response, type NextFunction } from "express";
import { WebSocketServer } from "ws";
import { parseCookie, stringifySetCookie } from "cookie";
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { findUser, hostsForUser, isAdmin, userAllowed, type LoadedConfig } from "./config.js";
import { ChallengeBook, findPasskey, MAX_PASSKEYS_PER_USER, PasskeyError, rpIdFor, userHandle, type PasskeyStore } from "./passkeys.js";
import { addHost, describeHost, HostAdminError, listKeys, removeHost, updateHost, type HostStore, type KeyProbe } from "./hostadmin.js";
import { verifyTotp } from "./totp.js";
import { SessionStore, RateLimiter, type UserSession } from "./sessions.js";
import { authorizeUrl, exchangeCode, type GitHubUser } from "./github.js";
import { openTerminal, type TerminalInfo, type TerminalTiming } from "./proxy.js";
import { audit } from "./log.js";
import { ActivityLog, sidTag } from "./activity.js";
import { AuditLog, AUDIT_GROUPS, AUDIT_KINDS, auditCsv, type AuditKind } from "./auditlog.js";
import * as files from "./sftp.js";
import type { RecordingStore } from "./recording.js";
import { BUILD_VERSION, releaseNotesUrl } from "./version.js";

const PERMISSIONS_POLICY = [
  "accelerometer", "autoplay", "bluetooth", "camera", "display-capture", "geolocation", "gyroscope",
  "hid", "magnetometer", "microphone", "midi", "payment", "serial", "usb", "xr-spatial-tracking",
].map((f) => `${f}=()`).concat(["publickey-credentials-get=(self)", "publickey-credentials-create=(self)"]).join(", ");

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
  aiStore?: StoreIoLike;
  probeHostKey?: KeyProbe;
  passkeyStore?: PasskeyStore;
  auditLog?: AuditLog;
  recordings?: RecordingStore;
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
  const auditLog = opts.auditLog ?? new AuditLog({ retentionDays: cfg.limits.auditRetentionDays });
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
  const rec = (kind: AuditKind, req: Request, user: string, extra: { host?: string; detail?: string } = {}) =>
    auditLog.add({ kind, user, ip: ipOf(req), ...extra });
  const anySession = (cookieHeader: string | undefined): UserSession | undefined =>
    sessions.get(cookieValue(cookieHeader, SID));
  const getSession = (cookieHeader: string | undefined): UserSession | undefined => {
    const s = anySession(cookieHeader);
    return s?.stage === "full" ? s : undefined;
  };
  const rpId = rpIdFor(cfg.server.publicUrl);
  const registrations = new ChallengeBook();
  const logins = new ChallengeBook();
  const passkeyLimiter = new RateLimiter(cfg.limits.loginAttemptsPer15Min, 15 * 60_000);
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

  const ai = aiRoutes(opts.aiStore, {
    terminal: (s, id) => [...(terminalsBySession.get(s.id) ?? [])].find((t) => t.id === id),
    trail: (kind, s, ip, host, detail) => auditLog.add({ kind, user: s.login, ip, host, detail }),
  });
  app.get("/api/ai/status", requireSession, ai.status);
  app.get("/api/ai/settings", requireSession, requireAdmin, ai.settings);
  app.put("/api/ai/settings", requireSession, requireAdmin, requireSameOrigin, express.json({ limit: "8kb" }), ai.save);
  app.post("/api/ai/suggest", requireSession, requireSameOrigin, express.json({ limit: "8kb" }), ai.suggest);
  app.post("/api/ai/investigate", requireSession, requireSameOrigin, express.json({ limit: "256kb" }), ai.investigate);
  app.post("/api/ai/investigate/run", requireSession, requireSameOrigin, express.json({ limit: "8kb" }), ai.run);
  app.post("/api/ai/investigate/stop", requireSession, requireSameOrigin, express.json({ limit: "8kb" }), ai.stop);

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
      rec("signin_denied", req, user.login, { detail: "Not on this server's allowlist" });
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
      rec("totp_failed", req, s.login, { detail: `At sign-in, attempt ${s.totpFailures} of ${MAX_TOTP_FAILURES}` });
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
    rec("signin", req, s.login, { detail: "GitHub + authenticator code" });
    activity.add({ kind: "signin", githubId: s.githubId, ip: ipOf(req), sid: sidTag(full.id) });
    res.setHeader("Set-Cookie", serializeCookie(SID, full.id, cookieOpts(cfg.session.ttlHours * 3600)));
    res.status(204).end();
  });

  app.post("/auth/passkey/options", requireSameOrigin, async (req, res) => {
    if (!loginLimiter.hit(ipOf(req))) return res.status(429).json({ error: "rate_limited" });
    const options = await generateAuthenticationOptions({ rpID: rpId, userVerification: "required", timeout: 120_000 });
    res.json({ challengeId: logins.put(options.challenge), options });
  });

  app.post("/auth/passkey/verify", requireSameOrigin, express.json({ limit: "16kb" }), async (req, res) => {
    const ip = ipOf(req);
    if (!loginLimiter.hit(ip)) return res.status(429).json({ error: "rate_limited" });
    const fail = (reason: string, extra: Record<string, unknown> = {}) => {
      audit("login.passkey_failed", { ip, reason, ...extra });
      auditLog.add({ kind: "passkey_failed", user: typeof extra.user === "string" ? extra.user : "", ip, detail: reason.replace(/_/g, " ") });
      res.status(401).json({ error: "passkey_failed" });
    };
    const challenge = logins.take(req.body?.challengeId);
    const response = req.body?.response;
    if (!challenge || !response || typeof response !== "object" || typeof response.id !== "string") return fail("bad_request");
    const found = findPasskey(cfg, response.id);
    if (!found) return fail("unknown_credential");
    const { user, passkey } = found;
    if (!userAllowed([user.match], { login: passkey.login, id: passkey.githubId })) return fail("owner_mismatch", { user: passkey.login });
    let verified;
    try {
      verified = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: cfg.server.publicUrl,
        expectedRPID: rpId,
        requireUserVerification: true,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(Buffer.from(passkey.publicKey, "base64url")),
          counter: passkey.counter,
          transports: passkey.transports as never,
        },
      });
    } catch (e) {
      return fail("verification", { user: passkey.login, error: (e as Error).message });
    }
    if (!verified.verified) return fail("not_verified", { user: passkey.login });
    passkey.counter = verified.authenticationInfo.newCounter;
    passkey.lastUsedAt = Date.now();
    try { opts.passkeyStore?.save(user.match, user.passkeys); } catch {}
    const stale = cookieValue(req.headers.cookie, SID);
    if (stale) sessions.destroy(stale);
    const s = sessions.create(
      { githubId: passkey.githubId, login: passkey.login, name: passkey.displayName ?? passkey.login, avatarUrl: passkey.avatarUrl },
      "full",
      "passkey",
    );
    audit("login.ok", { ip, user: s.login, githubId: s.githubId, method: "passkey", passkey: passkey.name });
    auditLog.add({ kind: "signin", user: s.login, ip, detail: `Passkey (${passkey.name})` });
    activity.add({ kind: "signin", githubId: s.githubId, ip, sid: sidTag(s.id), method: "passkey" });
    res.setHeader("Set-Cookie", serializeCookie(SID, s.id, cookieOpts(cfg.session.ttlHours * 3600)));
    res.status(204).end();
  });

  const unlocks = new ChallengeBook();
  const unlockLimiter = new RateLimiter(cfg.limits.loginAttemptsPer15Min, 15 * 60_000);

  const unlockFailed = (req: Request, res: Response, s: UserSession, how: "totp" | "passkey", reason: string) => {
    s.totpFailures++;
    audit("lock.unlock_failed", { ip: ipOf(req), user: s.login, githubId: s.githubId, method: how, reason, failures: s.totpFailures });
    rec("unlock_failed", req, s.login, { detail: `${how === "totp" ? "Wrong authenticator code" : "Passkey rejected"}, attempt ${s.totpFailures} of ${MAX_TOTP_FAILURES}${s.totpFailures >= MAX_TOTP_FAILURES ? ", session ended" : ""}` });
    if (how === "totp") activity.add({ kind: "totp_failed", githubId: s.githubId, ip: ipOf(req) });
    if (s.totpFailures >= MAX_TOTP_FAILURES) {
      sessions.destroy(s.id);
      res.setHeader("Set-Cookie", serializeCookie(SID, "", cookieOpts(0)));
      return res.status(401).json({ error: "too_many_attempts" });
    }
    return res.status(400).json({ error: how === "totp" ? "invalid_code" : "passkey_failed", remaining: MAX_TOTP_FAILURES - s.totpFailures });
  };

  const unlockOk = (req: Request, res: Response, s: UserSession, how: "totp" | "passkey") => {
    s.totpFailures = 0;
    audit("lock.unlocked", { ip: ipOf(req), user: s.login, githubId: s.githubId, method: how });
    res.status(204).end();
  };

  app.post("/api/lock/totp", requireSession, requireSameOrigin, express.json({ limit: "1kb" }), (req, res) => {
    const s: UserSession = res.locals.session;
    if (!unlockLimiter.hit(s.id)) return res.status(429).json({ error: "rate_limited" });
    const entry = findUser(cfg, who(s));
    const code = String(req.body?.code ?? "").replace(/\s/g, "");
    const counter = entry ? verifyTotp(entry.totpKey, code, opts.now?.() ?? Date.now()) : undefined;
    if (counter === undefined || counter <= (lastTotpCounter.get(s.githubId) ?? -1)) return unlockFailed(req, res, s, "totp", "bad_code");
    lastTotpCounter.set(s.githubId, counter);
    unlockOk(req, res, s, "totp");
  });

  app.post("/api/lock/passkey/options", requireSession, requireSameOrigin, async (_req, res) => {
    const s: UserSession = res.locals.session;
    if (!unlockLimiter.hit(s.id)) return res.status(429).json({ error: "rate_limited" });
    const user = findUser(cfg, who(s));
    if (!user?.passkeys.length) return res.status(409).json({ error: "no_passkeys" });
    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: "required",
      allowCredentials: user.passkeys.map((p) => ({ id: p.id, transports: p.transports as never })),
      timeout: 120_000,
    });
    unlocks.put(options.challenge, s.id);
    res.json(options);
  });

  app.post("/api/lock/passkey/verify", requireSession, requireSameOrigin, express.json({ limit: "16kb" }), async (req, res) => {
    const s: UserSession = res.locals.session;
    if (!unlockLimiter.hit(s.id)) return res.status(429).json({ error: "rate_limited" });
    const challenge = unlocks.take(s.id);
    const response = req.body?.response;
    if (!challenge || !response || typeof response !== "object" || typeof response.id !== "string") return unlockFailed(req, res, s, "passkey", "bad_request");
    const user = findUser(cfg, who(s));
    const passkey = user?.passkeys.find((p) => p.id === response.id);
    if (!user || !passkey) return unlockFailed(req, res, s, "passkey", "unknown_credential");
    let verified;
    try {
      verified = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: cfg.server.publicUrl,
        expectedRPID: rpId,
        requireUserVerification: true,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(Buffer.from(passkey.publicKey, "base64url")),
          counter: passkey.counter,
          transports: passkey.transports as never,
        },
      });
    } catch {
      return unlockFailed(req, res, s, "passkey", "verification");
    }
    if (!verified.verified) return unlockFailed(req, res, s, "passkey", "not_verified");
    passkey.counter = verified.authenticationInfo.newCounter;
    passkey.lastUsedAt = Date.now();
    try { opts.passkeyStore?.save(user.match, user.passkeys); } catch {}
    unlockOk(req, res, s, "passkey");
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
    res.json({ via: s.method, canManagePasskeys: !!opts.passkeyStore, login: s.login, name: s.name, avatarUrl: s.avatarUrl, expiresAt: s.expiresAt, sealable: !!opts.onSeal, admin: isAdmin(cfg, who(s)), canAddHosts: !!opts.hostStore && isAdmin(cfg, who(s)), version: BUILD_VERSION, releaseNotesUrl: releaseNotesUrl(BUILD_VERSION) });
  });

  if (opts.onSeal) {
    app.post("/api/seal", requireSession, requireSameOrigin, (req, res) => {
      const s: UserSession = res.locals.session;
      audit("seal", { ip: ipOf(req), user: s.login, githubId: s.githubId });
      rec("vault_sealed", req, s.login, { detail: "Everyone signed out" });
      res.on("finish", () => setImmediate(opts.onSeal!));
      res.status(204).end();
    });
  }

  const passkeyRoute = (action: string, fn: (a: { req: Request; res: Response; s: UserSession; store: PasskeyStore; user: NonNullable<ReturnType<typeof findUser>> }) => Promise<void> | void) =>
    async (req: Request, res: Response) => {
      const s: UserSession = res.locals.session;
      if (!opts.passkeyStore) return res.status(409).json({ error: "storage_unavailable", message: "Passkeys cannot be saved on this server." });
      if (!passkeyLimiter.hit(String(s.githubId))) return res.status(429).json({ error: "rate_limited" });
      const user = findUser(cfg, who(s));
      if (!user) return res.status(403).json({ error: "forbidden" });
      try {
        await fn({ req, res, s, store: opts.passkeyStore, user });
      } catch (e) {
        if (!(e instanceof PasskeyError)) throw e;
        audit(`passkey.${action}_failed`, { ip: ipOf(req), user: s.login, githubId: s.githubId, error: e.code });
        res.status(e.status).json({ error: e.code, message: e.message });
      }
    };

  const publicPasskey = (p: { id: string; name: string; createdAt: number; lastUsedAt?: number }) => ({ id: p.id, name: p.name, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt ?? null });

  app.get("/api/passkeys", requireSession, (_req, res) => {
    const s: UserSession = res.locals.session;
    res.json((findUser(cfg, who(s))?.passkeys ?? []).map(publicPasskey));
  });

  app.post("/api/passkeys/register/options", requireSession, requireSameOrigin, passkeyRoute("register", async ({ res, s, user }) => {
    if (user.passkeys.length >= MAX_PASSKEYS_PER_USER) throw new PasskeyError(409, "too_many", `You can have up to ${MAX_PASSKEYS_PER_USER} passkeys. Remove one first.`);
    const options = await generateRegistrationOptions({
      rpName: "Shellport",
      rpID: rpId,
      userName: s.login,
      userDisplayName: s.name || s.login,
      userID: new Uint8Array(userHandle(user)),
      attestationType: "none",
      excludeCredentials: user.passkeys.map((p) => ({ id: p.id, transports: p.transports as never })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      timeout: 120_000,
    });
    registrations.put(options.challenge, s.id);
    res.json(options);
  }));

  app.post("/api/passkeys/register/verify", requireSession, requireSameOrigin, express.json({ limit: "16kb" }), passkeyRoute("register", async ({ req, res, s, store, user }) => {
    const challenge = registrations.take(s.id);
    if (!challenge) throw new PasskeyError(400, "expired", "That request expired. Start again.");
    const name = String(req.body?.name ?? "").replace(/[ -]/g, "").trim();
    if (!name || name.length > 40) throw new PasskeyError(400, "invalid", "Give the passkey a name of up to 40 characters.");
    if (user.passkeys.some((p) => p.name.toLowerCase() === name.toLowerCase())) throw new PasskeyError(409, "duplicate_name", "You already have a passkey with that name.");
    if (user.passkeys.length >= MAX_PASSKEYS_PER_USER) throw new PasskeyError(409, "too_many", `You can have up to ${MAX_PASSKEYS_PER_USER} passkeys. Remove one first.`);
    let info;
    try {
      const v = await verifyRegistrationResponse({
        response: req.body?.response,
        expectedChallenge: challenge,
        expectedOrigin: cfg.server.publicUrl,
        expectedRPID: rpId,
        requireUserVerification: true,
      });
      if (!v.verified || !v.registrationInfo) throw new Error("not verified");
      info = v.registrationInfo;
    } catch (e) {
      throw new PasskeyError(400, "verification_failed", "The passkey could not be verified. Try again.");
    }
    if (findPasskey(cfg, info.credential.id)) throw new PasskeyError(409, "duplicate", "That passkey is already registered.");
    const record = {
      id: info.credential.id,
      publicKey: Buffer.from(info.credential.publicKey).toString("base64url"),
      counter: info.credential.counter,
      transports: info.credential.transports as string[] | undefined,
      name,
      createdAt: Date.now(),
      githubId: s.githubId,
      login: s.login,
      displayName: s.name,
      avatarUrl: s.avatarUrl,
    };
    const before = user.passkeys;
    user.passkeys = [...before, record];
    try {
      store.save(user.match, user.passkeys);
    } catch (e) {
      user.passkeys = before;
      throw e;
    }
    audit("passkey.add", { ip: ipOf(req), user: s.login, githubId: s.githubId, name, store: store.kind });
    rec("passkey_added", req, s.login, { detail: name });
    res.status(201).json(publicPasskey(record));
  }));

  app.delete("/api/passkeys/:id", requireSession, requireSameOrigin, passkeyRoute("remove", ({ req, res, s, store, user }) => {
    const id = String(req.params.id);
    const target = user.passkeys.find((p) => p.id === id);
    if (!target) throw new PasskeyError(404, "not_found", "That passkey no longer exists.");
    const before = user.passkeys;
    user.passkeys = before.filter((p) => p !== target);
    try {
      store.save(user.match, user.passkeys);
    } catch (e) {
      user.passkeys = before;
      throw e;
    }
    audit("passkey.remove", { ip: ipOf(req), user: s.login, githubId: s.githubId, name: target.name, store: store.kind });
    rec("passkey_removed", req, s.login, { detail: target.name });
    res.status(204).end();
  }));

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
        return { ...base, method: a.method ?? "github", session: a.sid, current: a.sid === mine, active: !!l, expiresAt: l?.expiresAt };
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
        via: h.via ?? "",
      })),
    );
  });

  const auditFilter = (req: Request) => {
    const str = (v: unknown) => (typeof v === "string" && v ? v.slice(0, 120) : undefined);
    const days = Number(req.query.days);
    return {
      user: str(req.query.user),
      host: str(req.query.host),
      type: str(req.query.type),
      from: Number.isFinite(days) && days > 0 ? Date.now() - days * 86_400_000 : undefined,
    };
  };

  app.get("/api/audit", requireSession, requireAdmin, (req, res) => {
    const { items, total } = auditLog.query({ ...auditFilter(req), limit: Number(req.query.limit) || 50, offset: Number(req.query.offset) || 0 });
    res.json({ items, total, ...auditLog.choices(), groups: AUDIT_GROUPS, kinds: AUDIT_KINDS, status: auditLog.status() });
  });

  // Browser downloads and exports are navigations; refuse ones started from another site.
  const sameSiteDownload = (req: Request) => {
    const fetchSite = req.headers["sec-fetch-site"];
    return fetchSite === undefined || fetchSite === "same-origin" || fetchSite === "none";
  };

  app.get("/api/audit/export", requireSession, requireAdmin, (req, res) => {
    if (!sameSiteDownload(req)) return res.status(403).json({ error: "bad_origin" });
    const s: UserSession = res.locals.session;
    const entries = auditLog.all(auditFilter(req));
    audit("audit.export", { ip: ipOf(req), user: s.login, rows: entries.length });
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="shellport-audit.csv"');
    res.send(auditCsv(entries));
  });

  app.get("/api/recordings", requireSession, requireAdmin, (_req, res) => {
    const store = opts.recordings;
    res.json({
      items: store?.list() ?? [],
      status: store?.status() ?? { available: false, error: "Session recording is turned off (recording.enabled is false in config)", encrypted: false, retentionDays: cfg.recording.retentionDays, maxMB: cfg.recording.maxMB },
    });
  });

  app.get("/api/recordings/:id", requireSession, requireAdmin, (req, res) => {
    const s: UserSession = res.locals.session;
    const meta = opts.recordings?.get(String(req.params.id));
    if (!opts.recordings || !meta) return res.status(404).json({ error: "not_found" });
    const { text, unreadable } = opts.recordings.read(meta.id);
    rec("recording_viewed", req, s.login, { host: meta.host, detail: `Session by ${meta.user}` });
    res.type("text/plain; charset=utf-8");
    if (unreadable) res.setHeader("X-Unreadable-Lines", String(unreadable));
    res.send(text);
  });

  app.get("/api/recordings/:id/download", requireSession, requireAdmin, (req, res) => {
    if (!sameSiteDownload(req)) return res.status(403).json({ error: "bad_origin" });
    const s: UserSession = res.locals.session;
    const meta = opts.recordings?.get(String(req.params.id));
    if (!opts.recordings || !meta) return res.status(404).json({ error: "not_found" });
    const { text } = opts.recordings.read(meta.id);
    rec("recording_downloaded", req, s.login, { host: meta.host, detail: `Session by ${meta.user}` });
    const when = new Date(meta.startedAt).toISOString().replace(/[:.]/g, "-");
    res.setHeader("Content-Type", "application/x-asciicast; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="shellport-${meta.hostId}-${when}.cast"`);
    res.send(text);
  });

  app.delete("/api/recordings/:id", requireSession, requireAdmin, requireSameOrigin, (req, res) => {
    const s: UserSession = res.locals.session;
    const store = opts.recordings;
    const meta = store?.get(String(req.params.id));
    if (!store || !meta) return res.status(404).json({ error: "not_found" });
    if (meta.status === "recording") return res.status(409).json({ error: "recording_live" });
    store.remove(meta.id);
    rec("recording_deleted", req, s.login, { host: meta.host, detail: `Session by ${meta.user}` });
    res.json({ deleted: meta.id });
  });

  app.get("/api/keys", requireSession, requireAdmin, (_req, res) => {
    res.json(listKeys(cfg));
  });

  const hostRoute = (action: string, fn: (a: { req: Request; res: Response; s: UserSession; store: HostStore; body: Record<string, any> }) => Promise<void> | void) =>
    async (req: Request, res: Response) => {
      const s: UserSession = res.locals.session;
      if (!opts.hostStore) return res.status(409).json({ error: "storage_unavailable", message: "Hosts cannot be changed from the browser on this server." });
      if (!hostAddLimiter.hit(String(s.githubId))) return res.status(429).json({ error: "rate_limited" });
      const body = req.body && typeof req.body === "object" ? req.body : {};
      try {
        await fn({ req, res, s, store: opts.hostStore, body });
      } catch (e) {
        if (!(e instanceof HostAdminError)) throw e;
        audit(`host.${action}_failed`, { ip: ipOf(req), user: s.login, githubId: s.githubId, host: req.params.id, error: e.code });
        res.status(e.status).json({ error: e.code, message: e.message });
      }
    };

  const keySource = (body: Record<string, any>) =>
    body.key && typeof body.key === "object" ? ("upload" in body.key ? "uploaded" : "keep" in body.key ? "kept" : "existing") : "none";

  const target = (h: { username: string; host: string; port?: number }) => `${h.username}@${h.host}${h.port && h.port !== 22 ? `:${h.port}` : ""}`;
  const recordKey = (req: Request, s: UserSession, h: { name: string; auth: { type: string; keyName?: string; passphrase?: unknown } }, body: Record<string, any>) => {
    if (keySource(body) !== "uploaded" || h.auth.type !== "key") return;
    rec("key_uploaded", req, s.login, { host: h.name, detail: `${h.auth.keyName ?? "uploaded key"}${h.auth.passphrase === false ? " (no passphrase, confirmed)" : ""}` });
  };

  app.post("/api/hosts", requireSession, requireAdmin, requireSameOrigin, express.json({ limit: "32kb" }), hostRoute("add", async ({ req, res, s, store, body }) => {
    const host = await addHost(cfg, store, body as never, opts.probeHostKey);
    rec("host_added", req, s.login, { host: host.name, detail: target(host) });
    recordKey(req, s, host as never, body);
    audit("host.add", {
      ip: ipOf(req), user: s.login, githubId: s.githubId, host: host.id, target: `${host.username}@${host.host}:${host.port}`, via: host.via ?? "",
      key: keySource(body), store: store.kind,
    });
    res.status(201).json({ id: host.id });
  }));

  app.get("/api/hosts/:id", requireSession, requireAdmin, (req, res) => {
    try {
      res.json(describeHost(cfg, String(req.params.id)));
    } catch (e) {
      if (!(e instanceof HostAdminError)) throw e;
      res.status(e.status).json({ error: e.code, message: e.message });
    }
  });

  app.put("/api/hosts/:id", requireSession, requireAdmin, requireSameOrigin, express.json({ limit: "32kb" }), hostRoute("edit", async ({ req, res, s, store, body }) => {
    const host = await updateHost(cfg, store, String(req.params.id), body as never, opts.probeHostKey);
    rec("host_edited", req, s.login, { host: host.name, detail: target(host) });
    recordKey(req, s, host as never, body);
    audit("host.edit", {
      ip: ipOf(req), user: s.login, githubId: s.githubId, host: host.id, target: `${host.username}@${host.host}:${host.port}`, via: host.via ?? "",
      key: keySource(body), store: store.kind,
    });
    res.json({ id: host.id });
  }));

  app.delete("/api/hosts/:id", requireSession, requireAdmin, requireSameOrigin, hostRoute("delete", ({ req, res, s, store }) => {
    const host = removeHost(cfg, store, String(req.params.id));
    let closed = 0;
    for (const set of [...terminals.values()]) {
      for (const t of [...set]) {
        if (t.hostId !== host.id) continue;
        t.close("This host was removed");
        closed++;
      }
    }
    audit("host.delete", { ip: ipOf(req), user: s.login, githubId: s.githubId, host: host.id, closedTerminals: closed, store: store.kind });
    rec("host_deleted", req, s.login, { host: host.name, detail: `${target(host)}${closed ? `, ${closed} open ${closed === 1 ? "terminal" : "terminals"} closed` : ""}` });
    res.status(204).end();
  }));

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
    let url: URL;
    try {
      if (!req.url?.startsWith("/") || req.url.startsWith("//")) return reject(400, "Bad Request");
      url = new URL(req.url, "http://x");
    } catch {
      return reject(400, "Bad Request");
    }
    if (url.pathname !== "/ws") return reject(404, "Not Found");
    const ip = clientIp(req.socket.remoteAddress ?? "", String(req.headers["x-forwarded-for"] ?? ""), cfg.server.trustProxy);
    if (!apiLimiter.hit(ip)) return reject(429, "Too Many Requests");
    if (req.headers.origin !== cfg.server.publicUrl) return reject(403, "Forbidden");
    const s = getSession(req.headers.cookie);
    if (!s) return reject(401, "Unauthorized");
    const visible = hostsForUser(cfg, who(s));
    const host = visible.find((h) => h.id === url.searchParams.get("host"));
    if (!host) return reject(404, "Not Found");
    const route = host.via ? visible.find((h) => h.id === host.via) : undefined;
    if (host.via && !route) return reject(403, "Forbidden");
    const mine = terminals.get(s.githubId) ?? new Set();
    if (mine.size >= cfg.limits.maxTerminalsPerUser) return reject(429, "Too Many Requests");

    wss.handleUpgrade(req, socket, head, (ws) => {
      const set = terminals.get(s.githubId) ?? new Set<TerminalInfo>();
      terminals.set(s.githubId, set);
      const bySess = terminalsBySession.get(s.id) ?? new Set<TerminalInfo>();
      terminalsBySession.set(s.id, bySess);
      const t = openTerminal({
        ws, cfg, host, route, session: s, activity, auditLog, passphraseLimiter, recordings: opts.recordings, ip, timing: opts.timing,
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

  return { app, server, sessions, shutdown, auditLog };
}
