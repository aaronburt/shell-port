import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import crypto from "node:crypto";
import express, { type NextFunction, type Request, type Response } from "express";
import type { LoadedConfig } from "./config.js";
import { checkPassphraseStrength } from "./vault.js";
import { migrateToVaultKeyed } from "./vaultops.js";
import { UnsealLockout } from "./unseal.js";
import { audit } from "./log.js";

const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MAX_PASSPHRASE_LENGTH = 1024;

export interface MigrateOptions {
  configPath: string;
  vaultPath: string;
  publicDir: string;
  token: string;
  trustProxy?: boolean | number;
  lockout?: UnsealLockout;
  onMigrated: (cfg: LoadedConfig, dek: Buffer) => void;
  onSkip: () => void;
}

function sameToken(given: unknown, expected: string): boolean {
  if (typeof given !== "string") return false;
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

export function createMigrateApp(opts: MigrateOptions) {
  const lockout = opts.lockout ?? new UnsealLockout();
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", opts.trustProxy ?? false);

  app.use((req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      ["default-src 'self'", "script-src 'self'", "style-src 'self'", "font-src 'self'", "img-src 'self' data:", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'"].join("; "),
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    if (!req.path.startsWith("/assets/")) res.setHeader("Cache-Control", "no-store");
    next();
  });

  const hostName = (req: Request) => (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();

  const requireSameOrigin = (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.headers.origin && new URL(req.headers.origin).host === req.headers.host) return next();
    } catch {}
    res.status(403).json({ error: "bad_origin" });
  };

  const requireToken = (req: Request, res: Response, next: NextFunction) => {
    const wait = lockout.retryAfterMs();
    if (wait > 0) {
      const seconds = Math.ceil(wait / 1000);
      res.setHeader("Retry-After", String(seconds));
      return res.status(429).json({ error: "locked", retryAfter: seconds });
    }
    if (!sameToken(req.body?.token, opts.token)) {
      lockout.fail();
      audit("migrate.bad_token", { ip: req.ip });
      return res.status(401).json({ error: "bad_token" });
    }
    next();
  };

  const body = express.json({ limit: "4kb" });

  app.get("/healthz", (_req, res) => res.json({ ok: true, migrate: true }));
  app.get("/", (_req, res) => res.sendFile(path.join(opts.publicDir, "migrate.html")));
  app.get("/api/migrate/status", (_req, res) => {
    const dir = path.dirname(path.resolve(opts.vaultPath));
    let reason: "missing" | "readonly" | undefined;
    if (!fs.existsSync(dir)) reason = "missing";
    else {
      try {
        fs.accessSync(dir, fs.constants.W_OK);
      } catch {
        reason = "readonly";
      }
    }
    res.json({ configPath: opts.configPath, vaultPath: path.resolve(opts.vaultPath), writable: !reason, reason });
  });

  app.post("/api/migrate", requireSameOrigin, body, requireToken, (req, res) => {
    const secure = req.secure || LOOPBACK.has(req.ip ?? "") || LOCAL_HOSTS.has(hostName(req));
    if (!secure) return res.status(403).json({ error: "https_required" });
    const passphrase = req.body?.passphrase;
    if (typeof passphrase !== "string" || !passphrase || passphrase.length > MAX_PASSPHRASE_LENGTH) {
      return res.status(400).json({ error: "bad_request" });
    }
    const weak = checkPassphraseStrength(passphrase);
    if (weak) return res.status(400).json({ error: "weak_passphrase", message: weak });
    let cfg: LoadedConfig;
    let dek: Buffer;
    try {
      ({ cfg, dek } = migrateToVaultKeyed({ configPath: opts.configPath, vaultPath: opts.vaultPath, passphrase }));
    } catch (e) {
      audit("migrate.failed", { error: (e as Error).message });
      return res.status(422).json({ error: "migrate_failed", message: (e as Error).message });
    }
    lockout.succeed();
    audit("migrate.ok", { vault: opts.vaultPath });
    res.on("finish", () => setImmediate(() => opts.onMigrated(cfg, dek)));
    res.status(204).end();
  });

  app.post("/api/migrate/skip", requireSameOrigin, body, requireToken, (_req, res) => {
    lockout.succeed();
    audit("migrate.skipped", {});
    res.on("finish", () => setImmediate(opts.onSkip));
    res.status(204).end();
  });

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

  let stopping: Promise<void> | undefined;
  const shutdown = (deadlineMs = 5000, reason = "shutdown"): Promise<void> =>
    (stopping ??= new Promise<void>((resolve) => {
      audit("migrate.stop", { reason });
      const done = () => {
        clearTimeout(deadline);
        resolve();
      };
      const deadline = setTimeout(() => {
        server.closeAllConnections();
        done();
      }, deadlineMs);
      server.close(() => done());
      server.closeIdleConnections();
    }));

  return { app, server, shutdown, lockout };
}
