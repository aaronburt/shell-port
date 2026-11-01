import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { openVaultKeyed, VaultError } from "./vault.js";
import { audit } from "./log.js";

const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
const MAX_PASSPHRASE_LENGTH = 1024;
const LOCK_STEPS_MS = [60_000, 120_000, 300_000, 900_000];

export class UnsealLockout {
  private failures = 0;
  private level = 0;
  private until = 0;

  constructor(
    private before = 5,
    private steps: number[] = LOCK_STEPS_MS,
    private now: () => number = Date.now,
  ) {}

  retryAfterMs(): number {
    return Math.max(0, this.until - this.now());
  }

  remaining(): number {
    return this.before - this.failures;
  }

  fail() {
    this.failures++;
    if (this.failures >= this.before) {
      this.until = this.now() + this.steps[Math.min(this.level, this.steps.length - 1)];
      this.level++;
      this.failures = 0;
    }
  }

  succeed() {
    this.failures = 0;
    this.level = 0;
    this.until = 0;
  }
}

export interface UnsealOptions {
  vaultPath: string;
  publicDir: string;
  trustProxy?: boolean | number;
  socketPath?: string;
  lockout?: UnsealLockout;
  onUnsealed: (plaintext: Buffer, dek: Buffer) => () => void;
}

export function createUnsealApp(opts: UnsealOptions) {
  const lockout = opts.lockout ?? new UnsealLockout();
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", opts.trustProxy ?? false);

  app.use((req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
      ].join("; "),
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    if (!req.path.startsWith("/assets/")) res.setHeader("Cache-Control", "no-store");
    next();
  });

  const viaSocket = (req: Request) => (req as Request & { viaSocket?: boolean }).viaSocket === true;

  const requireSecure = (req: Request, res: Response, next: NextFunction) =>
    viaSocket(req) || req.secure || LOOPBACK.has(req.ip ?? "") ? next() : res.status(403).json({ error: "https_required" });

  const requireSameOrigin = (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.headers.origin && new URL(req.headers.origin).host === req.headers.host) return next();
    } catch {}
    res.status(403).json({ error: "bad_origin" });
  };

  app.get("/healthz", (_req, res) => res.json({ ok: true, sealed: true }));

  app.get("/", (_req, res) => res.sendFile(path.join(opts.publicDir, "unseal.html")));

  app.post("/api/unseal", requireSecure, requireSameOrigin, express.json({ limit: "2kb" }), (req, res) => {
    const ip = req.ip ?? "";
    const local = viaSocket(req);
    const wait = local ? 0 : lockout.retryAfterMs();
    if (wait > 0) {
      const seconds = Math.ceil(wait / 1000);
      res.setHeader("Retry-After", String(seconds));
      audit("unseal.locked", { ip, seconds });
      return res.status(429).json({ error: "locked", retryAfter: seconds });
    }
    const passphrase = req.body?.passphrase;
    if (typeof passphrase !== "string" || !passphrase || passphrase.length > MAX_PASSPHRASE_LENGTH) {
      return res.status(400).json({ error: "bad_request" });
    }

    let plain: Buffer;
    let dek: Buffer;
    try {
      ({ plain, dek } = openVaultKeyed(fs.readFileSync(opts.vaultPath), passphrase));
    } catch (e) {
      if (e instanceof VaultError && e.code === "bad_passphrase") {
        if (!local) lockout.fail();
        const seconds = Math.ceil(lockout.retryAfterMs() / 1000);
        audit("unseal.failed", { ip, lockedSeconds: seconds || undefined });
        if (seconds) res.setHeader("Retry-After", String(seconds));
        return res.status(401).json({ error: "invalid_passphrase", remaining: lockout.remaining(), retryAfter: seconds || undefined });
      }
      audit("unseal.error", { ip, error: (e as Error).message });
      return res.status(500).json({ error: "vault_unusable" });
    }

    let start: () => void;
    try {
      start = opts.onUnsealed(plain, dek);
    } catch (e) {
      dek.fill(0);
      audit("unseal.config_invalid", { ip, error: (e as Error).message });
      return res.status(422).json({ error: "config_invalid", message: (e as Error).message });
    } finally {
      plain.fill(0);
    }

    lockout.succeed();
    audit("unseal.ok", { ip: local ? "local-socket" : ip });
    res.on("finish", () => setImmediate(start));
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

  const socketServer = opts.socketPath
    ? http.createServer((req, res) => {
        (req as http.IncomingMessage & { viaSocket?: boolean }).viaSocket = true;
        app(req, res);
      })
    : undefined;

  const listenSocket = (): Promise<void> =>
    new Promise((resolve) => {
      if (!socketServer || !opts.socketPath) return resolve();
      try { fs.rmSync(opts.socketPath, { force: true }); } catch {}
      socketServer.once("error", () => resolve());
      socketServer.listen(opts.socketPath, () => {
        try { fs.chmodSync(opts.socketPath!, 0o600); } catch {}
        resolve();
      });
    });

  let stopping: Promise<void> | undefined;
  const shutdown = (deadlineMs = 5000, reason = "shutdown"): Promise<void> =>
    (stopping ??= new Promise<void>((resolve) => {
      audit("unseal.stop", { reason });
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
      if (socketServer) {
        socketServer.close();
        socketServer.closeAllConnections();
        try { fs.rmSync(opts.socketPath!, { force: true }); } catch {}
      }
    }));

  return { app, server, shutdown, lockout, listenSocket };
}
