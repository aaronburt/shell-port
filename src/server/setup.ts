import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import express, { type Request, type Response, type NextFunction } from "express";
import QRCode from "qrcode";
import { newSecret, otpauthUri, base32Decode } from "./totp.js";
import { loadConfig, loadSealedConfig, type LoadedConfig } from "./config.js";
import { checkPassphraseStrength, sealVault } from "./vault.js";
import { inlineSecrets, writeFileAtomic } from "./vaultops.js";
import { audit } from "./log.js";

export interface SetupValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateSetupConfig(raw: any): SetupValidationResult {
  const errors: string[] = [];
  if (!raw || typeof raw !== "object") return { valid: false, errors: ["Configuration must be a JSON object"] };

  const server = raw.server;
  if (!server || typeof server !== "object") {
    errors.push("server configuration object is required");
  } else {
    if (typeof server.port !== "number" || !Number.isInteger(server.port) || server.port < 1 || server.port > 65535) {
      errors.push("server.port must be an integer from 1 to 65535");
    }
    if (typeof server.host !== "string" || !server.host.trim()) {
      errors.push("server.host is required");
    }
    const publicUrl = String(server.publicUrl ?? "").replace(/\/+$/, "");
    if (!/^https?:\/\/[^/]+$/.test(publicUrl)) {
      errors.push("server.publicUrl must be an origin like http://localhost:8080 or https://ssh.example.com");
    }
  }

  const github = raw.github;
  if (!github || typeof github !== "object") {
    errors.push("github configuration object is required");
  } else {
    if (!github.clientId || typeof github.clientId !== "string" || !github.clientId.trim()) {
      errors.push("github.clientId is required");
    }
    if (!github.clientSecret) {
      errors.push("github.clientSecret is required");
    } else if (typeof github.clientSecret !== "string" && (!github.clientSecret.env && !github.clientSecret.file)) {
      errors.push("github.clientSecret must be a string or an object with 'env' or 'file'");
    }
  }

  if (!Array.isArray(raw.users) || !raw.users.length) {
    errors.push("users must list at least one user with GitHub ID/login and TOTP secret");
  } else {
    raw.users.forEach((u: any, i: number) => {
      const g = String(u?.github ?? "").trim().toLowerCase();
      if (!/^[a-z0-9-]{1,39}$/.test(g)) {
        errors.push(`users[${i}].github must be a valid GitHub login or numeric ID`);
      }
      if (!u?.totpSecret) {
        errors.push(`users[${i}].totpSecret is required`);
      } else if (typeof u.totpSecret === "string") {
        try {
          const dec = base32Decode(u.totpSecret);
          if (dec.length < 16) errors.push(`users[${i}].totpSecret is too short (need at least 128 bits)`);
        } catch {
          errors.push(`users[${i}].totpSecret is not valid Base32`);
        }
      } else if (!u.totpSecret.env && !u.totpSecret.file) {
        errors.push(`users[${i}].totpSecret must be a string or an object with 'env' or 'file'`);
      }
    });
  }

  const hosts = raw.hosts;
  if (!Array.isArray(hosts) || !hosts.length) {
    errors.push("hosts must list at least one SSH host");
  } else {
    const seen = new Set<string>();
    const idRe = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;
    hosts.forEach((h: any, i: number) => {
      if (!h?.id || !idRe.test(h.id)) {
        errors.push(`hosts[${i}].id must be 1-64 characters matching ${idRe}`);
      } else if (seen.has(h.id)) {
        errors.push(`duplicate host id '${h.id}'`);
      } else {
        seen.add(h.id);
      }
      if (!h?.host || typeof h.host !== "string" || !h.host.trim()) {
        errors.push(`host '${h?.id || i}': host is required`);
      }
      if (!h?.username || typeof h.username !== "string" || !h.username.trim()) {
        errors.push(`host '${h?.id || i}': username is required`);
      }
      if (h?.port !== undefined && (typeof h.port !== "number" || !Number.isInteger(h.port) || h.port < 1 || h.port > 65535)) {
        errors.push(`host '${h?.id || i}': port must be an integer from 1 to 65535`);
      }
      if (!h?.auth || !["key", "password"].includes(h.auth.type)) {
        errors.push(`host '${h?.id || i}': auth.type must be 'key' or 'password'`);
      }
      if (!raw?.security?.allowUnpinnedHostKeys && (!Array.isArray(h?.hostKeyFingerprints) || !h.hostKeyFingerprints.length)) {
        errors.push(`host '${h?.id || i}': hostKeyFingerprints is required unless security.allowUnpinnedHostKeys is true`);
      }
    });
  }

  return { valid: errors.length === 0, errors };
}

export function isPathWritable(targetPath: string): boolean {
  try {
    const resolved = path.resolve(targetPath);
    if (fs.existsSync(resolved)) {
      fs.accessSync(resolved, fs.constants.W_OK);
      return true;
    }
    const dir = path.dirname(resolved);
    if (fs.existsSync(dir)) {
      fs.accessSync(dir, fs.constants.W_OK);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export interface SetupAppOptions {
  configPath: string;
  publicDir: string;
  vaultPath?: string;
  trustProxy?: boolean | number;
  onSaved?: (cfg: LoadedConfig, vaultPath?: string) => void;
}

export function createSetupApp(opts: SetupAppOptions) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", opts.trustProxy ?? false);

  app.use((req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
      ].join("; "),
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, setup: true });
  });

  app.get(["/", "/setup"], (_req, res) => {
    res.sendFile(path.join(opts.publicDir, "setup.html"));
  });

  app.get("/api/setup/status", (_req, res) => {
    res.json({
      configPath: opts.configPath,
      exists: fs.existsSync(opts.configPath),
      writable: isPathWritable(opts.configPath),
      vaultPath: opts.vaultPath,
      vaultWritable: Boolean(opts.vaultPath) && !fs.existsSync(opts.vaultPath!) && isPathWritable(opts.vaultPath!),
    });
  });

  app.post("/api/setup/totp", express.json({ limit: "16kb" }), async (req, res) => {
    try {
      const account = String(req.body?.account ?? "").trim() || "user";
      const issuer = String(req.body?.issuer ?? "").trim() || "Shellport";
      const secret = newSecret();
      const uri = otpauthUri(secret, account, issuer);
      const qr = await QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 1, width: 220 });
      res.json({ secret, uri, qr });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  app.post("/api/setup/validate", express.json({ limit: "128kb" }), (req, res) => {
    const result = validateSetupConfig(req.body);
    res.json(result);
  });

  app.post("/api/setup/save", express.json({ limit: "128kb" }), (req, res) => {
    const wrapped = req.body && typeof req.body === "object" && req.body.config && typeof req.body.config === "object";
    const config = wrapped ? req.body.config : req.body;
    const passphrase = wrapped && typeof req.body.passphrase === "string" && req.body.passphrase ? req.body.passphrase : undefined;
    const result = validateSetupConfig(config);
    if (!result.valid) {
      return res.status(400).json({ ok: false, errors: result.errors });
    }

    if (passphrase !== undefined) {
      if (!opts.vaultPath) return res.status(400).json({ ok: false, error: "Sealing is not available here." });
      if (!req.secure && !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.ip ?? ""))
        return res.status(403).json({ ok: false, error: "A passphrase can only be sent over HTTPS or from the local machine." });
      const weak = checkPassphraseStrength(passphrase);
      if (weak) return res.status(400).json({ ok: false, error: weak });
      if (fs.existsSync(opts.vaultPath)) return res.status(409).json({ ok: false, error: `${opts.vaultPath} already exists.` });
      let sealed: LoadedConfig;
      let json: string;
      try {
        json = JSON.stringify(inlineSecrets(config, path.dirname(path.resolve(opts.configPath))), null, 2);
        sealed = loadSealedConfig(json);
      } catch (e) {
        return res.status(400).json({ ok: false, error: (e as Error).message });
      }
      try {
        const dir = path.dirname(path.resolve(opts.vaultPath));
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        writeFileAtomic(path.resolve(opts.vaultPath), sealVault(json, passphrase));
      } catch (e) {
        return res.status(403).json({ ok: false, readOnly: true, error: `Cannot write to ${opts.vaultPath}: ${(e as Error).message}` });
      }
      audit("setup.sealed", { path: opts.vaultPath });
      res.json({ ok: true, saved: true, sealed: true, canTransition: Boolean(opts.onSaved) });
      if (opts.onSaved) setTimeout(() => opts.onSaved?.(sealed, opts.vaultPath), 500);
      return;
    }

    try {
      const resolved = path.resolve(opts.configPath);
      const dir = path.dirname(resolved);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(resolved, JSON.stringify(config, null, 2) + "\n", "utf8");
    } catch (e) {
      return res.status(403).json({
        ok: false,
        readOnly: true,
        error: `Cannot write to ${opts.configPath}: ${(e as Error).message}`,
      });
    }

    audit("setup.saved", { path: opts.configPath });

    let loaded: LoadedConfig | undefined;
    try {
      loaded = loadConfig(opts.configPath);
    } catch (e) {
      audit("setup.load_error", { error: (e as Error).message });
    }

    res.json({
      ok: true,
      saved: true,
      canTransition: Boolean(loaded && opts.onSaved),
    });

    if (loaded && opts.onSaved) {
      setTimeout(() => opts.onSaved?.(loaded!), 500);
    }
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
      audit("setup.stop", { reason });
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

  return { app, server, shutdown };
}

