import crypto from "node:crypto";
import ssh2, { Client, type ConnectConfig, type ClientChannel } from "ssh2";
import type { Socket } from "node:net";
import type { WebSocket, RawData } from "ws";
import { resolveSecret, hostNeedsPassphrase, type HostConfig, type LoadedConfig } from "./config.js";
import type { RateLimiter, UserSession } from "./sessions.js";
import { audit } from "./log.js";
import type { ActivityLog } from "./activity.js";

const HIGH_WATER = 1 << 20;
const PASSPHRASE_TRIES = 3;
const PASSPHRASE_WAIT_MS = 120_000;
const MAX_PASSPHRASE_LEN = 1024;
const DRAIN_POLL_MS = 25;

export interface TerminalTiming {
  passphraseWaitMs?: number;
  idleTimeoutMs?: number;
}

export interface TerminalInfo {
  user: string;
  hostId: string;
  close(reason: string): void;
}

function fingerprint(key: Buffer): string {
  return "SHA256:" + crypto.createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
}

function clampDim(n: unknown, def: number, max: number) {
  const v = Math.floor(Number(n));
  return Number.isFinite(v) && v > 0 ? Math.min(v, max) : def;
}

function formatDuration(ms: number): string {
  if (ms >= 60_000) return `${Math.round(ms / 60_000)} minutes`;
  return `${Math.round(ms / 1000)} seconds`;
}

function friendlyError(err: Error & { level?: string; code?: string }, mismatch: boolean): string {
  if (mismatch) return "Host key did not match the pinned fingerprint. Connection refused.";
  if (err.level === "client-authentication") return "The server rejected the configured credentials.";
  if (err.level === "client-timeout") return "Timed out connecting to the host.";
  if (err.code === "ECONNREFUSED") return "Connection refused by the host.";
  if (err.code === "ENOTFOUND" || err.code === "EAI_AGAIN") return "Host name could not be resolved.";
  if (err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH") return "Host is unreachable.";
  if (err.code === "ETIMEDOUT") return "Timed out connecting to the host.";
  return "SSH connection failed.";
}

export function openTerminal(opts: {
  ws: WebSocket;
  cfg: LoadedConfig;
  host: HostConfig;
  session: UserSession;
  activity: ActivityLog;
  passphraseLimiter: RateLimiter;
  ip: string;
  timing?: TerminalTiming;
  cols: unknown;
  rows: unknown;
  onClose: () => void;
}): TerminalInfo {
  const { ws, cfg, host, session, ip } = opts;
  const send = (msg: object) => ws.readyState === ws.OPEN && ws.send(JSON.stringify(msg));
  const started = Date.now();
  let lastActivity = Date.now();
  let stream: ClientChannel | undefined;
  let size = { cols: clampDim(opts.cols, 80, 500), rows: clampDim(opts.rows, 24, 200) };
  let closed = false;
  let bytesIn = 0;
  let bytesOut = 0;
  let mismatch = false;
  let awaitingPassphrase = false;
  let passphraseTries = 0;
  let passphraseTimer: NodeJS.Timeout | undefined;
  let drainTimer: NodeJS.Timeout | undefined;
  let inputPaused = false;

  const ssh = new Client();
  const auditBase = { user: session.login, host: host.id, ip };

  const close = (reason: string) => {
    if (closed) return;
    closed = true;
    clearInterval(timer);
    clearTimeout(passphraseTimer);
    clearInterval(drainTimer);
    try { stream?.close(); } catch {}
    ssh.end();
    send({ t: "status", state: "closed", reason });
    if (ws.readyState === ws.OPEN) ws.close(1000, reason.slice(0, 120));
    audit("terminal.close", { ...auditBase, reason, seconds: Math.round((Date.now() - started) / 1000), bytesIn, bytesOut });
    opts.onClose();
  };

  const timer = setInterval(() => {
    const idleMs = opts.timing?.idleTimeoutMs ?? cfg.limits.idleTimeoutMinutes * 60_000;
    if (idleMs > 0 && Date.now() - lastActivity > idleMs) close(`Closed after ${formatDuration(idleMs)} idle`);
  }, 1000);

  const conn: ConnectConfig = {
    host: host.host,
    port: host.port,
    username: host.username,
    readyTimeout: 15_000,
    keepaliveInterval: 20_000,
    keepaliveCountMax: 3,
    hostVerifier: (key: Buffer) => {
      if (!host.hostKeyFingerprints?.length) return cfg.security.allowUnpinnedHostKeys;
      const fp = fingerprint(key);
      const ok = host.hostKeyFingerprints.some((p) => p.replace(/=+$/, "") === fp);
      if (!ok) {
        mismatch = true;
        audit("terminal.hostkey_mismatch", { ...auditBase, presented: fp });
      }
      return ok;
    },
  };
  const needsPassphrase = hostNeedsPassphrase(host);
  let keyText: string | undefined;
  try {
    if (host.auth.type === "key") {
      keyText = resolveSecret(host.auth.privateKey, cfg.baseDir, "privateKey", true);
      if (!needsPassphrase) {
        conn.privateKey = keyText;
        if (host.auth.passphrase) conn.passphrase = resolveSecret(host.auth.passphrase, cfg.baseDir, "passphrase");
      }
    } else {
      conn.password = resolveSecret(host.auth.password, cfg.baseDir, "password");
    }
  } catch (e) {
    audit("terminal.error", { ...auditBase, error: (e as Error).message });
    send({ t: "error", message: "This host's credentials are misconfigured on the server." });
    queueMicrotask(() => close("Configuration error"));
    return { user: session.login, hostId: host.id, close };
  }

  let cipher = "";
  ssh.on("handshake", (n) => {
    cipher = n.cs.cipher;
  });

  ssh.on("ready", () => {
    ssh.shell({ term: "xterm-256color", ...size }, (err, s) => {
      if (err) {
        send({ t: "error", message: "The host refused to open a shell." });
        return close("Shell refused");
      }
      stream = s;
      audit("terminal.open", auditBase);
      send({
        t: "status",
        state: "connected",
        info: {
          host: `${host.host}:${host.port}`,
          user: host.username,
          auth: host.auth.type === "key"
            ? needsPassphrase ? "key, passphrase entered in browser" : "server-managed key"
            : "server-managed password",
          cipher,
          hostKey: host.hostKeyFingerprints?.length ? "pinned" : "not pinned",
          since: new Date().toISOString(),
        },
      });
      const onData = (d: Buffer) => {
        lastActivity = Date.now();
        bytesOut += d.length;
        if (ws.readyState !== ws.OPEN) return;
        ws.send(d);
        if (ws.bufferedAmount > HIGH_WATER && !drainTimer) {
          s.pause();
          drainTimer = setInterval(() => {
            if (ws.bufferedAmount >= HIGH_WATER / 4) return;
            clearInterval(drainTimer);
            drainTimer = undefined;
            s.resume();
          }, DRAIN_POLL_MS);
        }
      };
      s.on("data", onData);
      s.stderr.on("data", onData);
      s.on("close", () => close("Session ended"));
    });
  });

  ssh.on("error", (err) => {
    if (closed) return;
    audit("terminal.error", { ...auditBase, error: err.message });
    send({ t: "error", message: friendlyError(err, mismatch) });
    close("Connection failed");
  });
  ssh.on("close", () => close("Connection closed"));

  ws.on("message", (data: RawData, isBinary: boolean) => {
    if (isBinary) {
      if (!stream) return;
      const buf = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data);
      lastActivity = Date.now();
      bytesIn += buf.length;
      if (!stream.write(buf) && !inputPaused) {
        const socket = (ws as unknown as { _socket?: Socket })._socket;
        if (socket) {
          inputPaused = true;
          socket.pause();
          stream.once("drain", () => {
            inputPaused = false;
            socket.resume();
          });
        }
      }
      return;
    }
    let msg: any;
    try { msg = JSON.parse(data.toString()); } catch { return; }
    if (msg?.t === "passphrase") {
      if (!awaitingPassphrase) return;
      return submitPassphrase(typeof msg.value === "string" ? msg.value : "");
    }
    if (msg?.t === "resize") {
      size = { cols: clampDim(msg.cols, size.cols, 500), rows: clampDim(msg.rows, size.rows, 200) };
      stream?.setWindow(size.rows, size.cols, 0, 0);
    }
  });
  ws.on("close", () => close("Browser disconnected"));
  ws.on("error", () => close("Browser connection error"));

  function askPassphrase(retry: boolean, restartTimer = true) {
    awaitingPassphrase = true;
    if (restartTimer) {
      clearTimeout(passphraseTimer);
      passphraseTimer = setTimeout(() => {
        send({ t: "error", message: "No passphrase was entered in time." });
        close("Passphrase timeout");
      }, opts.timing?.passphraseWaitMs ?? PASSPHRASE_WAIT_MS);
    }
    send({ t: "passphrase", retry, remaining: PASSPHRASE_TRIES - passphraseTries });
  }

  function failPassphrase(restartTimer: boolean) {
    passphraseTries++;
    audit("terminal.passphrase_failed", { ...auditBase, attempt: passphraseTries });
    opts.activity.add({ kind: "passphrase_failed", githubId: session.githubId, ip, host: host.id });
    if (passphraseTries >= PASSPHRASE_TRIES) {
      send({ t: "error", message: "Incorrect passphrase." });
      return close("Incorrect passphrase");
    }
    askPassphrase(true, restartTimer);
  }

  function submitPassphrase(value: string) {
    if (!opts.passphraseLimiter.hit(`${session.githubId}:${host.id}`)) {
      audit("terminal.passphrase_throttled", auditBase);
      send({ t: "error", message: "Too many incorrect passphrases. Try again later." });
      return close("Passphrase attempts throttled");
    }
    if (!value || value.length > MAX_PASSPHRASE_LEN) return failPassphrase(false);
    awaitingPassphrase = false;
    clearTimeout(passphraseTimer);
    const parsed = ssh2.utils.parseKey(keyText!, value);
    const key = Array.isArray(parsed) ? parsed[0] : parsed;
    if (key instanceof Error || !key) return failPassphrase(true);
    conn.privateKey = keyText;
    conn.passphrase = value;
    send({ t: "status", state: "connecting" });
    ssh.connect(conn);
    conn.passphrase = undefined;
    keyText = undefined;
  }

  send({ t: "status", state: "connecting" });
  if (needsPassphrase) askPassphrase(false);
  else ssh.connect(conn);

  return { user: session.login, hostId: host.id, close };
}
