import crypto from "node:crypto";
import { Client, type ClientChannel, type ConnectConfig, type SFTPWrapper } from "ssh2";
import type { Socket } from "node:net";
import type { WebSocket, RawData } from "ws";
import type { HostConfig, LoadedConfig } from "./config.js";
import { addrOf, fingerprint, hopAuth, keyPinned, type HopAuth } from "./hop.js";
import type { RateLimiter, UserSession } from "./sessions.js";
import { audit } from "./log.js";
import type { ActivityLog } from "./activity.js";
import type { AuditLog } from "./auditlog.js";
import { FileError } from "./sftp.js";
import { RecordingError, type LiveRecording, type RecordingStore } from "./recording.js";

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
  id: string;
  user: string;
  hostId: string;
  files: boolean;
  sftp(): Promise<SFTPWrapper>;
  touch(): void;
  close(reason: string): void;
}

type Role = "bastion" | "target";
type FailureStage = "connection" | "host-key" | "authentication" | "shell" | "configuration" | "passphrase" | "recording";

function errorStage(err: Error & { level?: string }, mismatch: boolean): FailureStage {
  if (mismatch) return "host-key";
  if (err.level === "client-authentication") return "authentication";
  return "connection";
}

interface Hop {
  role: Role;
  host: HostConfig;
  client: Client;
  auth: HopAuth;
  tries: number;
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
  route?: HostConfig;
  session: UserSession;
  activity: ActivityLog;
  auditLog: AuditLog;
  passphraseLimiter: RateLimiter;
  recordings?: RecordingStore;
  ip: string;
  timing?: TerminalTiming;
  cols: unknown;
  rows: unknown;
  onClose: () => void;
}): TerminalInfo {
  const { ws, cfg, host, route, session, ip } = opts;
  const send = (msg: object) => ws.readyState === ws.OPEN && ws.send(JSON.stringify(msg));
  const failure = (message: string, stage: FailureStage, role: Role = "target") =>
    send({ t: "error", message, diagnostic: { stage, role } });
  const started = Date.now();
  let lastActivity = Date.now();
  let stream: ClientChannel | undefined;
  let size = { cols: clampDim(opts.cols, 80, 500), rows: clampDim(opts.rows, 24, 200) };
  let closed = false;
  let bytesIn = 0;
  let bytesOut = 0;
  let mismatch = false;
  let awaiting: Hop | undefined;
  let passphraseTimer: NodeJS.Timeout | undefined;
  let drainTimer: NodeJS.Timeout | undefined;
  let inputPaused = false;
  let connectStart = 0;
  let bastionUp = false;
  let opened = false;
  let recording: LiveRecording | undefined;
  let recordingError: string | undefined;
  const phases: Record<string, number> = {};
  const mark = (name: string) => { phases[name] = Date.now() - connectStart; };

  const id = crypto.randomBytes(16).toString("base64url");
  let ready = false;
  let sftpPromise: Promise<SFTPWrapper> | undefined;
  const files = host.files !== false;
  const sftp = (): Promise<SFTPWrapper> => {
    if (!files) return Promise.reject(new FileError(403, "files_disabled"));
    if (!ready || closed) return Promise.reject(new FileError(409, "not_connected"));
    sftpPromise ??= new Promise<SFTPWrapper>((resolve, reject) => {
      ssh.sftp((err, s) => {
        if (err) {
          sftpPromise = undefined;
          return reject(new FileError(502, "sftp_unavailable"));
        }
        s.on("close", () => { sftpPromise = undefined; });
        resolve(s);
      });
    });
    return sftpPromise;
  };
  const touch = () => { lastActivity = Date.now(); };
  const handle: TerminalInfo = { id, user: session.login, hostId: host.id, files, sftp, touch, close: (reason) => close(reason) };

  const ssh = new Client();
  const bastion = route ? new Client() : undefined;
  const auditFor = (h: HostConfig) => ({ user: session.login, host: h.id, ip });
  const trail = (kind: Parameters<AuditLog["add"]>[0]["kind"], detail: string, h: HostConfig = host, ref?: string) =>
    opts.auditLog.add({ kind, user: session.login, ip, host: h.name, detail, ref });

  // Stops the session because its recording could not be written. The chunk that failed is never forwarded.
  const recordingFailed = (e: unknown) => {
    if (closed) return;
    const limit = e instanceof RecordingError && e.code === "limit";
    const detail = (e as Error).message ?? String(e);
    recordingError = detail;
    audit("terminal.recording_failed", { ...auditFor(host), error: detail });
    trail("recording_failed", limit ? "Recording reached its size limit, session closed" : "Recording could not be saved, session closed");
    send({
      t: "error",
      message: limit
        ? "This session reached its recording size limit, so it was closed."
        : "Session recording failed, so the session was closed to keep the record complete.",
    });
    close("Recording stopped");
  };

  const close = (reason: string) => {
    if (closed) return;
    closed = true;
    clearInterval(timer);
    clearTimeout(passphraseTimer);
    clearInterval(drainTimer);
    try { stream?.close(); } catch {}
    ssh.end();
    bastion?.end();
    send({ t: "status", state: "closed", reason });
    if (ws.readyState === ws.OPEN) ws.close(1000, reason.slice(0, 120));
    audit("terminal.close", { ...auditFor(host), reason, seconds: Math.round((Date.now() - started) / 1000), bytesIn, bytesOut });
    if (opened) trail("ssh_disconnect", `${reason}. Lasted ${formatDuration(Date.now() - started)}`);
    if (route && bastionUp) trail("ssh_disconnect", `${reason}. Lasted ${formatDuration(Date.now() - started)}`, route);
    recording?.finish(recordingError ? "failed" : "complete", recordingError ?? reason);
    opts.onClose();
  };

  const timer = setInterval(() => {
    const idleMs = opts.timing?.idleTimeoutMs ?? cfg.limits.idleTimeoutMinutes * 60_000;
    if (idleMs > 0 && Date.now() - lastActivity > idleMs) close(`Closed after ${formatDuration(idleMs)} idle`);
  }, 1000);

  const hopFor = (role: Role, h: HostConfig, client: Client): Hop => {
    const auth = hopAuth(h, cfg.baseDir);
    auth.conn.hostVerifier = (key: Buffer) => {
      if (keyPinned(h, key, cfg.security.allowUnpinnedHostKeys)) return true;
      mismatch = true;
      audit("terminal.hostkey_mismatch", { ...auditFor(h), role, presented: fingerprint(key) });
      return false;
    };
    return { role, host: h, client, auth, tries: 0 };
  };

  let targetHop: Hop;
  let bastionHop: Hop | undefined;
  let loadingRole: Role = route ? "bastion" : "target";
  try {
    bastionHop = route && bastion ? hopFor("bastion", route, bastion) : undefined;
    loadingRole = "target";
    targetHop = hopFor("target", host, ssh);
  } catch (e) {
    audit("terminal.error", { ...auditFor(host), error: (e as Error).message });
    trail("ssh_failed", "Credentials are misconfigured on the server");
    failure("SSH credentials are misconfigured on the server.", "configuration", loadingRole);
    queueMicrotask(() => close("Configuration error"));
    return handle;
  }

  let cipher = "";
  ssh.on("handshake", (n) => {
    mark("handshakeMs");
    cipher = n.cs.cipher;
  });

  ssh.on("ready", () => {
    ready = true;
    mark("authMs");
    ssh.shell({ term: "xterm-256color", ...size }, (err, s) => {
      if (err) {
        failure("The host refused to open a shell.", "shell");
        return close("Shell refused");
      }
      stream = s;
      mark("shellMs");
      // Start the recording before any output reaches the browser. If it cannot start, the session does not open.
      if (opts.recordings) {
        try {
          recording = opts.recordings.start({ hostId: host.id, host: host.name, user: session.login, ip, cols: size.cols, rows: size.rows });
        } catch (e) {
          audit("terminal.recording_failed", { ...auditFor(host), error: (e as Error).message });
          trail("recording_failed", "Recording could not start, session not opened");
          failure("Session recording is unavailable, so the session was not opened.", "recording");
          return close("Recording unavailable");
        }
      }
      audit("terminal.open", { ...auditFor(host), ...phases, ...(route ? { via: route.id } : {}) });
      opened = true;
      trail("ssh_connect", `As ${host.username}, ${host.auth.type === "key" ? (targetHop.auth.needsPassphrase ? "key with a passphrase typed in the browser" : "server-managed key") : "server-managed password"}${route ? `, through ${route.name}` : ""}`, host, recording?.id);
      send({
        t: "status",
        state: "connected",
        info: {
          id,
          files,
          host: `${host.host}:${host.port}`,
          user: host.username,
          auth: host.auth.type === "key"
            ? targetHop.auth.needsPassphrase ? "key, passphrase entered in browser" : "server-managed key"
            : "server-managed password",
          route: route ? `Through ${route.name} (${addrOf(route)})` : "Direct",
          cipher,
          hostKey: host.hostKeyFingerprints?.length ? "pinned" : "not pinned",
          since: new Date().toISOString(),
          recording: !!recording,
        },
      });
      const onData = (d: Buffer) => {
        if (closed) return;
        lastActivity = Date.now();
        if (recording) {
          try {
            recording.output(d);
          } catch (e) {
            return recordingFailed(e);
          }
        }
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
    audit("terminal.error", { ...auditFor(host), error: err.message });
    trail("ssh_failed", friendlyError(err, mismatch));
    failure(friendlyError(err, mismatch), errorStage(err, mismatch));
    close("Connection failed");
  });
  ssh.on("close", () => close("Connection closed"));

  if (route && bastion) {
    bastion.on("ready", () => {
      bastionUp = true;
      trail("ssh_connect", `Tunnel to ${host.name} (${addrOf(host)}), as ${route.username}`, route);
      startHop(targetHop);
    });
    bastion.on("error", (err) => {
      if (closed) return;
      audit("terminal.error", { ...auditFor(route), error: err.message });
      trail("ssh_failed", friendlyError(err, mismatch), route);
      failure(`Bastion ${route.name}: ${friendlyError(err, mismatch)}`, errorStage(err, mismatch), "bastion");
      close("Bastion connection failed");
    });
    bastion.on("close", () => close("Bastion connection closed"));
  }

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
      if (!awaiting) return;
      return submitPassphrase(typeof msg.value === "string" ? msg.value : "");
    }
    if (msg?.t === "resize") {
      size = { cols: clampDim(msg.cols, size.cols, 500), rows: clampDim(msg.rows, size.rows, 200) };
      stream?.setWindow(size.rows, size.cols, 0, 0);
      try {
        recording?.resize(size.cols, size.rows);
      } catch (e) {
        recordingFailed(e);
      }
    }
  });
  ws.on("close", () => close("Browser disconnected"));
  ws.on("error", () => close("Browser connection error"));

  function askPassphrase(hop: Hop, retry: boolean, restartTimer = true) {
    awaiting = hop;
    if (restartTimer) {
      clearTimeout(passphraseTimer);
      passphraseTimer = setTimeout(() => {
        failure("No passphrase was entered in time.", "passphrase", hop.role);
        close("Passphrase timeout");
      }, opts.timing?.passphraseWaitMs ?? PASSPHRASE_WAIT_MS);
    }
    send({ t: "passphrase", retry, remaining: PASSPHRASE_TRIES - hop.tries, hostId: hop.host.id, addr: addrOf(hop.host), role: hop.role });
  }

  function failPassphrase(hop: Hop, restartTimer: boolean) {
    hop.tries++;
    audit("terminal.passphrase_failed", { ...auditFor(hop.host), attempt: hop.tries });
    trail("passphrase_failed", `Attempt ${hop.tries} of ${PASSPHRASE_TRIES}`, hop.host);
    opts.activity.add({ kind: "passphrase_failed", githubId: session.githubId, ip, host: hop.host.id });
    if (hop.tries >= PASSPHRASE_TRIES) {
      failure("Incorrect passphrase.", "passphrase", hop.role);
      return close("Incorrect passphrase");
    }
    askPassphrase(hop, true, restartTimer);
  }

  function submitPassphrase(value: string) {
    const hop = awaiting;
    if (!hop) return;
    if (!opts.passphraseLimiter.hit(`${session.githubId}:${hop.host.id}`)) {
      audit("terminal.passphrase_throttled", auditFor(hop.host));
      trail("ssh_failed", "Too many incorrect passphrases, throttled", hop.host);
      failure("Too many incorrect passphrases. Try again later.", "passphrase", hop.role);
      return close("Passphrase attempts throttled");
    }
    if (!value || value.length > MAX_PASSPHRASE_LEN) return failPassphrase(hop, false);
    awaiting = undefined;
    clearTimeout(passphraseTimer);
    hop.auth.conn.privateKey = hop.auth.keyText;
    hop.auth.conn.passphrase = value;
    connectStart = Date.now();
    connectHop(hop, true);
  }

  function startHop(hop: Hop) {
    if (hop.auth.needsPassphrase) return askPassphrase(hop, false);
    connectHop(hop, false);
  }

  function connectHop(hop: Hop, fromPassphrase: boolean) {
    if (hop.role === "bastion" || !route || !bastion) return connectClient(hop, fromPassphrase);
    const through = { route, client: bastion };
    through.client.forwardOut("127.0.0.1", 0, hop.host.host, hop.host.port ?? 22, (err, channel) => {
      if (closed) {
        channel?.close();
        return;
      }
      if (err || !channel) {
        audit("terminal.error", { ...auditFor(hop.host), error: `tunnel: ${err?.message ?? "no channel"}` });
        trail("ssh_failed", `Could not reach ${hop.host.name} through ${through.route.name}`, hop.host);
        failure(`Could not reach ${hop.host.name} through ${through.route.name}.`, "connection", "target");
        return close("Could not reach the host through the bastion");
      }
      connectClient(hop, fromPassphrase, channel);
    });
  }

  function connectClient(hop: Hop, fromPassphrase: boolean, sock?: ClientChannel) {
    const conn: ConnectConfig = sock ? { ...hop.auth.conn, sock } : hop.auth.conn;
    try {
      hop.client.connect(conn);
    } catch (e) {
      sock?.destroy();
      hop.auth.conn.passphrase = undefined;
      if (fromPassphrase && /^Cannot parse privateKey/.test((e as Error).message)) return failPassphrase(hop, true);
      audit("terminal.error", { ...auditFor(hop.host), error: (e as Error).message });
      failure("SSH connection failed.", "configuration", hop.role);
      return close("Connection failed");
    }
    if (hop.role === "target") mark(fromPassphrase ? "decryptMs" : "connectCallMs");
    hop.auth.conn.passphrase = undefined;
    hop.auth.keyText = undefined;
  }

  send({ t: "status", state: "connecting" });
  connectStart = Date.now();
  startHop(bastionHop ?? targetHop);

  return handle;
}
