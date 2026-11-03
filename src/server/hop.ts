import crypto from "node:crypto";
import type { ConnectConfig } from "ssh2";
import { hostNeedsPassphrase, resolveSecret, type HostConfig } from "./config.js";

export function fingerprint(key: Buffer): string {
  return "SHA256:" + crypto.createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
}

export function keyPinned(h: HostConfig, key: Buffer, allowUnpinned: boolean): boolean {
  if (!h.hostKeyFingerprints?.length) return allowUnpinned;
  const fp = fingerprint(key);
  return h.hostKeyFingerprints.some((p) => p.replace(/=+$/, "") === fp);
}

export function addrOf(h: HostConfig): string {
  return `${h.username}@${h.host}${(h.port ?? 22) !== 22 ? `:${h.port}` : ""}`;
}

export interface HopAuth {
  conn: ConnectConfig;
  keyText?: string;
  needsPassphrase: boolean;
}

export function hopAuth(h: HostConfig, baseDir: string): HopAuth {
  const conn: ConnectConfig = {
    host: h.host,
    port: h.port,
    username: h.username,
    readyTimeout: 15_000,
    keepaliveInterval: 20_000,
    keepaliveCountMax: 3,
  };
  const needsPassphrase = hostNeedsPassphrase(h);
  let keyText: string | undefined;
  if (h.auth.type === "key") {
    keyText = resolveSecret(h.auth.privateKey, baseDir, "privateKey", true);
    if (!needsPassphrase) {
      conn.privateKey = keyText;
      if (h.auth.passphrase) conn.passphrase = resolveSecret(h.auth.passphrase, baseDir, "passphrase");
    }
  } else {
    conn.password = resolveSecret(h.auth.password, baseDir, "password");
  }
  return { conn, keyText, needsPassphrase };
}
