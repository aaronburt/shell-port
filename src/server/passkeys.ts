import crypto from "node:crypto";
import { type LoadedConfig, type LoadedUser, type PasskeyRecord, type StoreIoLike } from "./config.js";

export class PasskeyError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "PasskeyError";
  }
}

export interface PasskeyStore {
  readonly kind: "file" | "vault";
  save(match: string, passkeys: PasskeyRecord[]): void;
}

export const MAX_PASSKEYS_PER_USER = 10;

export function passkeyStore(kind: "file" | "vault", io: StoreIoLike): PasskeyStore {
  return {
    kind,
    save(match, passkeys) {
      try {
        const raw = io.read() as { users?: Array<{ github: string | number; passkeys?: PasskeyRecord[] }> };
        const entry = raw.users?.find((u) => String(u.github).trim().toLowerCase() === match);
        if (!entry) throw new PasskeyError(404, "not_found", "Your account is no longer in the user list.");
        if (passkeys.length) entry.passkeys = passkeys;
        else delete entry.passkeys;
        io.write(raw);
      } catch (e) {
        if (e instanceof PasskeyError) throw e;
        throw new PasskeyError(500, "storage_failed", `Could not save passkeys: ${(e as Error).message}`);
      }
    },
  };
}

export function userHandle(user: Pick<LoadedUser, "match">): Buffer {
  return crypto.createHash("sha256").update("shellport-passkey-user:" + user.match).digest();
}

export function findPasskey(cfg: Pick<LoadedConfig, "users">, credentialId: string): { user: LoadedUser; passkey: PasskeyRecord } | undefined {
  for (const user of cfg.users) {
    const passkey = user.passkeys.find((p) => p.id === credentialId);
    if (passkey) return { user, passkey };
  }
  return undefined;
}

export function rpIdFor(publicUrl: string): string {
  return new URL(publicUrl).hostname;
}

export class ChallengeBook {
  private items = new Map<string, { challenge: string; exp: number }>();

  constructor(private ttlMs = 5 * 60_000, private max = 2000) {}

  put(challenge: string, key = crypto.randomBytes(18).toString("base64url")): string {
    this.sweep();
    if (this.items.size >= this.max) this.items.delete(this.items.keys().next().value!);
    this.items.set(key, { challenge, exp: Date.now() + this.ttlMs });
    return key;
  }

  take(key: unknown): string | undefined {
    if (typeof key !== "string") return undefined;
    const e = this.items.get(key);
    this.items.delete(key);
    return e && e.exp > Date.now() ? e.challenge : undefined;
  }

  private sweep() {
    const now = Date.now();
    for (const [k, v] of this.items) if (v.exp <= now) this.items.delete(k);
  }
}
