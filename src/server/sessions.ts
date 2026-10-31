import crypto from "node:crypto";

export interface UserSession {
  id: string;
  githubId: number;
  login: string;
  name: string;
  stage: "totp" | "full";
  totpFailures: number;
  createdAt: number;
  expiresAt: number;
}

const PENDING_TTL_MS = 5 * 60_000;

export class SessionStore {
  private sessions = new Map<string, UserSession>();
  private listeners = new Set<(s: UserSession) => void>();

  constructor(private ttlMs: number) {
    setInterval(() => this.sweep(), 60_000).unref();
  }

  create(user: { githubId: number; login: string; name: string }, stage: UserSession["stage"]): UserSession {
    const now = Date.now();
    const s: UserSession = {
      id: crypto.randomBytes(32).toString("base64url"),
      ...user,
      stage,
      totpFailures: 0,
      createdAt: now,
      expiresAt: now + (stage === "full" ? this.ttlMs : PENDING_TTL_MS),
    };
    this.sessions.set(s.id, s);
    return s;
  }

  promote(pending: UserSession): UserSession {
    this.sessions.delete(pending.id);
    return this.create(
      { githubId: pending.githubId, login: pending.login, name: pending.name },
      "full",
    );
  }

  get(id: string | undefined): UserSession | undefined {
    if (!id) return undefined;
    const s = this.sessions.get(id);
    if (!s) return undefined;
    if (s.expiresAt <= Date.now()) {
      this.destroy(id);
      return undefined;
    }
    return s;
  }

  forUser(githubId: number): UserSession[] {
    const now = Date.now();
    return [...this.sessions.values()].filter((s) => s.githubId === githubId && s.stage === "full" && s.expiresAt > now);
  }

  destroy(id: string) {
    const s = this.sessions.get(id);
    if (!s) return;
    this.sessions.delete(id);
    for (const fn of this.listeners) fn(s);
  }

  onEnd(fn: (s: UserSession) => void) {
    this.listeners.add(fn);
  }

  private sweep() {
    const now = Date.now();
    for (const [id, s] of this.sessions) if (s.expiresAt <= now) this.destroy(id);
  }
}

export class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();

  constructor(private limit: number, private windowMs: number, private maxEntries = 10_000) {
    setInterval(() => this.sweep(), Math.min(windowMs, 30_000)).unref();
  }

  get size() {
    return this.hits.size;
  }

  hit(key: string): boolean {
    const now = Date.now();
    let e = this.hits.get(key);
    if (!e || e.reset <= now) {
      this.hits.delete(key);
      if (this.hits.size >= this.maxEntries) this.makeRoom(now);
      e = { n: 0, reset: now + this.windowMs };
      this.hits.set(key, e);
    }
    e.n++;
    return e.n <= this.limit;
  }

  private sweep(now = Date.now()) {
    for (const [k, v] of this.hits) if (v.reset <= now) this.hits.delete(k);
  }

  private makeRoom(now: number) {
    this.sweep(now);
    while (this.hits.size >= this.maxEntries) {
      const oldest = this.hits.keys().next();
      if (oldest.done) break;
      this.hits.delete(oldest.value);
    }
  }
}
