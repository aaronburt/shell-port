import crypto from "node:crypto";

export type ActivityKind = "signin" | "totp_failed" | "passphrase_failed";

export interface Activity {
  id: string;
  kind: ActivityKind;
  githubId: number;
  ip: string;
  at: number;
  sid?: string;
  host?: string;
}

export const sidTag = (sessionId: string) => crypto.createHash("sha256").update(sessionId).digest("hex").slice(0, 10);

export class ActivityLog {
  private byUser = new Map<number, Activity[]>();

  constructor(private max = 200) {}

  add(e: Omit<Activity, "id" | "at"> & { at?: number }) {
    const list = this.byUser.get(e.githubId) ?? [];
    list.push({ ...e, id: crypto.randomBytes(6).toString("hex"), at: e.at ?? Date.now() });
    if (list.length > this.max) list.splice(0, list.length - this.max);
    this.byUser.set(e.githubId, list);
  }

  list(githubId: number, keep: (a: Activity) => boolean, limit = 50): Activity[] {
    return (this.byUser.get(githubId) ?? []).filter(keep).slice(-limit).reverse();
  }
}
