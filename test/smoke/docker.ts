import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { generateEd25519 } from "../keys.js";

export const LOCKED_PASSPHRASE = "correct horse smoke";

export interface SshTarget {
  name: string;
  port: number;
  fingerprint: string;
}

export interface SmokeTargets {
  id: string;
  plain: SshTarget & { privateKey: string };
  locked: SshTarget & { privateKey: string; passphrase: string };
  cleanup(): void;
}

function docker(args: string[], quiet = false) {
  const r = spawnSync("docker", args, { encoding: "utf8" });
  if (r.error) throw new Error(`docker is not available: ${r.error.message}`);
  if (r.status !== 0 && !quiet) throw new Error(`docker ${args.slice(0, 2).join(" ")} failed: ${(r.stderr || r.stdout).trim()}`);
  return r;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until<T>(what: string, fn: () => T | undefined | Promise<T | undefined>, ms = 30_000): Promise<T> {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(250);
  }
}

function sshBanner(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    s.setTimeout(2000, () => { s.destroy(); resolve(false); });
    s.on("data", (d) => { s.destroy(); resolve(d.toString().startsWith("SSH-")); });
    s.on("error", () => resolve(false));
  });
}

export async function startTargets(): Promise<SmokeTargets> {
  if (docker(["version", "--format", "{{.Server.Version}}"], true).status !== 0) throw new Error("docker is not running");
  const id = crypto.randomBytes(4).toString("hex");
  const label = `shellport-smoke=${id}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shellport-smoke-"));
  const images = [`shellport-smoke-${id}-plain`, `shellport-smoke-${id}-locked`];
  const containers = [`shellport-smoke-${id}-plain`, `shellport-smoke-${id}-locked`];

  const cleanup = () => {
    for (const c of containers) docker(["rm", "-f", "-v", c], true);
    for (const i of images) docker(["rmi", "-f", i], true);
    fs.rmSync(dir, { recursive: true, force: true });
  };
  const onSignal = () => { cleanup(); process.exit(130); };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  try {
    for (const f of ["Dockerfile", "sshd_config", "entrypoint.sh"]) fs.copyFileSync(path.resolve("demo-ssh", f), path.join(dir, f));
    const plainKey = generateEd25519();
    const lockedKey = generateEd25519(LOCKED_PASSPHRASE);
    fs.writeFileSync(path.join(dir, "authorized_keys"), plainKey.public);
    fs.writeFileSync(path.join(dir, "authorized_keys.locked"), lockedKey.public);

    docker(["build", "-q", "--label", label, "-t", images[0], dir]);
    docker(["build", "-q", "--label", label, "--build-arg", "AUTHORIZED_KEYS=authorized_keys.locked", "-t", images[1], dir]);
    for (const [i, c] of containers.entries()) docker(["run", "-d", "--name", c, "--label", label, "-p", "127.0.0.1::22", images[i]]);

    const target = async (name: string): Promise<SshTarget> => {
      const port = await until(`${name} port mapping`, () => {
        const m = /127\.0\.0\.1:(\d+)/.exec(docker(["port", name, "22/tcp"], true).stdout);
        return m ? Number(m[1]) : undefined;
      });
      const fingerprint = await until(`${name} host key`, () => {
        const r = docker(["exec", name, "ssh-keygen", "-lf", "/hostkeys/ssh_host_ed25519_key.pub"], true);
        const fp = r.status === 0 ? r.stdout.trim().split(/\s+/)[1] : undefined;
        return fp?.startsWith("SHA256:") ? fp : undefined;
      });
      await until(`${name} sshd`, () => sshBanner(port));
      return { name, port, fingerprint };
    };

    const plain = await target(containers[0]);
    const locked = await target(containers[1]);
    return {
      id,
      plain: { ...plain, privateKey: plainKey.private },
      locked: { ...locked, privateKey: lockedKey.private, passphrase: LOCKED_PASSPHRASE },
      cleanup,
    };
  } catch (e) {
    cleanup();
    throw e;
  }
}

export function leftovers(id: string): string[] {
  const out: string[] = [];
  const containers = docker(["ps", "-a", "--filter", `label=shellport-smoke=${id}`, "--format", "{{.Names}}"], true).stdout.trim();
  if (containers) out.push(...containers.split(/\s+/).map((c) => `container ${c}`));
  const images = docker(["images", "--filter", `label=shellport-smoke=${id}`, "--format", "{{.Repository}}"], true).stdout.trim();
  if (images) out.push(...images.split(/\s+/).map((i) => `image ${i}`));
  return out;
}
