import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const keysDir = path.join(root, "keys");
const demoDir = path.join(root, "demo-ssh");
const passphraseFile = path.join(root, "demo-locked.passphrase");
const composeArgs = ["compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml"];

const DEMO_HOSTS = [
  {
    service: "demo-ssh",
    authorizedKeys: "authorized_keys",
    key: "demo_ed25519",
    host: {
      id: "demo",
      name: "demo-ssh",
      group: "Demo",
      host: "demo-ssh",
      port: 22,
      username: "demo",
      auth: { type: "key", privateKey: { file: "keys/demo_ed25519" }, passphrase: false },
    },
  },
  {
    service: "demo-ssh-locked",
    authorizedKeys: "authorized_keys.locked",
    key: "demo_locked_ed25519",
    locked: true,
    host: {
      id: "demo-locked",
      name: "demo-ssh-locked",
      group: "Demo",
      tag: "passphrase",
      host: "demo-ssh-locked",
      port: 22,
      username: "demo",
      auth: { type: "key", privateKey: { file: "keys/demo_locked_ed25519" } },
    },
  },
];

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { cwd: root, encoding: "utf8", ...opts });
}

function die(message) {
  console.error(`demo:setup: ${message}`);
  process.exit(1);
}

function hasLocalKeygen() {
  const r = run("ssh-keygen", ["-?"]);
  return !r.error;
}

function generateLocal(file, passphrase) {
  const r = run("ssh-keygen", ["-q", "-t", "ed25519", "-N", passphrase, "-C", "shellport-demo", "-f", file]);
  if (r.status !== 0) die(`ssh-keygen failed: ${r.stderr.trim()}`);
}

function generateInDocker(name, passphrase) {
  const container = `shellport-keygen-${crypto.randomBytes(4).toString("hex")}`;
  const script = `apk add -q --no-cache openssh-keygen >/dev/null && mkdir /out && ssh-keygen -q -t ed25519 -N "$KEY_PASSPHRASE" -C shellport-demo -f /out/${name}`;
  const r = run("docker", ["run", "--name", container, "-e", `KEY_PASSPHRASE=${passphrase}`, "--entrypoint", "sh", "alpine:3.20", "-c", script]);
  try {
    if (r.status !== 0) die(`key generation in docker failed: ${(r.stderr || r.stdout).trim()}`);
    const cp = run("docker", ["cp", `${container}:/out/.`, keysDir]);
    if (cp.status !== 0) die(`docker cp failed: ${cp.stderr.trim()}`);
  } finally {
    run("docker", ["rm", "-f", container]);
  }
}

function ensureKey(spec) {
  const file = path.join(keysDir, spec.key);
  const have = fs.existsSync(file) && fs.existsSync(`${file}.pub`);
  const haveSecret = !spec.locked || fs.existsSync(passphraseFile);
  if (have && haveSecret) return;
  fs.rmSync(file, { force: true });
  fs.rmSync(`${file}.pub`, { force: true });
  const passphrase = spec.locked ? crypto.randomBytes(12).toString("base64url") : "";
  if (hasLocalKeygen()) generateLocal(file, passphrase);
  else generateInDocker(spec.key, passphrase);
  if (spec.locked) fs.writeFileSync(passphraseFile, `${passphrase}\n`, { mode: 0o600 });
  console.log(`generated keys/${spec.key}`);
}

function copyIfMissing(from, to) {
  if (!fs.existsSync(to)) fs.copyFileSync(path.join(root, from), to);
}

function hostFingerprint(service) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const r = run("docker", [...composeArgs, "exec", "-T", service, "ssh-keygen", "-lf", "/hostkeys/ssh_host_ed25519_key.pub"]);
    const fp = r.status === 0 ? r.stdout.trim().split(/\s+/)[1] : undefined;
    if (fp?.startsWith("SHA256:")) return fp;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  return die(`could not read the host key of ${service}`);
}

if (run("docker", ["version", "--format", "{{.Server.Version}}"]).status !== 0) die("docker is not running");

fs.mkdirSync(keysDir, { recursive: true });
copyIfMissing(".env.example", path.join(root, ".env"));
copyIfMissing("config.local.example.json", path.join(root, "config.json"));

for (const spec of DEMO_HOSTS) {
  ensureKey(spec);
  fs.copyFileSync(path.join(keysDir, `${spec.key}.pub`), path.join(demoDir, spec.authorizedKeys));
}

const up = run("docker", [...composeArgs, "up", "-d", "--build", ...DEMO_HOSTS.map((s) => s.service)], { stdio: "inherit" });
if (up.status !== 0) die("docker compose up failed");

const configFile = path.join(root, "config.json");
const config = JSON.parse(fs.readFileSync(configFile, "utf8"));
const demoIds = new Set(["example", ...DEMO_HOSTS.map((s) => s.host.id)]);
const kept = (config.hosts ?? []).filter((h) => !demoIds.has(h.id));
const demos = DEMO_HOSTS.map((s) => ({ ...s.host, hostKeyFingerprints: [hostFingerprint(s.service)] }));
config.hosts = [...demos, ...kept];
fs.writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n");

console.log("config.json now has the demo and demo-locked hosts with pinned host keys");
console.log("passphrase for the demo-locked key is in demo-locked.passphrase");
console.log("start Shellport with: docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build");
