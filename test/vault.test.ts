import { test } from "node:test";
import assert from "node:assert/strict";
import {
  VaultError, sealVault, openVault, readVaultHeader, changeVaultPassphrase, checkPassphraseStrength,
  type VaultErrorCode,
} from "../src/server/vault.js";

const FAST = { N: 1 << 10, r: 8, p: 1 };
const PASS = "correct horse battery staple";
const PLAIN = JSON.stringify({ github: { clientSecret: "s3cret" }, users: [{ github: 1, totpSecret: "ABC" }] });

const failsWith = (code: VaultErrorCode) => (e: unknown) => e instanceof VaultError && e.code === code;

function edit(file: string, change: (v: any) => void): string {
  const v = JSON.parse(file);
  change(v);
  return JSON.stringify(v);
}

function flipFirstByte(b64: string): string {
  const b = Buffer.from(b64, "base64");
  b[0] ^= 0xff;
  return b.toString("base64");
}

test("a sealed vault opens with the right passphrase and returns the original contents", () => {
  const vault = sealVault(PLAIN, PASS, FAST);
  assert.equal(openVault(vault, PASS).toString("utf8"), PLAIN);
});

test("the sealed file does not contain the plaintext", () => {
  const vault = sealVault(PLAIN, PASS, FAST);
  assert.ok(!vault.includes("s3cret"));
  assert.ok(!vault.includes("totpSecret"));
});

test("a wrong passphrase is rejected as bad_passphrase", () => {
  const vault = sealVault(PLAIN, PASS, FAST);
  assert.throws(() => openVault(vault, "another long passphrase"), failsWith("bad_passphrase"));
});

test("the same contents sealed twice produce different files", () => {
  assert.notEqual(sealVault(PLAIN, PASS, FAST), sealVault(PLAIN, PASS, FAST));
});

test("weak passphrases are refused when sealing", () => {
  assert.throws(() => sealVault(PLAIN, "short", FAST), failsWith("weak_passphrase"));
  assert.throws(() => sealVault(PLAIN, "aaaaaaaaaaaaaaaa", FAST), failsWith("weak_passphrase"));
  assert.equal(checkPassphraseStrength(PASS), undefined);
});

test("composed and decomposed forms of the same passphrase both open the vault", () => {
  const composed = "café au lait été 2026";
  const decomposed = composed.normalize("NFD");
  assert.notEqual(composed, decomposed);
  const vault = sealVault(PLAIN, composed, FAST);
  assert.equal(openVault(vault, decomposed).toString("utf8"), PLAIN);
});

test("a tampered body is reported as corrupt, not as a wrong passphrase", () => {
  const vault = edit(sealVault(PLAIN, PASS, FAST), (v) => { v.body.data = flipFirstByte(v.body.data); });
  assert.throws(() => openVault(vault, PASS), failsWith("corrupt"));
});

test("a tampered wrapped key is rejected", () => {
  const vault = edit(sealVault(PLAIN, PASS, FAST), (v) => { v.wrap.data = flipFirstByte(v.wrap.data); });
  assert.throws(() => openVault(vault, PASS), failsWith("bad_passphrase"));
});

test("changing the KDF settings in the header is detected", () => {
  const vault = edit(sealVault(PLAIN, PASS, FAST), (v) => { v.kdf.N = 1 << 11; });
  assert.throws(() => openVault(vault, PASS), failsWith("bad_passphrase"));
});

test("a header asking for unreasonable KDF cost is refused before any work is done", () => {
  const vault = edit(sealVault(PLAIN, PASS, FAST), (v) => { v.kdf.N = 1 << 30; });
  assert.throws(() => openVault(vault, PASS), failsWith("unsupported"));
  assert.throws(() => readVaultHeader(vault), failsWith("unsupported"));
});

test("files that are not vaults are told apart from damaged vaults", () => {
  assert.throws(() => readVaultHeader("not json"), failsWith("corrupt"));
  assert.throws(() => readVaultHeader(JSON.stringify({ server: { port: 8080 } })), failsWith("corrupt"));
  const future = edit(sealVault(PLAIN, PASS, FAST), (v) => { v.version = 99; });
  assert.throws(() => readVaultHeader(future), failsWith("unsupported"));
});

test("the header can be read without the passphrase", () => {
  const header = readVaultHeader(sealVault(PLAIN, PASS, FAST));
  assert.equal(header.magic, "shellport-vault");
  assert.equal(header.version, 1);
  assert.equal(header.kdf.name, "scrypt");
  assert.equal(header.kdf.N, FAST.N);
});

test("changing the passphrase re-wraps the key and leaves the encrypted contents untouched", () => {
  const original = sealVault(PLAIN, PASS, FAST);
  const next = "a brand new long passphrase";
  const changed = changeVaultPassphrase(original, PASS, next, FAST);
  assert.equal(openVault(changed, next).toString("utf8"), PLAIN);
  assert.throws(() => openVault(changed, PASS), failsWith("bad_passphrase"));
  assert.deepEqual(JSON.parse(changed).body, JSON.parse(original).body);
  assert.notEqual(JSON.parse(changed).kdf.salt, JSON.parse(original).kdf.salt);
});

test("changing the passphrase needs the current one and a strong new one", () => {
  const vault = sealVault(PLAIN, PASS, FAST);
  assert.throws(() => changeVaultPassphrase(vault, "not the passphrase", "a brand new long passphrase", FAST), failsWith("bad_passphrase"));
  assert.throws(() => changeVaultPassphrase(vault, PASS, "short", FAST), failsWith("weak_passphrase"));
});

test("binary contents survive a round trip", () => {
  const bytes = Buffer.from(Array.from({ length: 512 }, (_, i) => i % 256));
  assert.deepEqual(openVault(sealVault(bytes, PASS, FAST), PASS), bytes);
});
