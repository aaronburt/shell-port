import crypto from "node:crypto";

export type VaultErrorCode = "weak_passphrase" | "bad_passphrase" | "corrupt" | "unsupported";

export class VaultError extends Error {
  constructor(public code: VaultErrorCode, message: string) {
    super(message);
    this.name = "VaultError";
  }
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

export const DEFAULT_PARAMS: ScryptParams = { N: 1 << 17, r: 8, p: 1 };
export const MIN_PASSPHRASE_LENGTH = 12;

const MAGIC = "shellport-vault";
const VERSION = 1;
const KEY_LEN = 32;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const MAX_MEMORY = 512 * 1024 * 1024;
const MIN_N = 1 << 10;
const MAX_N = 1 << 18;

interface Kdf extends ScryptParams {
  name: "scrypt";
  salt: string;
}

interface Sealed {
  nonce: string;
  data: string;
}

export interface VaultHeader {
  magic: string;
  version: number;
  kdf: Kdf;
}

interface VaultFile extends VaultHeader {
  wrap: Sealed;
  body: Sealed;
}

const b64 = (b: Buffer) => b.toString("base64");

function unb64(value: unknown, length?: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new VaultError("corrupt", "vault field is not base64");
  const b = Buffer.from(value, "base64");
  if (length !== undefined && b.length !== length) throw new VaultError("corrupt", "vault field has the wrong length");
  return b;
}

function validParams(k: any): boolean {
  const { N, r, p } = k;
  return (
    Number.isInteger(N) && N >= MIN_N && N <= MAX_N && (N & (N - 1)) === 0 &&
    Number.isInteger(r) && r >= 1 && r <= 16 &&
    Number.isInteger(p) && p >= 1 && p <= 4
  );
}

function parseVault(file: string | Buffer): VaultFile {
  let raw: any;
  try {
    raw = JSON.parse(file.toString("utf8"));
  } catch {
    throw new VaultError("corrupt", "vault is not valid JSON");
  }
  if (!raw || typeof raw !== "object" || raw.magic !== MAGIC) throw new VaultError("corrupt", "not a Shellport vault");
  if (raw.version !== VERSION) throw new VaultError("unsupported", `vault version ${String(raw.version)} is not supported`);
  const k = raw.kdf;
  if (!k || typeof k !== "object" || k.name !== "scrypt" || !validParams(k)) throw new VaultError("unsupported", "vault KDF settings are not supported");
  unb64(k.salt, SALT_LEN);
  for (const part of [raw.wrap, raw.body]) {
    if (!part || typeof part !== "object") throw new VaultError("corrupt", "vault is missing a section");
    unb64(part.nonce, NONCE_LEN);
    if (unb64(part.data).length < TAG_LEN) throw new VaultError("corrupt", "vault section is too short");
  }
  return raw as VaultFile;
}

function headerAad(h: VaultHeader): Buffer {
  const { name, N, r, p, salt } = h.kdf;
  return Buffer.from(JSON.stringify({ magic: h.magic, version: h.version, kdf: { name, N, r, p, salt } }));
}

const bodyAad = Buffer.from(JSON.stringify({ magic: MAGIC, version: VERSION }));

function encrypt(key: Buffer, aad: Buffer, plain: Buffer): Sealed {
  const nonce = crypto.randomBytes(NONCE_LEN);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const data = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return { nonce: b64(nonce), data: b64(data) };
}

function decrypt(key: Buffer, aad: Buffer, sealed: Sealed): Buffer | undefined {
  const nonce = unb64(sealed.nonce, NONCE_LEN);
  const data = unb64(sealed.data);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(data.subarray(data.length - TAG_LEN));
  try {
    return Buffer.concat([decipher.update(data.subarray(0, data.length - TAG_LEN)), decipher.final()]);
  } catch {
    return undefined;
  }
}

function deriveKey(passphrase: string, kdf: Kdf): Buffer {
  const secret = Buffer.from(passphrase.normalize("NFKC"), "utf8");
  try {
    return crypto.scryptSync(secret, unb64(kdf.salt, SALT_LEN), KEY_LEN, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: MAX_MEMORY });
  } finally {
    secret.fill(0);
  }
}

function newKdf(params: ScryptParams): Kdf {
  if (!validParams(params)) throw new VaultError("unsupported", "KDF settings are outside the supported range");
  return { name: "scrypt", N: params.N, r: params.r, p: params.p, salt: b64(crypto.randomBytes(SALT_LEN)) };
}

function unwrapKey(vault: VaultFile, passphrase: string): Buffer {
  const kek = deriveKey(passphrase, vault.kdf);
  try {
    const dek = decrypt(kek, headerAad(vault), vault.wrap);
    if (!dek || dek.length !== KEY_LEN) throw new VaultError("bad_passphrase", "wrong passphrase, or the vault header was altered");
    return dek;
  } finally {
    kek.fill(0);
  }
}

function serialize(v: VaultFile): string {
  const { magic, version, kdf, wrap, body } = v;
  return JSON.stringify({ magic, version, kdf, wrap, body }, null, 2) + "\n";
}

export function checkPassphraseStrength(passphrase: string): string | undefined {
  const chars = [...passphrase.normalize("NFKC")];
  if (chars.length < MIN_PASSPHRASE_LENGTH) return `Use at least ${MIN_PASSPHRASE_LENGTH} characters.`;
  if (new Set(chars).size < 6) return "Use more different characters.";
  return undefined;
}

export function readVaultHeader(file: string | Buffer): VaultHeader {
  const { magic, version, kdf } = parseVault(file);
  return { magic, version, kdf };
}

export function sealVaultKeyed(plaintext: string | Buffer, passphrase: string, params: ScryptParams = DEFAULT_PARAMS): { file: string; dek: Buffer } {
  const weak = checkPassphraseStrength(passphrase);
  if (weak) throw new VaultError("weak_passphrase", weak);
  const header: VaultHeader = { magic: MAGIC, version: VERSION, kdf: newKdf(params) };
  const dek = crypto.randomBytes(KEY_LEN);
  const kek = deriveKey(passphrase, header.kdf);
  try {
    const file = serialize({
      ...header,
      wrap: encrypt(kek, headerAad(header), dek),
      body: encrypt(dek, bodyAad, Buffer.from(plaintext)),
    });
    return { file, dek: Buffer.from(dek) };
  } finally {
    kek.fill(0);
    dek.fill(0);
  }
}

export function sealVault(plaintext: string | Buffer, passphrase: string, params: ScryptParams = DEFAULT_PARAMS): string {
  const { file, dek } = sealVaultKeyed(plaintext, passphrase, params);
  dek.fill(0);
  return file;
}

export function openVaultKeyed(file: string | Buffer, passphrase: string): { plain: Buffer; dek: Buffer } {
  const vault = parseVault(file);
  const dek = unwrapKey(vault, passphrase);
  const plain = decrypt(dek, bodyAad, vault.body);
  if (!plain) {
    dek.fill(0);
    throw new VaultError("corrupt", "vault contents failed their integrity check");
  }
  return { plain, dek };
}

export function openVault(file: string | Buffer, passphrase: string): Buffer {
  const { plain, dek } = openVaultKeyed(file, passphrase);
  dek.fill(0);
  return plain;
}

export function openVaultWithKey(file: string | Buffer, dek: Buffer): Buffer {
  const plain = decrypt(dek, bodyAad, parseVault(file).body);
  if (!plain) throw new VaultError("corrupt", "vault contents failed their integrity check");
  return plain;
}

export function replaceVaultBody(file: string | Buffer, dek: Buffer, plaintext: string | Buffer): string {
  const vault = parseVault(file);
  if (!decrypt(dek, bodyAad, vault.body)) throw new VaultError("corrupt", "vault on disk does not match the unlocked vault");
  return serialize({ ...vault, body: encrypt(dek, bodyAad, Buffer.from(plaintext)) });
}

export function changeVaultPassphrase(file: string | Buffer, oldPassphrase: string, newPassphrase: string, params: ScryptParams = DEFAULT_PARAMS): string {
  const weak = checkPassphraseStrength(newPassphrase);
  if (weak) throw new VaultError("weak_passphrase", weak);
  const vault = parseVault(file);
  const dek = unwrapKey(vault, oldPassphrase);
  const header: VaultHeader = { magic: MAGIC, version: VERSION, kdf: newKdf(params) };
  const kek = deriveKey(newPassphrase, header.kdf);
  try {
    return serialize({ ...header, wrap: encrypt(kek, headerAad(header), dek), body: vault.body });
  } finally {
    kek.fill(0);
    dek.fill(0);
  }
}
