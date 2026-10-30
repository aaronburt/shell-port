import crypto from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const c of clean) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error("invalid base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function hotp(key: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", key).update(msg).digest();
  const off = h[h.length - 1] & 15;
  const n = (h.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return n.toString().padStart(6, "0");
}

export function verifyTotp(key: Buffer, code: string, now = Date.now()): number | undefined {
  if (!/^\d{6}$/.test(code)) return undefined;
  const t = Math.floor(now / 30_000);
  let match: number | undefined;
  for (const c of [t - 1, t, t + 1]) {
    if (crypto.timingSafeEqual(Buffer.from(hotp(key, c)), Buffer.from(code))) match = c;
  }
  return match;
}

export function newSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

export function otpauthUri(secret: string, account: string, issuer = "Shellport"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
