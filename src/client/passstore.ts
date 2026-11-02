const DB_NAME = "shellport";
const KEY_STORE = "keys";
const PASS_STORE = "passphrases";
const WRAP_KEY_ID = "wrap";
const FLAG = "sp.autoPass";

interface Sealed { iv: Uint8Array<ArrayBuffer>; ct: ArrayBuffer }

export const passSupported = (): boolean =>
  typeof indexedDB !== "undefined" && typeof crypto !== "undefined" && !!crypto.subtle;

export function autoPassEnabled(): boolean {
  try { return localStorage.getItem(FLAG) === "1"; } catch { return false; }
}

export function setAutoPassEnabled(on: boolean): void {
  try { localStorage.setItem(FLAG, on ? "1" : "0"); } catch {}
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(KEY_STORE);
      req.result.createObjectStore(PASS_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(store, mode);
      const req = fn(tx.objectStore(store));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function wrapKey(create: boolean): Promise<CryptoKey | undefined> {
  const existing = await run<CryptoKey | undefined>(KEY_STORE, "readonly", (s) => s.get(WRAP_KEY_ID));
  if (existing || !create) return existing;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await run(KEY_STORE, "readwrite", (s) => s.put(key, WRAP_KEY_ID));
  return (await run<CryptoKey | undefined>(KEY_STORE, "readonly", (s) => s.get(WRAP_KEY_ID))) ?? key;
}

const slot = (scope: string, hostId: string) => `${scope}\u0000${hostId}`;
const aad = (scope: string, hostId: string) => new TextEncoder().encode(slot(scope, hostId));

export async function savePassphrase(scope: string, hostId: string, value: string): Promise<void> {
  const key = await wrapKey(true);
  if (!key) return;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(scope, hostId) },
    key,
    new TextEncoder().encode(value),
  );
  const sealed: Sealed = { iv, ct };
  await run(PASS_STORE, "readwrite", (s) => s.put(sealed, slot(scope, hostId)));
}

export async function loadPassphrase(scope: string, hostId: string): Promise<string | undefined> {
  const sealed = await run<Sealed | undefined>(PASS_STORE, "readonly", (s) => s.get(slot(scope, hostId)));
  if (!sealed) return undefined;
  const key = await wrapKey(false);
  if (!key) return undefined;
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.iv, additionalData: aad(scope, hostId) }, key, sealed.ct);
    return new TextDecoder().decode(pt);
  } catch {
    await forgetPassphrase(scope, hostId);
    return undefined;
  }
}

export async function forgetPassphrase(scope: string, hostId: string): Promise<void> {
  await run(PASS_STORE, "readwrite", (s) => s.delete(slot(scope, hostId)));
}

export async function countPassphrases(scope: string): Promise<number> {
  const keys = await run<IDBValidKey[]>(PASS_STORE, "readonly", (s) => s.getAllKeys());
  const prefix = `${scope}\u0000`;
  return keys.filter((k) => typeof k === "string" && k.startsWith(prefix)).length;
}

export async function forgetAllPassphrases(): Promise<void> {
  await run(PASS_STORE, "readwrite", (s) => s.clear());
  await run(KEY_STORE, "readwrite", (s) => s.clear());
}
