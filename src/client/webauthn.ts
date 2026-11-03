const toBuf = (s: string): ArrayBuffer => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
};

const toB64u = (buf: ArrayBuffer): string => {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const passkeysSupported = () => typeof window.PublicKeyCredential === "function" && !!navigator.credentials;

export type PasskeyFailure = "cancelled" | "unsupported" | "failed";

export function failureOf(e: unknown): PasskeyFailure {
  const name = (e as { name?: string })?.name;
  if (name === "NotAllowedError" || name === "AbortError") return "cancelled";
  if (name === "NotSupportedError" || name === "SecurityError") return "unsupported";
  return "failed";
}

export async function createPasskey(options: any): Promise<unknown> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: toBuf(options.challenge),
      user: { ...options.user, id: toBuf(options.user.id) },
      excludeCredentials: (options.excludeCredentials ?? []).map((c: any) => ({ ...c, id: toBuf(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      attestationObject: toB64u(r.attestationObject),
      transports: r.getTransports?.() ?? [],
    },
  };
}

export async function getPasskey(options: any): Promise<unknown> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: toBuf(options.challenge),
      allowCredentials: (options.allowCredentials ?? []).map((c: any) => ({ ...c, id: toBuf(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      authenticatorData: toB64u(r.authenticatorData),
      signature: toB64u(r.signature),
      userHandle: r.userHandle ? toB64u(r.userHandle) : undefined,
    },
  };
}
