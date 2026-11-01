# Security policy

## Supported versions

Only the `main` branch is supported. Fixes land on `main`; there are no backports.

## Reporting a vulnerability

Please report vulnerabilities privately with GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a security problem. Include what you found, how to reproduce it, and the version or commit you tested.

## Threat model

Shellport gives a signed-in browser a shell on pre-configured hosts, so a compromise of the service is a compromise of those hosts. The design assumes:

- **Trusted:** the server operator, the machine running Shellport, and the contents of `config.json`, `.env` and `keys/`.
- **Administrators:** users with `"admin": true` can add hosts and upload SSH keys from the browser, so an admin account is as powerful as the server operator for choosing where Shellport connects. Keep the flag to as few people as possible. Adding a host makes the server open one connection to the address given (to read and pin its host key), so an admin can use it to probe addresses the server can reach. Each add is rate limited, needs the same `Origin`, and is written to the audit log with the user, target and whether a key was uploaded, never the key.
- **Authenticated, partly trusted:** users listed in `config.json`. They pass GitHub sign-in and a TOTP code, and can reach only the hosts they are allowed. They can run anything the configured SSH account can run.
- **Untrusted:** everyone else on the network, other websites open in a user's browser, and the content of the remote hosts' output.

What it defends against:

- Anonymous access: GitHub OAuth plus a required, single-use TOTP code, with rate limits on sign-in and code entry.
- Cross-site attacks: exact `Origin` check on the WebSocket, `SameSite` HttpOnly cookies, no CORS, a strict Content-Security-Policy with no inline or third-party scripts, and no framing.
- Credential theft from the browser: SSH keys and passwords stay on the server and are never sent to the client. Key hosts ask the user for the key passphrase in the terminal tab, and it is never stored or logged.
- Abuse of the file explorer: it uses the terminal's own SSH connection, so no second login or credential is involved. Each request needs the signed-in session that owns the terminal and an unguessable terminal id, and deletes also need the same `Origin`. Paths must be absolute with no `..` or control characters, previews and downloads are size limited, at most two downloads run per terminal, and every list, view, download and delete is written to the audit log with the user, host and path. A host can opt out with `files: false`.
- Man-in-the-middle on the SSH hop: host keys must be pinned by fingerprint, and a mismatch is refused and logged.

Design notes (choices that look odd but are deliberate):

- The Content-Security-Policy allows inline styles because xterm.js sets styles on its renderer at runtime. Scripts stay limited to `'self'`, so injected markup still cannot run code.
- The WebSocket upgrade checks the `Origin` header against `server.publicUrl`, because browsers send cookies on cross-site WebSocket handshakes and the same-origin policy does not apply to them.
- A TOTP code is compared in constant time against every candidate step, and a step is never accepted twice for the same user, so a code captured after use cannot be replayed.
- The GitHub access token is used once to read the profile and then revoked immediately; only the numeric id and login are kept, so a token leaked from logs or memory is already dead.
- Cookies are `__Host-` prefixed and `Secure` over HTTPS so they cannot be set from a subdomain or sent over plain HTTP.
- Key hosts default to a browser-typed passphrase so the server never holds a usable private key by default; a wrong, empty or oversized passphrase counts as a failed try.

What it does not defend against:

- Anyone who can read the server's files or environment, since TOTP secrets and host credentials are stored there in plaintext. Sealed mode removes this for files at rest; see below.
- A user who has passed both factors: there is no per-command control or session recording. The file explorer can read and delete anything the configured SSH account can, exactly like the terminal can; Shellport adds no path jail beyond that account's permissions.
- Running over plain HTTP on an untrusted network. Use HTTPS, and preferably put the service behind a VPN or an identity-aware proxy.
- Multiple instances: sessions are in memory and per-IP rate limits are not shared.

## Sealed mode

An optional vault (`vault.sealed`) replaces `config.json` and `.env`. See the README for how to use it.

- **Format.** The passphrase goes through scrypt (N=2^17, r=8, p=1) to a key that wraps a random 256-bit data key with AES-256-GCM, and the data key encrypts the config with AES-256-GCM. The header (version and KDF settings) is authenticated, so changed settings are detected. Changing the passphrase re-wraps the data key without re-encrypting the contents. The KDF name is stored in the header so Argon2id can be added later.
- **Protects against:** a disk image, backup, container layer or leaked volume that does not include the running process. Without the passphrase, host passwords, SSH keys, OAuth secret and TOTP secrets are unreadable and tampering is detected.
- **Does not protect against:** anyone who can read the running process's memory, or who can unseal it, since the decrypted config lives in memory while the server is unsealed. A weak passphrase can be guessed offline against a stolen vault; use a long one. There is no recovery path if the passphrase is lost, by design.
- **Sealed server surface.** While sealed it serves only the unseal page, its static assets, `/healthz` and `POST /api/unseal`. Unsealing needs a same-origin request over HTTPS (or from loopback), accepts a body of at most 2 KB, and has a global lockout after repeated failures. Successful and failed attempts are audit-logged.
- **Migration page.** When a plain `config.json` exists and no vault does, the server serves only a migration page until someone enters the one-time code from its log (compared in constant time, with a lockout on repeated wrong codes). Without log access the page cannot be used to set a passphrase. It accepts the passphrase over HTTPS or when the request is addressed to localhost.
- **Local unseal socket.** A sealed server also listens on `<vault>.sock` with mode 0600. Anyone who can open it can try passphrases without the web lockout, so protect the directory like the vault itself.
- **The passphrase** is used once to derive a key, then dropped; derived keys and decrypted buffers are zeroed after use where Node allows. The one exception is the vault's data key, which an unsealed server keeps in memory so admins can add hosts and keys without being asked for the passphrase again. It is zeroed when the server is sealed. It is sent to the server in the unseal request, so the server operator and the TLS endpoint are trusted with it.
- **Plain-text leftovers.** `export` and the editor's temporary file contain secrets in plain text. The temporary file is mode 0600, placed in `/dev/shm` when available, and overwritten and removed afterwards.

Do not commit `.env`, `config.json`, `keys/` or any private key. The repository's `.gitignore` excludes them.
