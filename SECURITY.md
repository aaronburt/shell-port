# Security policy

## Supported versions

Only the `main` branch is supported. Fixes land on `main`; there are no backports.

## Reporting a vulnerability

Please report vulnerabilities privately with GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a security problem. Include what you found, how to reproduce it, and the version or commit you tested.

## Threat model

Shellport gives a signed-in browser a shell on pre-configured hosts, so a compromise of the service is a compromise of those hosts. The design assumes:

- **Trusted:** the server operator, the machine running Shellport, and the contents of `config.json`, `.env` and `keys/`.
- **Authenticated, partly trusted:** users listed in `config.json`. They pass GitHub sign-in and a TOTP code, and can reach only the hosts they are allowed. They can run anything the configured SSH account can run.
- **Untrusted:** everyone else on the network, other websites open in a user's browser, and the content of the remote hosts' output.

What it defends against:

- Anonymous access: GitHub OAuth plus a required, single-use TOTP code, with rate limits on sign-in and code entry.
- Cross-site attacks: exact `Origin` check on the WebSocket, `SameSite` HttpOnly cookies, no CORS, a strict Content-Security-Policy with no inline or third-party scripts, and no framing.
- Credential theft from the browser: SSH keys and passwords stay on the server and are never sent to the client. Key hosts ask the user for the key passphrase in the terminal tab, and it is never stored or logged.
- Man-in-the-middle on the SSH hop: host keys must be pinned by fingerprint, and a mismatch is refused and logged.

Design notes (choices that look odd but are deliberate):

- The Content-Security-Policy allows inline styles because xterm.js sets styles on its renderer at runtime. Scripts stay limited to `'self'`, so injected markup still cannot run code.
- The WebSocket upgrade checks the `Origin` header against `server.publicUrl`, because browsers send cookies on cross-site WebSocket handshakes and the same-origin policy does not apply to them.
- A TOTP code is compared in constant time against every candidate step, and a step is never accepted twice for the same user, so a code captured after use cannot be replayed.
- The GitHub access token is used once to read the profile and then revoked immediately; only the numeric id and login are kept, so a token leaked from logs or memory is already dead.
- Cookies are `__Host-` prefixed and `Secure` over HTTPS so they cannot be set from a subdomain or sent over plain HTTP.
- Key hosts default to a browser-typed passphrase so the server never holds a usable private key by default; a wrong, empty or oversized passphrase counts as a failed try.

What it does not defend against:

- Anyone who can read the server's files or environment, since TOTP secrets and host credentials are stored there in plaintext.
- A user who has passed both factors: there is no per-command control or session recording.
- Running over plain HTTP on an untrusted network. Use HTTPS, and preferably put the service behind a VPN or an identity-aware proxy.
- Multiple instances: sessions are in memory and per-IP rate limits are not shared.

Do not commit `.env`, `config.json`, `keys/` or any private key. The repository's `.gitignore` excludes them.
