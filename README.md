# Shellport

A lightweight, browser-based SSH client with GitHub sign-in, TOTP, and preconfigured hosts.

Runs [xterm.js](https://xtermjs.org/) in the browser connected over WebSocket to a server-side SSH proxy (`ssh2` + `ws`). Host credentials stay on the server—users cannot create arbitrary connections or export private keys.

## Quickstart (Docker)

```sh
cp config.local.example.json config.json
cp .env.example .env
mkdir -p keys

# Generate a TOTP secret for your user
docker compose run --rm --no-deps --entrypoint node shellport dist/totp-cli.js <github-login>

docker compose up -d --build
```

Access the client at `http://localhost:8080`.

### Web Configuration Generator

If Shellport is launched without an existing `config.json` (such as running a fresh container), it automatically starts in Setup Mode. Visit `http://localhost:8080` in your browser to use the interactive configuration generator:

- Visually configure server networking, GitHub OAuth, session limits, and SSH targets.
- Generate RFC 6238 Base32 TOTP secrets and scan QR codes directly into your authenticator app.
- Validate configuration against Shellport's schema.
- Download `config.json`, copy the JSON payload, or save directly if the container volume is writable.

For production deployment with automatic HTTPS via Caddy, use `deploy/docker-compose.yml`.

## Local Development

```sh
npm ci
npm run build
cp config.example.json config.json
npm run totp -- <github-login>
npm start
```

### Demo SSH Targets

To test Shellport without real SSH servers, spin up the local demo containers:

```sh
npm run demo:setup
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build
```

This generates keys, starts two demo SSH servers (unencrypted and passphrase-protected), and pins their host keys in `config.json`.

## Using the interface

- **Tab bar:** the sidebar toggle and the host search box sit together in one tab at the left of a full-width tab bar. The toggle is coloured while the sidebar is open. Each session is a tab 200px wide (shrinking to 120px only when the bar is full), and you can drag tabs to reorder them.
- **Sidebar:** click a host to open a terminal, or use the **+** that appears on a host row (on hover or keyboard focus) to open another session of the same host.
- **Session panel:** the panel on the right of the tab bar slides in and out and shows the connection details and your recent sign-ins. **Close session** at the top closes the active tab (tabs have no close cross), and **Sign out others** ends your other sessions. On a phone the panel opens over the terminal.
- **Account:** the avatar at the bottom of the sidebar opens a centred account modal with your login, a **Hide host addresses** switch (kept in this browser only), the keyboard shortcuts, **Close** and **Sign out**. Signing out asks for confirmation first, because it disconnects your open terminals.

## Configuration

Settings are defined in `config.json` (see [`config.example.json`](config.example.json)). Secrets can be literal strings, `{ "env": "VAR_NAME" }`, or `{ "file": "path/to/file" }`.

| Section | Description |
| --- | --- |
| `server` | Port, listen host, `publicUrl` (origin used for OAuth redirects and WebSocket checks), and `trustProxy`. |
| `github` | OAuth application credentials (`clientId`, `clientSecret`). |
| `users` | Allowlist of users by numeric GitHub ID or login, each with a required `totpSecret`. |
| `hosts` | Preconfigured SSH destinations with credentials, pinned host keys (`hostKeyFingerprints`), and optional `allowedUsers`. |
| `limits` | Concurrency and rate limits (`maxTerminalsPerUser`, `idleTimeoutMinutes`, `loginAttemptsPer15Min`). |

### Host Authentication

- **Password**: Credential stored on the server via env or file secret.
- **SSH Key**: Private key stored on the server. If passphrase-protected, the user unlocks it by typing the passphrase in the terminal tab on connect.

## Testing

```sh
npm test               # Unit and end-to-end test suite
npm run typecheck      # TypeScript type checking
npm run smoke -- <url> # Black-box security and header checks against a running instance
npm run smoke:full     # Isolated end-to-end run: real SSH containers and a headless browser (set SMOKE_SCREENSHOTS=<folder> to save screenshots)
```

## Security

See [SECURITY.md](SECURITY.md) for the threat model and security policy.

## License

[AGPL-3.0](LICENSE)
