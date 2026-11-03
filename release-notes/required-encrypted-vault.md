## Changes

- Obsolete plaintext host/key storage and config-loading code has been removed; host administration tests now use encrypted vaults.
- Configuration and secrets must be stored in an encrypted vault. Setup always requires a passphrase; plaintext setup saves and the web migration page have been removed.
- Hosts, passkeys, audit events and session recordings use the unlocked vault key in normal operation.
- Fresh Docker deployments mount only a writable vault directory. The setup wizard accepts private-key uploads and SSH passwords directly into the vault.

## After updating

- Existing vault installations continue to work. Keep the vault directory writable.
- A missing vault opens setup; an existing vault opens unseal. Legacy config files are ignored by startup. Configure a fresh vault or explicitly convert an old config using `npm run vault -- seal`. `SHELLPORT_MIGRATE=off` has no effect.
- For Docker CLI conversion, temporarily mount the original config and key files and provide their referenced environment variables. After verifying the vault, remove the original plaintext files and mounts. They are not automatically deleted. Startup uses only the vault.
- Explicit CLI import/export and editor tools remain available; exported configs and editor temporary files contain plaintext secrets.
