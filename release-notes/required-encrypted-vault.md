## Changes

- Configuration and secrets must be stored in an encrypted vault. Setup always requires a passphrase; plaintext setup saves and the migration skip option have been removed.
- Hosts, passkeys, audit events and session recordings use the unlocked vault key in normal operation.
- Fresh Docker deployments mount only a writable vault directory. The setup wizard accepts private-key uploads and SSH passwords directly into the vault.

## After updating

- Existing vault installations continue to work. Keep the vault directory writable.
- Plaintext installations must migrate using the one-time migration code in the server log or `npm run vault -- seal`. `SHELLPORT_MIGRATE=off` no longer bypasses encryption.
- For migration with Docker, temporarily mount the original config and key files and provide their referenced environment variables. After verifying the vault, remove the original plaintext config, environment and key files and their mounts. They are not automatically deleted. Restarting with both config and vault is refused.
- Explicit CLI import/export and editor tools remain available; exported configs and editor temporary files contain plaintext secrets.
