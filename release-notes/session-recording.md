## Changes

- Admins can review SSH sessions. Each session opened in the browser is recorded as its terminal output. Typed keys are not recorded.
- The Audit log has a new **Recordings** view to play, download or delete recordings, and connect events link to their recording.
- A red **REC** badge shows on a session tab while the session is being recorded.
- Recordings are kept for 90 days by default, and a session stops being recorded at 100 MB.

## After updating

- Recording is on by default. To turn it off, add `"recording": { "enabled": false }` to `config.json`. Sessions then open without a recording.
- Optional settings: `recording.retentionDays` (default 90) and `recording.maxMB` (default 100).
- Recordings are kept in a `recordings` folder next to the vault, or next to `config.json` when the vault is not used. Set `SHELLPORT_RECORDINGS` to use another folder. If that folder cannot be written, sessions will not open until it can. The server log says why.
- Existing configuration, vault and audit log files need no migration.
