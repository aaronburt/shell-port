## Changes

- The screen lock is now enforced by the server. While locked, the server drops terminal input, holds back terminal output (up to 1 MB, shown again on unlock) and refuses every other request and new terminal for that sign-in until you unlock. SSH connections stay open.
- A refresh or another tab of the same sign-in stays locked.

## After updating

- No action is needed.
