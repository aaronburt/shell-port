## Changes

Smoke checks run in six parallel CI jobs with isolated apps and SSH fixtures. Browser jobs cache the Playwright headless shell, while authentication and SSH jobs skip browser installation. All existing smoke checks remain enabled.

## After updating

No deployment changes are needed. Contributors can run every smoke section with `npm run smoke:ci`, or selected sections with `node scripts/smoke-tests.mjs auth ssh`.
