# Release notes

Add a new Markdown file here for each user-facing change, named with a short lowercase slug such as `account-version.md`. Do not edit an older release's file to describe a new change.

Use both sections:

```markdown
## Changes

- Describe what users can now do or what was fixed.

## After updating

- Explain any configuration changes, migrations, or other action needed.
- If no action is needed, say so explicitly.
```

The release workflow combines files added or modified since the previous release tag, then appends GitHub's generated pull-request changelog and comparison link. Previously released files are not repeated. Files are retained as history; `README.md` is excluded from release content.

The first release includes all patch-note files. If a release contains no patch-note files, it still includes GitHub's generated changelog and directs users to the pull requests for update instructions.

Preview notes after committing your changes:

```sh
node scripts/release-notes.mjs /tmp/shellport-release-notes.md
```

Keep these notes focused on users. Do not include credentials, deployment-specific addresses, or unverified test claims.
