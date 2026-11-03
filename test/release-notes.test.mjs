import { test } from "node:test";
import assert from "node:assert/strict";
import { changedNoteFiles, renderReleaseNotes } from "../scripts/release-notes.mjs";

test("release notes include only changed patch-note files since the last reachable release", () => {
  const calls = [];
  const files = changedNoteFiles(args => {
    calls.push(args);
    return args[0] === "tag" ? "not-a-release\nv0.47\nv0.46\n"
      : "release-notes/new-ui.md\0release-notes/README.md\0release-notes/security.md\0";
  });
  assert.deepEqual(files, ["release-notes/new-ui.md", "release-notes/security.md"]);
  assert.deepEqual(calls[1], ["diff", "--no-renames", "--name-only", "--diff-filter=AM", "-z", "v0.47", "HEAD", "--", "release-notes/"]);
});

test("a first release collects all committed patch notes", () => {
  const files = changedNoteFiles(args => {
    if (args[0] === "tag") return "";
    assert.equal(args[0], "ls-tree");
    return "release-notes/first.md\0release-notes/README.md\0";
  });
  assert.deepEqual(files, ["release-notes/first.md"]);
});

test("notes combine changes and update steps without repeating section headings", () => {
  const body = renderReleaseNotes([
    { file: "a.md", text: "## Changes\n\n- A.\n\n## After updating\n\n- Restart.\n" },
    { file: "b.md", text: "## Changes\r\n\r\n- B.\r\n\r\n## After updating\r\n\r\n- Update config.\r\n" },
  ]);
  assert.equal(body, "## Changes\n\n- A.\n\n- B.\n\n## After updating\n\n- Restart.\n\n- Update config.\n");
});

test("missing, duplicate, empty or unknown sections stop release-note generation", () => {
  for (const text of ["## Changes\n- A.", "## Changes\n\n## After updating\n- B.", "## Changes\n- A.\n## Changes\n- B.\n## After updating\n- C.", "## Other\n- A.\n## After updating\n- B."]) {
    assert.throws(() => renderReleaseNotes([{ file: "invalid.md", text }]), /invalid\.md/);
  }
});

test("releases with no patch notes do not claim that no update steps are needed", () => {
  assert.match(renderReleaseNotes([]), /Review the pull requests below/);
});
