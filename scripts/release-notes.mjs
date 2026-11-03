import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export function changedNoteFiles(git) {
  const previous = git(["tag", "--merged", "HEAD", "--sort=-version:refname"])
    .split(/\r?\n/).find((tag) => /^v?\d+\.\d+$/.test(tag));
  const files = previous
    ? git(["diff", "--no-renames", "--name-only", "--diff-filter=AM", "-z", previous, "HEAD", "--", "release-notes/"])
    : git(["ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "release-notes/"]);
  return files.split("\0").filter((file) => /^release-notes\/[a-z0-9][a-z0-9-]*\.md$/.test(file)).sort();
}

export function renderReleaseNotes(notes) {
  const changes = [];
  const updating = [];
  for (const { file, text } of notes) {
    const [preamble, ...sections] = text.replace(/\r\n/g, "\n").split(/^## /m);
    if (preamble.trim()) throw new Error(`${file}: start with ## Changes`);
    const parsed = new Map();
    for (const section of sections) {
      const end = section.indexOf("\n");
      const heading = section.slice(0, end).trim();
      const body = section.slice(end + 1).trim();
      if (!["Changes", "After updating"].includes(heading) || parsed.has(heading) || !body)
        throw new Error(`${file}: provide one non-empty ## Changes and ## After updating section`);
      parsed.set(heading, body);
    }
    if (parsed.size !== 2) throw new Error(`${file}: both ## Changes and ## After updating are required`);
    changes.push(parsed.get("Changes"));
    updating.push(parsed.get("After updating"));
  }
  if (!notes.length) return "## After updating\n\nReview the pull requests below for changes and any update instructions.\n";
  return `## Changes\n\n${changes.join("\n\n")}\n\n## After updating\n\n${updating.join("\n\n")}\n`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2];
  if (!out) throw new Error("Usage: node scripts/release-notes.mjs <output.md>");
  const git = (args) => execFileSync("git", args, { encoding: "utf8" });
  const files = changedNoteFiles(git);
  const notes = files.map((file) => ({ file, text: fs.readFileSync(file, "utf8") }));
  fs.writeFileSync(out, renderReleaseNotes(notes));
  console.log(`Prepared release notes from ${files.length} patch-note file(s).`);
}
