import { spawnSync } from "node:child_process";
import { build } from "esbuild";

const files = {
  auth: "test/smoke/auth.ts",
  ssh: "test/smoke/ssh.ts",
  "ui-terminal": "test/smoke/ui-terminal.ts",
  "ui-account": "test/smoke/ui-account.ts",
  setup: "test/smoke/setup.ts",
  pages: "test/smoke/page-links.ts",
};
const sections = process.argv.slice(2);
if (!sections.length) sections.push(...Object.keys(files));
for (const section of sections) {
  if (!Object.hasOwn(files, section)) {
    console.error(`Unknown smoke section: ${section}. Choose: ${Object.keys(files).join(", ")}`);
    process.exit(1);
  }
}

function run(args) {
  const result = spawnSync(process.execPath, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

// Docker Desktop's CLI can lock context metadata when workers build together.
// Resolve the active endpoint once; all workers still use the same daemon.
if (process.platform === "win32" && !process.env.DOCKER_HOST && sections.some(section => !["setup", "pages"].includes(section))) {
  const endpoint = spawnSync("docker", ["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], { encoding: "utf8" });
  if (endpoint.error) throw endpoint.error;
  if (endpoint.status !== 0 || !endpoint.stdout.trim()) {
    console.error(endpoint.stderr || "Could not resolve the active Docker endpoint");
    process.exit(1);
  }
  process.env.DOCKER_HOST = endpoint.stdout.trim();
  delete process.env.DOCKER_CONTEXT;
}

// Build assets once before any worker starts, so workers only read dist/.
run(["build.mjs"]);
await build({
  entryPoints: Object.fromEntries(sections.map(section => [section, files[section]])),
  bundle: true,
  platform: "node",
  format: "esm",
  packages: "external",
  logLevel: "warning",
  outdir: ".test-build/smoke",
  outExtension: { ".js": ".mjs" },
});
// Each file has its own app, clock, browser contexts and SSH containers.
// Tests within a file stay sequential because some exercise a session lifecycle.
run([
  "--test", "--test-timeout=240000", `--test-concurrency=${sections.length}`,
  ...sections.map(section => `.test-build/smoke/${section}.mjs`),
]);
