import * as esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";

fs.rmSync("dist", { recursive: true, force: true });
fs.mkdirSync("dist/public/assets", { recursive: true });

const client = await esbuild.build({
  entryPoints: { app: "src/client/app.ts", login: "src/client/login.ts", totp: "src/client/totp.ts", setup: "src/client/setup.ts", unseal: "src/client/unseal.ts", migrate: "src/client/migrate.ts" },
  metafile: true,
  entryNames: "[name]-[hash]",
  bundle: true,
  minify: true,
  target: "es2022",
  outdir: "dist/public/assets",
  loader: { ".woff": "file", ".woff2": "file" },
  assetNames: "[name]-[hash]",
});

await esbuild.build({
  entryPoints: ["src/server/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  packages: "external",
  outfile: "dist/server.js",
});

await esbuild.build({
  entryPoints: ["src/cli/totp.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  packages: "external",
  outfile: "dist/totp-cli.js",
});

await esbuild.build({
  entryPoints: ["src/cli/vault.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  packages: "external",
  outfile: "dist/vault-cli.js",
});

const built = {};
for (const [file, meta] of Object.entries(client.metafile.outputs)) {
  if (!meta.entryPoint) continue;
  const name = path.basename(meta.entryPoint, ".ts");
  built[name] = { js: path.basename(file), css: meta.cssBundle ? path.basename(meta.cssBundle) : undefined };
}
for (const [file, entry] of [["app.html", "app"], ["login.html", "login"], ["totp.html", "totp"], ["setup.html", "setup"], ["unseal.html", "unseal"], ["migrate.html", "migrate"]]) {
  const html = fs.readFileSync(`public/${file}`, "utf8").replace(
    /(href|src)="\/assets\/[a-z]+\.(css|js)"/g,
    (_m, attr, ext) => `${attr}="/assets/${built[entry][ext]}"`,
  );
  fs.writeFileSync(`dist/public/${file}`, html);
}
fs.copyFileSync("public/favicon.svg", "dist/public/assets/favicon.svg");
console.log("built dist/");
