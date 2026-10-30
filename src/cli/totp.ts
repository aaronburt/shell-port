import QRCode from "qrcode";
import { newSecret, otpauthUri } from "../server/totp.js";

const args = process.argv.slice(2);
const si = args.indexOf("--secret");
const existing = si >= 0 ? args.splice(si, 2)[1] : undefined;
const account = args[0] || "user";
const secret = existing || newSecret();
const uri = otpauthUri(secret, account);

console.log(await QRCode.toString(uri, { type: "terminal", small: true }));
console.log(`Scan the code above with an authenticator app, or enter this secret by hand:\n\n  ${secret}\n`);
console.log(`Then give it to Shellport. Prefer an environment variable over pasting it into config.json:\n`);
console.log(`  "users": [{ "github": <your GitHub user id>, "totpSecret": { "env": "SHELLPORT_TOTP_${account.toUpperCase().replace(/[^A-Z0-9]/g, "_")}" } }]\n`);
console.log(`Find your numeric GitHub id at https://api.github.com/users/${encodeURIComponent(account)}`);
