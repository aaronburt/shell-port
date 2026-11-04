const COMMAND_LIMIT = 500;
const FORBIDDEN = /[;&<>`$\\(){}\u0000-\u001f\u007f]/;
const SENSITIVE = /\.ssh|id_rsa|id_ed25519|id_ecdsa|\.env\b|shadow|\.pem\b|\.key\b|\.kdbx|credential|\.netrc|\.aws|bash_history|zsh_history|\.history|secret|\/proc\/[^/\s]*\/(environ|mem)|config\.json|vault|totp|token/i;

type Rule = { pipeOnly?: boolean; args: (args: string[]) => boolean };

const flagsOnly = (re: RegExp) => (args: string[]) => args.every((a) => re.test(a));
const noneOf = (re: RegExp) => (args: string[]) => !args.some((a) => re.test(a));
const any = () => true;

const RULES: Record<string, Rule> = {
  df: { args: any },
  du: { args: any },
  free: { args: any },
  uptime: { args: flagsOnly(/^-[a-z]+$/) },
  uname: { args: flagsOnly(/^-[a-z]+$/) },
  hostname: { args: flagsOnly(/^-[fisdIA]$/) },
  whoami: { args: () => false },
  id: { args: any },
  pwd: { args: any },
  who: { args: any },
  w: { args: any },
  last: { args: any },
  ls: { args: any },
  stat: { args: any },
  cat: { args: any },
  head: { args: noneOf(/^(-f|-F|--follow)/) },
  tail: { args: noneOf(/^-[a-zA-Z]*[fF]|^--follow/) },
  wc: { args: any },
  grep: { args: any },
  getent: { args: any },
  findmnt: { args: any },
  lsblk: { args: any },
  lscpu: { args: any },
  lsmem: { args: any },
  find: { args: noneOf(/^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/) },
  ps: { args: (a) => a.every((x) => /^-?[a-zA-Z]+$/.test(x) || /^--sort=[-+]?[%a-z]+$/.test(x)) },
  ss: { args: flagsOnly(/^-[tuwxlnpaoes46HrmiOQ]+$/) },
  netstat: { args: flagsOnly(/^-[a-zA-Z]+$/) },
  ip: { args: (a) => a.length > 0 && a.every((x) => /^(addr|address|a|link|route|r|neigh|n|show|list|-br|-s|-4|-6|-c|-j)$/.test(x)) && /^(addr|address|a|link|route|r|neigh|n)$/.test(a.find((x) => !x.startsWith("-")) ?? "") },
  date: { args: (a) => a.every((x) => /^(\+[\w%:/ .-]+|-u|--utc|-R|--rfc-email|-I\w*)$/.test(x)) },
  dmesg: { args: flagsOnly(/^(-T|-H|-x|--human|--ctime)$/) },
  sort: { pipeOnly: true, args: (a) => a.every((x) => /^-[rnhuV]+$|^-k\d+(,\d+)?[nrh]*$/.test(x)) },
  uniq: { pipeOnly: true, args: flagsOnly(/^-[cdui]+$/) },
  journalctl: { args: noneOf(/^--(follow|vacuum|rotate|flush|sync|relinquish|smart-relinquish|setup-keys|update-catalog|verify|interval|file|directory|root|image|namespace|machine|merge)|^-[a-zA-Z]*[fFN]/) },
  systemctl: { args: (a) => /^(status|is-active|is-enabled|is-failed|list-units|list-unit-files|list-timers|show|cat)$/.test(a.find((x) => !x.startsWith("-")) ?? "") && a.every((x) => /^-[la]+$|^--(no-pager|failed|all|full|state=\w+|type=\w+|property=\w+)$|^[\w@.:-]+$/.test(x)) },
  docker: { args: (a) => /^(ps|images|info|version|stats|logs)$/.test(a[0] ?? "") && !a.some((x) => /^-[a-zA-Z]*f$|^--follow$/.test(x)) },
};

export function tokenize(segment: string): string[] | undefined {
  const tokens: string[] = [];
  let cur = "";
  let quote = "";
  let started = false;
  for (const ch of segment) {
    if (quote) {
      if (ch === quote) quote = "";
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
    } else if (ch === " " || ch === "\t") {
      if (started || cur) tokens.push(cur);
      cur = "";
      started = false;
    } else {
      cur += ch;
      started = true;
    }
  }
  if (quote) return undefined;
  if (started || cur) tokens.push(cur);
  return tokens;
}

function splitPipes(command: string): string[] | undefined {
  const parts: string[] = [];
  let cur = "";
  let quote = "";
  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = "";
      cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
    } else if (ch === "|") {
      parts.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (quote) return undefined;
  parts.push(cur);
  return parts;
}

export function readOnlyCheck(command: unknown): string | undefined {
  if (typeof command !== "string" || !command.trim()) return "The command is empty.";
  if (command.length > COMMAND_LIMIT) return "The command is too long.";
  if (FORBIDDEN.test(command)) return "It uses shell features that are not allowed here (redirects, substitution, chaining or variables).";
  if (SENSITIVE.test(command)) return "It refers to a path or name that may hold secrets.";
  const segments = splitPipes(command);
  if (!segments || segments.length > 4) return "The pipeline is not allowed.";
  for (const [i, seg] of segments.entries()) {
    const tokens = tokenize(seg);
    if (!tokens || !tokens.length) return "The command could not be parsed.";
    const [name, ...args] = tokens;
    const rule = Object.hasOwn(RULES, name) ? RULES[name] : undefined;
    if (!rule) return `${name.replace(/[^\w.-]/g, "").slice(0, 40) || "That command"} is not on the read-only list.`;
    if (rule.pipeOnly && i === 0) return `${name} can only be used after a pipe.`;
    if (!rule.args(args)) return `That use of ${name} is not allowed.`;
  }
  return undefined;
}
