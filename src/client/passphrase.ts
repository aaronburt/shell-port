export type PassphraseAction = "none" | "submit" | "cancel";

const isC1Control = (ch: string) => ch >= "\x80" && ch <= "\x9f";

function lastIndexOfEscape(chars: string[], start: number): number {
  const next = chars[start + 1];
  if (next === undefined) return start;
  if (next === "[") {
    let i = start + 2;
    while (i < chars.length && chars[i] >= " " && chars[i] <= "?") i++;
    return Math.min(i, chars.length - 1);
  }
  if (next === "O") return Math.min(start + 2, chars.length - 1);
  return start + 1;
}

export function feedPassphrase(current: string, data: string): { value: string; action: PassphraseAction } {
  const chars = Array.from(data);
  let value = current;
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch === "\x1b") i = lastIndexOfEscape(chars, i);
    else if (ch === "\r" || ch === "\n") return { value, action: "submit" };
    else if (ch === "\x03" || ch === "\x04") return { value, action: "cancel" };
    else if (ch === "\x7f" || ch === "\b") value = Array.from(value).slice(0, -1).join("");
    else if (ch === "\x15") value = "";
    else if (ch >= " " && !isC1Control(ch)) value += ch;
  }
  return { value, action: "none" };
}
