import readline from "node:readline";

export async function readSecret(question: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  }
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const out = (rl as unknown as { output: NodeJS.WriteStream });
    const write = out.output.write.bind(out.output);
    let muted = false;
    out.output.write = ((chunk: string | Uint8Array, ...rest: unknown[]) =>
      muted ? true : (write as (...a: unknown[]) => boolean)(chunk, ...rest)) as typeof out.output.write;
    rl.question(question, (answer) => {
      muted = false;
      out.output.write = write as typeof out.output.write;
      process.stdout.write("\n");
      rl.close();
      resolve(answer);
    });
    muted = true;
  });
}

export async function readNewPassphrase(label = "New passphrase"): Promise<string> {
  const first = await readSecret(`${label}: `);
  if (!process.stdin.isTTY) return first;
  const second = await readSecret("Repeat it: ");
  if (first !== second) throw new Error("The two passphrases do not match.");
  return first;
}
