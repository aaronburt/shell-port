export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function until(what: string, fn: () => unknown | Promise<unknown>, ms = 10_000) {
  const t0 = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(40);
  }
}
