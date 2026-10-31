export interface GitHubUser {
  id: number;
  login: string;
  name: string;
}

export function authorizeUrl(clientId: string, redirectUri: string, state: string): string {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("state", state);
  u.searchParams.set("scope", "");
  u.searchParams.set("allow_signup", "false");
  return u.toString();
}

export async function exchangeCode(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string,
): Promise<GitHubUser> {
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }),
    signal: AbortSignal.timeout(10_000),
  });
  const tok = (await tokenRes.json()) as { access_token?: string; error?: string };
  if (!tok.access_token) throw new Error(`GitHub token exchange failed: ${tok.error ?? tokenRes.status}`);

  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${tok.access_token}`,
      "User-Agent": "shellport",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!userRes.ok) throw new Error(`GitHub /user failed: ${userRes.status}`);
  const u = (await userRes.json()) as { id: number; login: string; name: string | null };

  fetch(`https://api.github.com/applications/${clientId}/token`, {
    method: "DELETE",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
      "User-Agent": "shellport",
    },
    body: JSON.stringify({ access_token: tok.access_token }),
    signal: AbortSignal.timeout(10_000),
  }).catch(() => {});

  return { id: u.id, login: u.login, name: u.name || u.login };
}
