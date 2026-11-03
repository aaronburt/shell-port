declare const __SHELLPORT_BUILD_VERSION__: string;

export const GITHUB_URL = "https://github.com/aaronburt/shell-port";
export const BUILD_VERSION = typeof __SHELLPORT_BUILD_VERSION__ === "string" ? __SHELLPORT_BUILD_VERSION__ : "development";

export function releaseNotesUrl(version: string): string {
  return /^v\d+\.\d+(?:\.\d+)?$/.test(version)
    ? `${GITHUB_URL}/releases/tag/${version}`
    : `${GITHUB_URL}/releases`;
}
