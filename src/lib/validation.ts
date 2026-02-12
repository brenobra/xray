const HOSTNAME_RE =
  /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
]);

const BLOCKED_HOSTNAME_SUFFIXES = [".localhost", ".internal"];

export function extractHostname(input: string): string | null {
  let raw = input;
  if (!/^https?:\/\//.test(raw)) raw = `https://${raw}`;
  try {
    const parsed = new URL(raw);
    return HOSTNAME_RE.test(parsed.hostname) ? parsed.hostname : null;
  } catch {
    return null;
  }
}

export function isBlockedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(lower)) return true;
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (lower.endsWith(suffix)) return true;
  }
  return false;
}

export function simpleHash(str: string): number {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) >>> 0;
  }
  return hash;
}
