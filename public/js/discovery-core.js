// Content Discovery — pure, DOM-free core. Builds candidate URLs from a base
// URL + a wordlist and classifies responses so existing-but-unspecced paths
// (shadow endpoints) stand out from plain 404s. DOM-free for `node --test`.

// A small built-in list of paths common to web APIs and their infrastructure.
export const COMMON_PATHS = [
  'admin', 'api', 'api/v1', 'api/v2', 'actuator', 'actuator/health', 'health',
  'healthz', 'status', 'metrics', 'debug', 'swagger', 'swagger.json',
  'swagger-ui', 'openapi.json', 'v2/api-docs', 'v3/api-docs', 'graphql',
  'graphiql', '.git/config', '.env', 'config', 'backup', 'backup.zip',
  'users', 'user', 'login', 'logout', 'register', 'auth', 'token', 'oauth',
  'me', 'account', 'settings', 'internal', 'private', 'test', 'dev', 'staging',
  'console', 'dashboard', 'robots.txt', 'sitemap.xml', '.well-known/security.txt',
  'phpinfo.php', 'server-status', 'info', 'version',
];

// Parse a wordlist: split lines, trim, drop blanks and # comments.
export function parseWordlist(text) {
  return String(text || '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

// Build deduped candidate URLs from base + words.
export function buildCandidates(baseUrl, words) {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  const seen = new Set();
  const out = [];
  for (const word of words || []) {
    const path = String(word).replace(/^\/+/, '');
    if (!path) continue;
    const url = base ? `${base}/${path}` : `/${path}`;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push({ word: path, url });
  }
  return out;
}

// Classify a response status into a discovery outcome.
// Returns { kind, interesting }.
export function classify(status) {
  if (status == null) return { kind: 'error', interesting: true };
  if (status >= 200 && status < 300) return { kind: 'found', interesting: true };
  if ([301, 302, 307, 308].includes(status)) return { kind: 'redirect', interesting: true };
  if (status === 401 || status === 403) return { kind: 'protected', interesting: true };
  if (status === 404 || status === 410) return { kind: 'missing', interesting: false };
  if (status >= 500) return { kind: 'server-error', interesting: true };
  return { kind: 'other', interesting: true };
}
