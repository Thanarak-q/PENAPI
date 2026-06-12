// Attack Headers — pure, DOM-free core. A categorized library of HTTP request
// headers useful in testing (IP spoofing, host/URL override, cache poisoning,
// auth-context tricks), each with a sample value and an explanation, plus a
// search filter. DOM-free for `node --test`.

const HEADERS = [
  // category, name, sampleValue, note
  ['IP spoofing', 'X-Forwarded-For', '127.0.0.1', 'Claim a trusted source IP; can bypass IP allow-lists and rate limits.'],
  ['IP spoofing', 'X-Real-IP', '127.0.0.1', 'Alternative client-IP header honored by some proxies.'],
  ['IP spoofing', 'X-Originating-IP', '127.0.0.1', 'Legacy client-IP header; occasionally trusted for ACLs.'],
  ['IP spoofing', 'X-Client-IP', '127.0.0.1', 'Another client-IP variant some frameworks read.'],
  ['IP spoofing', 'True-Client-IP', '127.0.0.1', 'Akamai/Cloudflare client-IP header; may override XFF.'],
  ['URL/path override', 'X-Original-URL', '/admin', 'Some stacks route on this instead of the real path — front-end ACL bypass.'],
  ['URL/path override', 'X-Rewrite-URL', '/admin', 'IIS/.NET path override; reach internal-only routes.'],
  ['URL/path override', 'X-Forwarded-Path', '/admin', 'Path the proxy thinks was requested; can desync auth and routing.'],
  ['Host/cache', 'Host', 'evil.com', 'Host-header injection — password-reset poisoning, routing, cache key abuse.'],
  ['Host/cache', 'X-Forwarded-Host', 'evil.com', 'Overrides the host used to build absolute links — cache poisoning / redirect.'],
  ['Host/cache', 'X-Forwarded-Server', 'evil.com', 'Another host-override proxies may trust.'],
  ['Host/cache', 'X-Host', 'evil.com', 'Host override honored by some CDNs.'],
  ['Scheme', 'X-Forwarded-Proto', 'https', 'Make the app think it is on HTTPS; can defeat scheme-based redirects.'],
  ['Scheme', 'X-Forwarded-Scheme', 'https', 'Scheme override variant.'],
  ['Auth context', 'X-Forwarded-User', 'admin', 'Some gateways trust an upstream-set user header — auth bypass if exposed.'],
  ['Auth context', 'X-Remote-User', 'admin', 'mod_auth / SSO upstream user header; impersonation if reachable.'],
  ['Auth context', 'X-User-Id', '1', 'App-specific identity header occasionally trusted from the client.'],
  ['Method', 'X-HTTP-Method-Override', 'PUT', 'Smuggle a different verb past a method-restricted filter.'],
  ['Method', 'X-HTTP-Method', 'DELETE', 'Method-override variant.'],
  ['Method', 'X-Method-Override', 'PATCH', 'Method-override variant.'],
];

const TABLE = HEADERS.map(([category, name, sample, note]) => ({ category, name, sample, note }));

// All entries.
export function allHeaders() {
  return TABLE.slice();
}

// Distinct category names in declaration order.
export function categories() {
  return [...new Set(TABLE.map((e) => e.category))];
}

// Search by header name / note / category (case-insensitive).
export function searchHeaders(query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return allHeaders();
  return TABLE.filter((e) =>
    e.name.toLowerCase().includes(q) ||
    e.note.toLowerCase().includes(q) ||
    e.category.toLowerCase().includes(q)
  );
}

// Render one entry as a "Name: value" header line.
export function toHeaderLine(entry) {
  return `${entry.name}: ${entry.sample}`;
}
