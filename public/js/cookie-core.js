// Cookie Inspector — pure, DOM-free core. Parses Set-Cookie / Cookie header
// values and audits cookie security attributes (HttpOnly, Secure, SameSite).
// DOM-free for `node --test`.

// Parse one Set-Cookie line into { name, value, httpOnly, secure, sameSite,
// path, domain, expires, maxAge }.
export function parseSetCookie(line) {
  const parts = String(line || '').split(';').map((s) => s.trim()).filter(Boolean);
  const nv = parts.shift() || '';
  const eq = nv.indexOf('=');
  const cookie = {
    name: eq === -1 ? nv : nv.slice(0, eq),
    value: eq === -1 ? '' : nv.slice(eq + 1),
    httpOnly: false, secure: false, sameSite: null,
    path: null, domain: null, expires: null, maxAge: null,
  };
  for (const attr of parts) {
    const i = attr.indexOf('=');
    const key = (i === -1 ? attr : attr.slice(0, i)).toLowerCase();
    const val = i === -1 ? '' : attr.slice(i + 1);
    if (key === 'httponly') cookie.httpOnly = true;
    else if (key === 'secure') cookie.secure = true;
    else if (key === 'samesite') cookie.sameSite = val;
    else if (key === 'path') cookie.path = val;
    else if (key === 'domain') cookie.domain = val;
    else if (key === 'expires') cookie.expires = val;
    else if (key === 'max-age') cookie.maxAge = val;
  }
  return cookie;
}

// Parse a request Cookie header ("a=1; b=2") into [{ name, value }].
export function parseCookies(header) {
  return String(header || '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((pair) => {
      const i = pair.indexOf('=');
      return { name: i === -1 ? pair : pair.slice(0, i), value: i === -1 ? '' : pair.slice(i + 1) };
    });
}

// Return security issues for a parsed Set-Cookie object.
export function auditCookie(cookie) {
  const issues = [];
  if (!cookie.httpOnly) issues.push('Missing HttpOnly — readable by JavaScript (XSS can steal it)');
  if (!cookie.secure) issues.push('Missing Secure — may be sent over plaintext HTTP');
  if (!cookie.sameSite) issues.push('No SameSite — cross-site requests send it (CSRF exposure)');
  else if (/^none$/i.test(cookie.sameSite)) issues.push('SameSite=None — explicitly sent cross-site; requires Secure');
  return issues;
}
