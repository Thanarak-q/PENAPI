// Passive response analysis: surfaces missing/weak security headers, permissive
// CORS, info-leak banners, weak cookie flags, cacheable secrets, verbose errors,
// and secrets leaked in the body. Pure and client-side (DOM-free for tests).

const SECURITY_HEADERS = [
  ['strict-transport-security', 'HSTS not set', 'medium', 'no HSTS — connection can be downgraded'],
  ['content-security-policy', 'No Content-Security-Policy', 'low', 'no CSP'],
  ['x-content-type-options', 'X-Content-Type-Options missing', 'low', 'MIME sniffing not blocked'],
  ['x-frame-options', 'X-Frame-Options / frame-ancestors missing', 'low', 'clickjacking not blocked'],
  ['referrer-policy', 'Referrer-Policy not set', 'info', 'referrer may leak'],
  ['permissions-policy', 'Permissions-Policy not set', 'info', 'powerful browser features not restricted'],
];

const MIN_HSTS = 15552000; // 180 days, in seconds

export function analyzeResponse(result) {
  if (!result || result.error) return [];
  const h = lower(result.headers || {});
  const findings = [];

  // Missing security headers.
  for (const [name, title, sev, note] of SECURITY_HEADERS) {
    if (name === 'x-frame-options') {
      const csp = h['content-security-policy'] || '';
      if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp)) findings.push({ sev, title, note });
      continue;
    }
    if (!h[name]) findings.push({ sev, title, note });
  }

  // Weak header configuration.
  const hsts = h['strict-transport-security'];
  if (hsts) {
    const m = /max-age\s*=\s*(\d+)/i.exec(hsts);
    if (!m || Number(m[1]) < MIN_HSTS) {
      findings.push({ sev: 'low', title: 'Weak HSTS max-age', note: 'max-age below 180 days' });
    }
  }
  const csp = h['content-security-policy'];
  if (csp && /unsafe-inline|unsafe-eval/i.test(csp)) {
    findings.push({ sev: 'low', title: "CSP allows 'unsafe-inline'/'unsafe-eval'", note: 'weakens XSS protection' });
  }

  // CORS.
  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];
  if (acao === '*') {
    findings.push({ sev: 'medium', title: 'CORS allows any origin (*)', note: 'Access-Control-Allow-Origin: *' });
  }
  if (acao === 'null') {
    findings.push({ sev: 'medium', title: 'CORS allows the "null" origin', note: 'ACAO: null is reachable from sandboxed iframes / data: URLs' });
  }
  if (acao && acao !== '*' && acac === 'true') {
    findings.push({
      sev: 'high',
      title: 'CORS reflects origin with credentials',
      note: `ACAO: ${acao} + Allow-Credentials: true — test origin reflection`,
    });
  }

  // Info-leak banners.
  for (const banner of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    if (h[banner]) findings.push({ sev: 'info', title: `Tech disclosure: ${banner}`, note: `${banner}: ${h[banner]}` });
  }
  if (h['www-authenticate']) {
    findings.push({ sev: 'info', title: 'WWW-Authenticate exposes the auth scheme', note: h['www-authenticate'] });
  }

  // Cookie flags.
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const sc = setCookie.toLowerCase();
    if (!sc.includes('httponly')) findings.push({ sev: 'medium', title: 'Cookie without HttpOnly', note: 'session cookie readable from JS' });
    if (!sc.includes('secure')) findings.push({ sev: 'medium', title: 'Cookie without Secure', note: 'cookie sent over plaintext' });
    if (!sc.includes('samesite')) findings.push({ sev: 'low', title: 'Cookie without SameSite', note: 'CSRF surface' });
    if (/samesite=none/.test(sc) && !sc.includes('secure')) {
      findings.push({ sev: 'medium', title: 'Cookie SameSite=None without Secure', note: 'browsers reject it; cross-site if accepted' });
    }
  }

  // Sensitive responses should not be cacheable.
  const cacheControl = h['cache-control'] || '';
  if ((setCookie || h['authorization']) && !/no-store/i.test(cacheControl)) {
    findings.push({ sev: 'low', title: 'Sensitive response may be cacheable', note: 'Set-Cookie/auth response without Cache-Control: no-store' });
  }

  // Status- and body-based disclosure.
  const status = Number(result.status || 0);
  if (status >= 500) {
    findings.push({ sev: 'medium', title: `Server error ${status}`, note: '5xx may leak stack traces and aids error-based injection' });
  }

  const body = String(result.body || '');
  if (body) {
    if (/Traceback \(most recent call last\)|Exception in thread|\bat [\w.$]+\([\w.]+\.java:\d+\)|SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|System\.[A-Za-z.]+Exception/.test(body)) {
      findings.push({ sev: 'medium', title: 'Verbose error / stack trace in body', note: 'framework error details disclosed' });
    }
    if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/.test(body)) {
      findings.push({ sev: 'high', title: 'Private key in response body', note: 'a private-key block was returned' });
    }
    if (/\bAKIA[0-9A-Z]{16}\b/.test(body)) {
      findings.push({ sev: 'high', title: 'AWS access key in response body', note: 'an AKIA-prefixed key was returned' });
    }
  }

  return findings;
}

function lower(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}
