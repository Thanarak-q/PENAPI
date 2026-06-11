// Passive response analysis: surfaces missing security headers, permissive
// CORS, info-leak banners, and weak cookie flags from a response. Client-side.

const SECURITY_HEADERS = [
  ['strict-transport-security', 'HSTS not set', 'medium', 'no HSTS — connection can be downgraded'],
  ['content-security-policy', 'No Content-Security-Policy', 'low', 'no CSP'],
  ['x-content-type-options', 'X-Content-Type-Options missing', 'low', 'MIME sniffing not blocked'],
  ['x-frame-options', 'X-Frame-Options / frame-ancestors missing', 'low', 'clickjacking not blocked'],
  ['referrer-policy', 'Referrer-Policy not set', 'info', 'referrer may leak'],
];

export function analyzeResponse(result) {
  if (!result || result.error) return [];
  const h = lower(result.headers || {});
  const findings = [];

  // Missing security headers
  for (const [name, title, sev, note] of SECURITY_HEADERS) {
    if (name === 'x-frame-options') {
      const csp = h['content-security-policy'] || '';
      if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp)) {
        findings.push({ sev, title, note });
      }
      continue;
    }
    if (!h[name]) findings.push({ sev, title, note });
  }

  // Permissive CORS
  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];
  if (acao === '*') {
    findings.push({ sev: 'medium', title: 'CORS allows any origin (*)', note: 'Access-Control-Allow-Origin: *' });
  }
  if (acao && acao !== '*' && acac === 'true') {
    findings.push({
      sev: 'high',
      title: 'CORS reflects origin with credentials',
      note: `ACAO: ${acao} + Allow-Credentials: true — test origin reflection`,
    });
  }

  // Info-leak banners
  for (const banner of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    if (h[banner]) findings.push({ sev: 'info', title: `Tech disclosure: ${banner}`, note: `${banner}: ${h[banner]}` });
  }

  // Cookie flags
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const sc = setCookie.toLowerCase();
    if (!sc.includes('httponly')) findings.push({ sev: 'medium', title: 'Cookie without HttpOnly', note: 'session cookie readable from JS' });
    if (!sc.includes('secure')) findings.push({ sev: 'medium', title: 'Cookie without Secure', note: 'cookie sent over plaintext' });
    if (!sc.includes('samesite')) findings.push({ sev: 'low', title: 'Cookie without SameSite', note: 'CSRF surface' });
  }

  return findings;
}

function lower(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}
