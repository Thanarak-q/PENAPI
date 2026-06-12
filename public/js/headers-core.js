// Security Header Auditor — pure, DOM-free core. Parses a raw response-header
// block and audits it for missing / weak HTTP security headers.
// DOM-free for `node --test`.

// Parse a raw header block ("Name: value" lines, optional "HTTP/1.1 200" first
// line) into a lower-cased { name -> value } map. Duplicate headers keep the
// last value, except Set-Cookie which is ignored here (use Cookie Inspector).
export function parseHeaders(raw) {
  const out = {};
  for (const line of String(raw || '').split('\n')) {
    const s = line.trim();
    if (!s || /^HTTP\//i.test(s)) continue;
    const i = s.indexOf(':');
    if (i === -1) continue;
    const name = s.slice(0, i).trim().toLowerCase();
    const value = s.slice(i + 1).trim();
    if (name === 'set-cookie') continue;
    out[name] = value;
  }
  return out;
}

// Audit a parsed header map. Returns [{ header, level, note }] where level is
// 'missing' | 'weak' | 'ok'. Covers the headers a pentester checks first.
export function auditHeaders(headers) {
  const h = headers || {};
  const findings = [];
  const has = (k) => Object.prototype.hasOwnProperty.call(h, k);

  if (!has('content-security-policy')) {
    findings.push({ header: 'Content-Security-Policy', level: 'missing', note: 'No CSP — page has no script-source allowlist (XSS mitigation absent).' });
  } else if (/unsafe-inline|unsafe-eval/i.test(h['content-security-policy'])) {
    findings.push({ header: 'Content-Security-Policy', level: 'weak', note: "CSP allows 'unsafe-inline'/'unsafe-eval' — weakens XSS protection." });
  } else {
    findings.push({ header: 'Content-Security-Policy', level: 'ok', note: 'Present.' });
  }

  if (!has('strict-transport-security')) {
    findings.push({ header: 'Strict-Transport-Security', level: 'missing', note: 'No HSTS — connection can be downgraded to plaintext HTTP.' });
  } else if (!/max-age\s*=\s*([0-9]+)/i.test(h['strict-transport-security']) || Number(RegExp.$1) < 15552000) {
    findings.push({ header: 'Strict-Transport-Security', level: 'weak', note: 'HSTS max-age below 180 days (15552000s) — weak enforcement window.' });
  } else {
    findings.push({ header: 'Strict-Transport-Security', level: 'ok', note: 'Present.' });
  }

  if (!has('x-content-type-options')) {
    findings.push({ header: 'X-Content-Type-Options', level: 'missing', note: "Missing — browser may MIME-sniff responses. Set to 'nosniff'." });
  } else if (!/nosniff/i.test(h['x-content-type-options'])) {
    findings.push({ header: 'X-Content-Type-Options', level: 'weak', note: "Present but not 'nosniff'." });
  } else {
    findings.push({ header: 'X-Content-Type-Options', level: 'ok', note: 'nosniff.' });
  }

  const frame = has('x-frame-options');
  const cspFrame = has('content-security-policy') && /frame-ancestors/i.test(h['content-security-policy']);
  if (!frame && !cspFrame) {
    findings.push({ header: 'X-Frame-Options', level: 'missing', note: 'No X-Frame-Options or CSP frame-ancestors — clickjacking possible.' });
  } else if (frame && /allowall/i.test(h['x-frame-options'])) {
    findings.push({ header: 'X-Frame-Options', level: 'weak', note: 'ALLOWALL defeats clickjacking protection.' });
  } else {
    findings.push({ header: 'X-Frame-Options', level: 'ok', note: frame ? h['x-frame-options'] : 'covered by CSP frame-ancestors.' });
  }

  if (!has('referrer-policy')) {
    findings.push({ header: 'Referrer-Policy', level: 'missing', note: 'No Referrer-Policy — full URLs may leak to third parties.' });
  } else {
    findings.push({ header: 'Referrer-Policy', level: 'ok', note: h['referrer-policy'] });
  }

  // Information-disclosure headers: presence is the problem.
  for (const leak of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    if (has(leak)) {
      findings.push({ header: leak.replace(/\b\w/g, (c) => c.toUpperCase()), level: 'weak', note: `Discloses tech stack: "${h[leak]}" — fingerprinting aid.` });
    }
  }

  if (has('access-control-allow-origin') && h['access-control-allow-origin'] === '*') {
    const creds = has('access-control-allow-credentials') && /true/i.test(h['access-control-allow-credentials']);
    findings.push({
      header: 'Access-Control-Allow-Origin',
      level: creds ? 'missing' : 'weak',
      note: creds
        ? 'ACAO "*" with Allow-Credentials:true — invalid + dangerous CORS config.'
        : 'ACAO "*" — any origin can read responses.',
    });
  }

  return findings;
}

// Convenience: parse + audit in one call.
export function auditRawHeaders(raw) {
  return auditHeaders(parseHeaders(raw));
}

// Summary counts by level for a findings array.
export function summarize(findings) {
  return (findings || []).reduce(
    (acc, f) => ((acc[f.level] = (acc[f.level] || 0) + 1), acc),
    { missing: 0, weak: 0, ok: 0 }
  );
}
