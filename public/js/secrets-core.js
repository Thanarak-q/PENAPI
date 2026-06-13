// Secret Scanner — pure, DOM-free core. Scans pasted text for leaked
// credentials / secrets using regex detectors.
// DOM-free for `node --test`.

// Each detector: { type, severity, re }. Severity: 'high' | 'medium' | 'low'.
const DETECTORS = [
  {
    type: 'AWS Access Key ID',
    severity: 'high',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    type: 'Google API Key',
    severity: 'high',
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    type: 'GitHub Token',
    severity: 'high',
    re: /\bgh[poustr]_[0-9A-Za-z]{36}\b/g,
  },
  {
    type: 'GitHub Fine-grained PAT',
    severity: 'high',
    re: /\bgithub_pat_[0-9A-Za-z_]{20,}\b/g,
  },
  {
    type: 'Slack Token',
    severity: 'high',
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  },
  {
    type: 'Stripe Live Secret Key',
    severity: 'high',
    re: /\bsk_live_[0-9a-zA-Z]{16,}\b/g,
  },
  {
    type: 'SendGrid API Key',
    severity: 'high',
    re: /\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b/g,
  },
  {
    type: 'JWT',
    severity: 'medium',
    // Trailing segment is optional so `alg:none` unsigned tokens (empty
    // signature, e.g. `eyJ….eyJ….`) are also caught.
    re: /\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]*/g,
  },
  {
    type: 'Private Key Block',
    severity: 'high',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    type: 'Basic Auth in URL',
    severity: 'high',
    re: /https?:\/\/[^/\s:@]+:[^/\s:@]+@/g,
  },
  {
    type: 'Bearer Token',
    severity: 'medium',
    re: /\bBearer\s+[A-Za-z0-9._\-]{20,}/g,
  },
  {
    type: 'Assigned Secret',
    severity: 'medium',
    re: /\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*["']?[^\s"'`,;]{8,}/gi,
  },
  {
    type: 'Email Address',
    severity: 'low',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
];

// Redact a match so the preview never splashes a full secret. Basic-auth URLs
// embed the password right before the `@`, so a generic first/last slice would
// still leak it — mask the whole credential for that type. Other short matches
// are fully masked; longer ones keep just the first/last few chars for context.
function redact(str, type) {
  if (type === 'Basic Auth in URL') {
    return str.replace(/(:\/\/)[^@]*@/, '$1••••@');
  }
  if (str.length <= 8) return '•'.repeat(str.length);
  return str.slice(0, 4) + '…' + str.slice(-4);
}

// Scan text for leaked secrets. Returns an array of findings:
// { type, severity, match, index, preview }
// Identical (type+match) findings are de-duplicated.
// Empty / whitespace-only input returns [].
export function scanSecrets(text) {
  if (!text || !text.trim()) return [];
  const seen = new Set();
  const findings = [];
  for (const { type, severity, re } of DETECTORS) {
    // Clone the regex so we never share stateful lastIndex across calls.
    const pattern = new RegExp(re.source, re.flags);
    for (const m of text.matchAll(pattern)) {
      const match = m[0];
      const key = type + '\x00' + match;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ type, severity, match, index: m.index, preview: redact(match, type) });
    }
  }
  return findings;
}

// Summarize findings by severity. Returns { high, medium, low, total }.
export function summarizeSecrets(findings) {
  const counts = { high: 0, medium: 0, low: 0, total: findings.length };
  for (const f of findings) {
    if (f.severity === 'high') counts.high++;
    else if (f.severity === 'medium') counts.medium++;
    else if (f.severity === 'low') counts.low++;
  }
  return counts;
}
