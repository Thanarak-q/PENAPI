// OWASP API Security Top 10 (2023) reference data + a classifier that tags
// findings with an OWASP-API id and a representative CWE when the analyzer
// that produced them did not already supply one. Pure and side-effect free.

export const OWASP_API = {
  'API1:2023': { title: 'Broken Object Level Authorization', short: 'BOLA', fix: 'Enforce per-object ownership checks on every request using the authenticated subject; never trust client-supplied object ids.' },
  'API2:2023': { title: 'Broken Authentication', short: 'Auth', fix: 'Use short-lived tokens over TLS, validate JWT alg/exp server-side, rate-limit and lock out auth endpoints, and avoid credentials in URLs.' },
  'API3:2023': { title: 'Broken Object Property Level Authorization', short: 'BOPLA', fix: 'Whitelist writable fields (block mass assignment) and return only the properties each caller is authorized to see.' },
  'API4:2023': { title: 'Unrestricted Resource Consumption', short: 'Resource', fix: 'Apply rate limits, pagination caps, request/array size limits, and timeouts; queue or bound expensive operations.' },
  'API5:2023': { title: 'Broken Function Level Authorization', short: 'BFLA', fix: 'Deny by default and check role/function authorization on every administrative or privileged operation.' },
  'API6:2023': { title: 'Unrestricted Access to Sensitive Business Flows', short: 'Bus. flow', fix: 'Add anti-automation to sensitive flows: rate limiting, device/identity limits, step-up auth, and idempotency.' },
  'API7:2023': { title: 'Server Side Request Forgery', short: 'SSRF', fix: 'Validate and allow-list outbound targets, block internal ranges/metadata IPs, and disable unneeded redirects.' },
  'API8:2023': { title: 'Security Misconfiguration', short: 'Misconfig', fix: 'Set security headers and strict CORS, harden cookies (HttpOnly/Secure/SameSite), suppress stack traces and tech banners, and disable debug surfaces.' },
  'API9:2023': { title: 'Improper Inventory Management', short: 'Inventory', fix: 'Retire old/pre-release versions, keep specs accurate, and remove internal/non-production hosts from public docs.' },
  'API10:2023': { title: 'Unsafe Consumption of APIs', short: '3rd-party', fix: 'Validate and sanitize data from upstream/third-party APIs and constrain how their responses are used.' },
};

// Ordered keyword rules. The first rule whose regex matches the finding's
// "<category> <title>" string wins. Keep specific rules above generic ones.
const RULES = [
  { re: /\bssrf\b|redirect|callback|webhook|fetch.*url|url param/i, owasp: 'API7:2023', cwe: 'CWE-918' },
  { re: /idor|bola|object identifier|ownership|object level/i, owasp: 'API1:2023', cwe: 'CWE-639' },
  { re: /mass assignment|over-?post|object property|excessive data|property level/i, owasp: 'API3:2023', cwe: 'CWE-915' },
  { re: /function level|admin|privileg|management or debug|debug surface|bfla/i, owasp: 'API5:2023', cwe: 'CWE-285' },
  { re: /plaintext|cleartext|over http\b|non-tls|without tls/i, owasp: 'API2:2023', cwe: 'CWE-319' },
  { re: /brute|credential stuffing|rate limit|enumerat|otp|2fa|mfa|jwt|token|authenticat|login|password|credential/i, owasp: 'API2:2023', cwe: 'CWE-287' },
  { re: /pagination|resource consumption|bulk|batch|unbounded|no limit|array length|expensive|export|denial/i, owasp: 'API4:2023', cwe: 'CWE-770' },
  { re: /business flow|checkout|purchase|transfer|booking|coupon/i, owasp: 'API6:2023', cwe: 'CWE-840' },
  { re: /cors|security header|hsts|cookie flag|cookie missing|cookie without|httponly|samesite|set-cookie|clickjack|frame-options|frame-ancestors|referrer-policy|permissions-policy|content-security|\bcsp\b|fingerprint|tech disclosure|stack trace|verbose error|server error|content-type|x-powered-by|server header|misconfig|cache/i, owasp: 'API8:2023', cwe: 'CWE-16' },
  { re: /version|shadow|deprecated|inventory|non-?prod|staging|legacy|undocumented host/i, owasp: 'API9:2023', cwe: 'CWE-1059' },
  { re: /third-?party|upstream|external api|unsafe consumption/i, owasp: 'API10:2023', cwe: 'CWE-1104' },
  // Secrets observed in responses/logs → sensitive data exposure.
  { re: /access key|private key|aws access key|key in (the )?(response|body)|secret in/i, owasp: 'API3:2023', cwe: 'CWE-312' },
  // Category fallbacks.
  { re: /injection|sqli|xss|graphql/i, owasp: 'API8:2023', cwe: 'CWE-20' },
  { re: /sensitive data|leak|disclos|pii/i, owasp: 'API3:2023', cwe: 'CWE-213' },
];

// Return { owasp, cwe } for a finding, preferring values it already carries.
export function classify(finding) {
  if (finding.owasp || finding.cwe) {
    return { owasp: finding.owasp || '', cwe: finding.cwe || '' };
  }
  // Classify on the finding's intrinsic nature only. Evidence is excluded on
  // purpose: it can carry incidental keywords (e.g. a "staging" URL) that would
  // otherwise mis-route the finding to the wrong OWASP category.
  const hay = `${finding.category || ''} ${finding.title || ''}`;
  for (const rule of RULES) {
    if (rule.re.test(hay)) return { owasp: rule.owasp, cwe: rule.cwe };
  }
  return { owasp: '', cwe: '' };
}

// Immutably return a finding with owasp/cwe filled in.
export function enrich(finding) {
  const { owasp, cwe } = classify(finding);
  if (owasp === finding.owasp && cwe === finding.cwe) return finding;
  return { ...finding, owasp, cwe };
}

// Short label for UI badges, e.g. 'API8 Misconfig'.
export function owaspLabel(id) {
  const meta = OWASP_API[id];
  if (!meta) return id || '';
  return `${id.replace(':2023', '')} ${meta.short}`;
}
